"""Tests for the AWS posture server, against moto rather than a live account.

Two properties are asserted throughout, and the second is the one that matters:

  1. The tools work.
  2. The tools do not return raw findings. A GuardDuty finding carries instance
     IDs, IP addresses, and principal ARNs; piping it verbatim into a model
     means an inventory of the environment ends up in a third party's logs.
     Several tests assert on what is ABSENT from the output.
"""

from __future__ import annotations

import io
import json

import boto3
import pytest

moto = pytest.importorskip("moto", reason="moto is required for AWS tests")

from aws_posture_mcp.server import build_server  # noqa: E402
from mcp_core import PROTOCOL_VERSION, AuditLog  # noqa: E402

REGION = "eu-north-1"

# A realistic AccessDenied message: it carries the caller's full ARN, which is
# exactly what must not reach the model.
DENIED_MESSAGE = (
    "arn:aws:sts::123456789012:assumed-role/SECRET-ROLE/x is not authorized"
)


@pytest.fixture(autouse=True)
def aws_env(monkeypatch: pytest.MonkeyPatch):
    # Fake credentials so botocore never reaches a real endpoint or picks up a
    # developer's profile by accident.
    for key, value in {
        "AWS_ACCESS_KEY_ID": "testing",
        "AWS_SECRET_ACCESS_KEY": "testing",
        "AWS_SECURITY_TOKEN": "testing",
        "AWS_SESSION_TOKEN": "testing",
        "AWS_DEFAULT_REGION": REGION,
        "AWS_REGION": REGION,
    }.items():
        monkeypatch.setenv(key, value)


def call(server, tool: str, arguments: dict | None = None) -> dict:
    server.handle_frame(
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": {"protocolVersion": PROTOCOL_VERSION}})
    )
    server.handle_frame(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}))
    raw = server.handle_frame(json.dumps({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": tool, "arguments": arguments or {}},
    }))
    return json.loads(raw)


def fresh_server():
    return build_server(audit=AuditLog(stream=io.StringIO()))


def test_tools_are_an_allowlist_with_no_passthrough():
    """There must be no generic 'call any AWS API' escape hatch."""
    server = fresh_server()
    server.handle_frame(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                    "params": {"protocolVersion": PROTOCOL_VERSION}}))
    server.handle_frame(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}))
    listed = json.loads(server.handle_frame(
        json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    ))["result"]["tools"]
    names = {t["name"] for t in listed}
    assert names == {
        "guardduty_summary", "securityhub_summary", "iam_principal_risk",
        "s3_public_exposure", "kms_key_rotation", "config_compliance",
    }
    for forbidden in ("call_aws", "execute", "invoke", "raw"):
        assert not any(forbidden in n for n in names)


def test_summarise_findings_discards_everything_identifying():
    """The core security property, tested directly rather than through moto.

    moto does not implement GuardDuty's list_findings filter, so an integration
    test cannot exercise this path. The property matters more than the plumbing,
    so it is tested against a realistic finding payload instead.
    """
    from aws_posture_mcp.server import summarise_findings

    raw = [
        {
            "Severity": 8.0,
            "Type": "CryptoCurrency:EC2/BitcoinTool.B!DNS",
            "AccountId": "123456789012",
            "Resource": {
                "InstanceDetails": {
                    "InstanceId": "i-0abcdef1234567890",
                    "NetworkInterfaces": [{"PrivateIpAddress": "10.0.4.17",
                                           "PublicIp": "203.0.113.9"}],
                },
                "AccessKeyDetails": {"PrincipalId": "AROAEXAMPLE:secret-session",
                                     "UserName": "prod-admin"},
            },
            "Service": {"Action": {"DnsRequestAction": {"Domain": "pool.evil.example"}}},
        },
        {"Severity": 5.0, "Type": "Recon:EC2/PortProbeUnprotectedPort"},
        {"Severity": 2.0, "Type": "Recon:EC2/PortProbeUnprotectedPort"},
    ]

    out = json.dumps(summarise_findings(raw))
    parsed = json.loads(out)

    assert parsed["findings_examined"] == 3
    assert parsed["by_severity"] == {"HIGH": 1, "MEDIUM": 1, "LOW": 1}
    assert parsed["top_types"]["Recon:EC2/PortProbeUnprotectedPort"] == 2

    # Nothing identifying survives. This is the whole point of the function.
    for identifying in ("i-0abcdef1234567890", "10.0.4.17", "203.0.113.9",
                        "123456789012", "prod-admin", "AROAEXAMPLE",
                        "pool.evil.example"):
        assert identifying not in out, f"{identifying} leaked into the summary"


@moto.mock_aws
def test_guardduty_detects_enabled_detector():
    boto3.client("guardduty", region_name=REGION).create_detector(Enable=True)
    payload = call(fresh_server(), "guardduty_summary", {"min_severity": 1})
    parsed = json.loads(payload["result"]["content"][0]["text"])
    assert parsed["detectors"] == 1


@moto.mock_aws
def test_unreadable_detector_is_reported_not_silently_zero():
    """'No findings' and 'could not read' must not look the same.

    Conflating them turns a blind spot into a clean bill of health, which is the
    worst possible output from a posture tool.
    """
    boto3.client("guardduty", region_name=REGION).create_detector(Enable=True)
    payload = call(fresh_server(), "guardduty_summary", {"min_severity": 1})
    parsed = json.loads(payload["result"]["content"][0]["text"])
    # moto does not implement the findings filter, so this path is exercised
    # for real here: the tool must say so rather than report zero findings.
    assert parsed.get("detectors_unreadable", 0) >= 1
    assert "incomplete" in parsed.get("warning", "")


@moto.mock_aws
def test_guardduty_reports_when_not_enabled():
    """Silence and 'not enabled' are different answers; conflating them hides a gap."""
    parsed = json.loads(call(fresh_server(), "guardduty_summary")["result"]["content"][0]["text"])
    assert parsed["detectors"] == 0
    assert "not enabled" in parsed["note"]


@moto.mock_aws
def test_iam_flags_roles_without_a_permissions_boundary():
    iam = boto3.client("iam", region_name=REGION)
    trust = json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
         "Action": "sts:AssumeRole"}]})
    iam.create_role(RoleName="unbounded-role", AssumeRolePolicyDocument=trust)

    parsed = json.loads(call(fresh_server(), "iam_principal_risk")["result"]["content"][0]["text"])
    assert "unbounded-role" in parsed["without_permissions_boundary"]["roles"]
    assert parsed["without_permissions_boundary"]["count"] >= 1


@moto.mock_aws
def test_iam_output_never_contains_policy_documents():
    """Policy documents are the account's authorisation model; they stay out."""
    iam = boto3.client("iam", region_name=REGION)
    trust = json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"},
         "Action": "sts:AssumeRole"}]})
    iam.create_role(RoleName="some-role", AssumeRolePolicyDocument=trust)

    body = call(fresh_server(), "iam_principal_risk")["result"]["content"][0]["text"]
    assert "sts:AssumeRole" not in body
    assert "PolicyDocument" not in body
    assert "Statement" not in body


@moto.mock_aws
def test_s3_flags_bucket_without_public_access_block():
    s3 = boto3.client("s3", region_name=REGION)
    s3.create_bucket(Bucket="exposed-bucket",
                     CreateBucketConfiguration={"LocationConstraint": REGION})
    parsed = json.loads(call(fresh_server(), "s3_public_exposure")["result"]["content"][0]["text"])
    assert parsed["buckets_examined"] == 1
    assert parsed["buckets_with_incomplete_block"] == 1


@moto.mock_aws
def test_s3_clean_bucket_is_not_a_finding():
    s3 = boto3.client("s3", region_name=REGION)
    s3.create_bucket(Bucket="locked-bucket",
                     CreateBucketConfiguration={"LocationConstraint": REGION})
    s3.put_public_access_block(Bucket="locked-bucket", PublicAccessBlockConfiguration={
        "BlockPublicAcls": True, "IgnorePublicAcls": True,
        "BlockPublicPolicy": True, "RestrictPublicBuckets": True})
    parsed = json.loads(call(fresh_server(), "s3_public_exposure")["result"]["content"][0]["text"])
    assert parsed["buckets_with_incomplete_block"] == 0


@moto.mock_aws
def test_kms_flags_customer_key_without_rotation():
    kms = boto3.client("kms", region_name=REGION)
    kms.create_key(Description="unrotated")
    parsed = json.loads(call(fresh_server(), "kms_key_rotation")["result"]["content"][0]["text"])
    assert parsed["customer_managed_keys_examined"] >= 1
    assert parsed["without_rotation"]["count"] >= 1


@moto.mock_aws
def test_access_denied_becomes_a_legible_refusal_without_leaking_the_arn():
    """AccessDenied from boto3 carries the caller's full ARN and the operation."""
    server = fresh_server()
    import aws_posture_mcp.server as mod
    from botocore.exceptions import ClientError

    def denied(*_a, **_k):
        raise ClientError(
            {"Error": {"Code": "AccessDenied", "Message": DENIED_MESSAGE}},
            "ListDetectors")

    monkey = mod.boto3.client
    try:
        mod.boto3.client = lambda *a, **k: type("C", (), {"list_detectors": denied})()
        payload = call(server, "guardduty_summary")
    finally:
        mod.boto3.client = monkey

    result = payload["result"]
    assert result["isError"] is True
    text = result["content"][0]["text"]
    assert "aws-iam" in text
    assert "SECRET-ROLE" not in text
    assert "123456789012" not in text


def test_iam_policy_grants_no_data_reading_actions():
    """The shipped policy must not permit reading data, only describing posture."""
    import pathlib
    policy = json.loads(
        (pathlib.Path(__file__).resolve().parents[1] / "aws_posture_mcp" / "iam-policy.json")
        .read_text(encoding="utf-8")
    )
    allowed = [a for s in policy["Statement"] if s["Effect"] == "Allow"
               for a in (s["Action"] if isinstance(s["Action"], list) else [s["Action"]])]
    for forbidden in ("secretsmanager:GetSecretValue", "kms:Decrypt", "s3:GetObject",
                      "iam:GetPolicyVersion", "iam:GetRolePolicy"):
        assert forbidden not in allowed, f"{forbidden} must not be granted"
    assert not any(a == "*" or a.endswith(":*") for a in allowed), "no wildcard actions"

    denied = [a for s in policy["Statement"] if s["Effect"] == "Deny"
              for a in (s["Action"] if isinstance(s["Action"], list) else [s["Action"]])]
    assert "secretsmanager:*" in denied and "kms:Decrypt" in denied
