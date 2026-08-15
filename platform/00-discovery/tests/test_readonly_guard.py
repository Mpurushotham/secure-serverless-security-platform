"""The read-only guard is the control that makes this tool safe to point at a
production account. These tests are the evidence that it works.

The last test is the one that matters: it drives **every collector** and asserts
that not one of them attempts an operation the guard would refuse. That is a
statement about the whole tool rather than about the guard in isolation — the
guard could be perfect and a collector could still be reaching for data, and
only this test would notice.
"""

from __future__ import annotations

import boto3
import pytest
from discovery import readonly_guard
from discovery.collectors import build_all
from discovery.readonly_guard import DATA_PLANE_READS, ReadOnlyViolation, classify


class TestStructuralCheck:
    @pytest.mark.parametrize(
        "service,operation",
        [
            ("s3", "ListBuckets"),
            ("iam", "GetAccountSummary"),
            ("organizations", "DescribeOrganization"),
            ("ec2", "DescribeSecurityGroups"),
            ("iam", "GenerateCredentialReport"),
            ("iam", "SimulatePrincipalPolicy"),
            ("lambda", "GetFunctionConfiguration"),
        ],
    )
    def test_read_operations_are_permitted(self, service: str, operation: str) -> None:
        assert classify(service, operation) is None

    @pytest.mark.parametrize(
        "service,operation",
        [
            ("s3", "PutBucketPolicy"),
            ("s3", "DeleteBucket"),
            ("iam", "CreateUser"),
            ("iam", "AttachRolePolicy"),
            ("ec2", "AuthorizeSecurityGroupIngress"),
            ("organizations", "LeaveOrganization"),
            ("guardduty", "DeleteDetector"),
            ("kms", "ScheduleKeyDeletion"),
        ],
    )
    def test_mutating_operations_are_refused(self, service: str, operation: str) -> None:
        assert classify(service, operation) == "is not a read-only operation"

    def test_an_unknown_future_mutating_verb_is_refused_by_default(self) -> None:
        # The point of matching on read-only prefixes rather than listing every
        # mutating verb: an API nobody has thought about yet is refused without
        # anyone updating this file.
        assert classify("bedrock", "InvokeModel") is not None
        assert classify("someservice", "ObliterateEverything") is not None


class TestDataPlaneCheck:
    @pytest.mark.parametrize(
        "service,operation",
        [
            ("s3", "GetObject"),
            ("s3", "ListObjectsV2"),
            ("secretsmanager", "GetSecretValue"),
            ("ssm", "GetParameter"),
            ("ssm", "GetParametersByPath"),
            ("kms", "Decrypt"),
            ("dynamodb", "GetItem"),
            ("dynamodb", "Scan"),
            ("rds-data", "ExecuteStatement"),
            ("logs", "FilterLogEvents"),
            ("lambda", "GetFunction"),
            ("cloudtrail", "LookupEvents"),
        ],
    )
    def test_data_reads_are_refused_despite_read_only_verbs(
        self, service: str, operation: str
    ) -> None:
        # Every one of these begins with Get/List/Select and so passes the
        # structural check. Refusing them is the entire reason the second
        # check exists: they change nothing and return everything.
        assert classify(service, operation) == "reads data rather than configuration"

    def test_configuration_reads_on_the_same_services_are_permitted(self) -> None:
        assert classify("s3", "GetBucketPolicyStatus") is None
        assert classify("secretsmanager", "ListSecrets") is None
        assert classify("ssm", "DescribeParameters") is None
        assert classify("kms", "DescribeKey") is None
        assert classify("dynamodb", "DescribeTable") is None


class TestInstalledOnASession:
    def test_a_denied_call_never_reaches_the_wire(self) -> None:
        session = boto3.Session(
            region_name="us-east-1",
            aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
            aws_secret_access_key="x" * 40,
        )
        readonly_guard.install(session)
        client = session.client("s3")

        with pytest.raises(ReadOnlyViolation) as excinfo:
            client.get_object(Bucket="any", Key="any")

        assert excinfo.value.service == "s3"
        assert excinfo.value.operation == "GetObject"

    def test_violation_is_not_a_client_error(self) -> None:
        # A collector's `except ClientError` must not be able to swallow this.
        from botocore.exceptions import ClientError

        assert not issubclass(ReadOnlyViolation, ClientError)

    def test_the_message_says_where_to_fix_it(self) -> None:
        violation = ReadOnlyViolation("s3", "GetObject", "reads data")
        assert "discovery-readonly.json" in str(violation)


class RecordingSession:
    """A DiscoverySession stand-in that records operations instead of calling AWS.

    Returns empty results for everything, which is enough: the assertion is
    about which operations are *attempted*, not about what they return.
    """

    def __init__(self) -> None:
        self.attempted: list[tuple[str, str]] = []
        self.calls: list[object] = []

    def caller_identity(self) -> dict[str, str]:
        return {"Account": "123456789012", "Arn": "arn:aws:iam::123456789012:role/test"}

    def client(self, service: str, region: str | None = None) -> str:
        return service

    def call(self, client: str, operation: str, **kwargs: object) -> None:
        self.attempted.append((client, _camel(operation)))
        return None

    def paginate(
        self, client: str, operation: str, key: str, **kwargs: object
    ) -> list[object]:
        self.attempted.append((client, _camel(operation)))
        return []

    def enabled_regions(self) -> list[str]:
        return ["us-east-1"]


def _camel(snake: str) -> str:
    """boto3 method name to the AWS operation name the guard sees."""
    return "".join(part.title() for part in snake.split("_"))


def test_no_collector_attempts_an_operation_the_guard_would_refuse() -> None:
    session = RecordingSession()

    for collector in build_all():
        collector.collect(session, ["us-east-1"])  # type: ignore[arg-type]

    assert session.attempted, "collectors made no calls — the harness is broken"

    refused = [
        (service, operation, classify(service, operation))
        for service, operation in set(session.attempted)
        if classify(service, operation) is not None
    ]
    assert not refused, (
        "collectors attempted operations the read-only guard refuses:\n"
        + "\n".join(f"  {s}:{o} — {why}" for s, o, why in refused)
    )


# API operation names are not always IAM action names. S3 is the notable case:
# four distinct list/select APIs are all authorised by two IAM actions. A test
# that assumes they are identical reports drift that does not exist, and — worse
# — could be "fixed" by adding invalid actions to the policy.
API_TO_IAM_ACTION = {
    "s3:ListObjects": "s3:ListBucket",
    "s3:ListObjectsV2": "s3:ListBucket",
    "s3:ListObjectVersions": "s3:ListBucketVersions",
    "s3:SelectObjectContent": "s3:GetObject",
    "s3:GetObjectTorrent": "s3:GetObject",
    "s3:GetObjectAttributes": "s3:GetObject",
}


def test_guard_and_iam_policy_do_not_drift() -> None:
    """Layer 2 and layer 3 must forbid the same things.

    ``readonly_guard`` is application code and ``discovery-readonly.json`` is
    enforced by AWS. They are independent controls, which is the point — but if
    they disagree, one of them is wrong and nobody finds out until an assessment
    either crashes or reads something it should not have.

    The asymmetry is deliberate: the IAM policy may deny *more* than the guard
    (it costs nothing to deny a service no collector uses). It must never deny
    less.
    """
    import json
    from pathlib import Path

    policy_path = (
        Path(__file__).resolve().parents[1] / "iam" / "discovery-readonly.json"
    )
    policy = json.loads(policy_path.read_text(encoding="utf-8"))

    denied_in_policy: set[str] = set()
    for statement in policy["Statement"]:
        if statement.get("Effect") != "Deny":
            continue
        for action in statement.get("Action", []):
            denied_in_policy.add(action.rstrip("*").lower())

    missing: list[str] = []
    for service, operations in DATA_PLANE_READS.items():
        for operation in operations:
            action = API_TO_IAM_ACTION.get(
                f"{service}:{operation}", f"{service}:{operation}"
            ).lower()
            if not any(action.startswith(denied) for denied in denied_in_policy):
                missing.append(f"{service}:{operation}")

    assert not missing, (
        "the guard refuses these operations but the IAM policy does not deny them, "
        "so an assessment run under that policy would rely on application code "
        f"alone: {sorted(missing)}"
    )
