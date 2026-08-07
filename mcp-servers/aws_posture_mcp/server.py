"""Read-only MCP server for AWS security posture.

Gives an agent access to GuardDuty, Security Hub, IAM, Config, S3, and KMS —
strictly read-only, and strictly summarised.

Two design choices distinguish this from a thin boto3 wrapper, and both are
security decisions rather than ergonomics:

**Findings are summarised, never returned raw.** A GuardDuty finding contains
instance IDs, IP addresses, principal ARNs, and sometimes S3 object keys. Piping
that verbatim into a model's context means an inventory of the environment is
now in a third party's logs. Each tool here returns counts, severities, and
types — enough to reason about posture, not enough to reconstruct the estate.

**The tool surface is an allowlist of read operations, not a passthrough.** There
is no `call_aws_api` tool. If a capability is not enumerated here it does not
exist, which means the IAM policy and the tool list can be reviewed against each
other rather than one being a superset of the other.

The accompanying IAM policy (`iam-policy.json`) grants only these operations,
with no `*` resources on anything that reads data and no access to Secrets
Manager at all.
"""

from __future__ import annotations

import os
import sys
from collections import Counter
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from mcp_core import AuditLog, MCPServer, StdioTransport
from mcp_core.errors import GuardrailViolation

SERVER_NAME = "aws-posture-mcp"

# Bounded retries: an agent that retries a throttled call in a loop turns a
# read-only server into a denial of service against the account's own API quota.
_BOTO_CONFIG = Config(retries={"max_attempts": 3, "mode": "standard"})

# Caps on every list operation. Without them a single tool call can pull tens of
# thousands of findings into a context window.
MAX_FINDINGS = 100
MAX_PRINCIPALS = 200


def _region() -> str:
    return os.environ.get("AWS_REGION", "eu-north-1")


def _client(service: str):
    return boto3.client(service, region_name=_region(), config=_BOTO_CONFIG)


def _guard_aws(fn, *args, **kwargs):
    """Translate AWS errors into guardrail refusals without leaking detail.

    An AccessDenied from boto3 carries the full ARN of the calling principal and
    the exact operation. Useful in a log, not something to hand to a model.
    """
    try:
        return fn(*args, **kwargs)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "Unknown")
        if code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation"):
            raise GuardrailViolation(
                "this server's IAM role is not permitted that operation",
                control="aws-iam",
                internal_detail=str(exc),
            ) from exc
        raise GuardrailViolation(
            f"AWS request failed ({code})", control="aws-upstream", internal_detail=str(exc)
        ) from exc
    except BotoCoreError as exc:
        raise GuardrailViolation(
            "AWS request failed", control="aws-upstream", internal_detail=str(exc)
        ) from exc


def build_server(audit: AuditLog | None = None) -> MCPServer:
    server = MCPServer(SERVER_NAME, audit=audit)

    @server.tool(
        "guardduty_summary",
        "Summarise GuardDuty findings by severity and type. Returns counts and "
        "type names only — never the raw finding, which contains instance IDs, "
        "IP addresses, and principal ARNs.",
        {
            "type": "object",
            "properties": {
                "min_severity": {
                    "type": "number",
                    "description": "1-8 (low), 4-6 (medium), 7-8 (high).",
                    "minimum": 0,
                    "maximum": 10,
                }
            },
        },
    )
    def _guardduty(args: dict) -> dict:
        min_severity = float(args.get("min_severity", 4))
        client = _client("guardduty")
        detectors = _guard_aws(client.list_detectors).get("DetectorIds", [])
        if not detectors:
            return {"detectors": 0, "note": "GuardDuty is not enabled in this region."}

        collected: list[dict[str, Any]] = []
        unreadable = 0

        for detector_id in detectors:
            try:
                ids = client.list_findings(
                    DetectorId=detector_id,
                    FindingCriteria={"Criterion": {"severity": {"Gte": int(min_severity)}}},
                    MaxResults=MAX_FINDINGS,
                ).get("FindingIds", [])
                if not ids:
                    continue
                collected.extend(
                    client.get_findings(DetectorId=detector_id, FindingIds=ids[:MAX_FINDINGS])
                    .get("Findings", [])
                )
            except (ClientError, BotoCoreError):
                # Report the detector as unreadable rather than silently
                # contributing zero. "No findings" and "could not read" are
                # different answers, and conflating them turns a blind spot
                # into a clean bill of health.
                unreadable += 1

        summary = summarise_findings(collected)
        summary["detectors"] = len(detectors)
        summary["truncated"] = len(collected) >= MAX_FINDINGS
        if unreadable:
            summary["detectors_unreadable"] = unreadable
            summary["warning"] = (
                f"{unreadable} detector(s) could not be queried; this summary is incomplete."
            )
        return summary

    @server.tool(
        "securityhub_summary",
        "Summarise active Security Hub findings by severity, compliance status, "
        "and control. Counts only.",
        {"type": "object", "properties": {}},
    )
    def _securityhub(_args: dict) -> dict:
        client = _client("securityhub")
        findings = _guard_aws(
            client.get_findings,
            Filters={
                "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
                "WorkflowStatus": [{"Value": "NEW", "Comparison": "EQUALS"}],
            },
            MaxResults=MAX_FINDINGS,
        ).get("Findings", [])

        by_severity: Counter[str] = Counter()
        by_control: Counter[str] = Counter()
        for finding in findings:
            by_severity[finding.get("Severity", {}).get("Label", "UNKNOWN")] += 1
            by_control[finding.get("GeneratorId", "unknown")] += 1

        return {
            "active_findings_examined": len(findings),
            "by_severity": dict(by_severity),
            "top_controls": dict(by_control.most_common(10)),
            "truncated": len(findings) >= MAX_FINDINGS,
        }

    @server.tool(
        "iam_principal_risk",
        "Report IAM roles carrying administrative policies or lacking a "
        "permissions boundary. Returns role names and a risk reason — never "
        "policy documents, which would expose the full authorisation model.",
        {"type": "object", "properties": {}},
    )
    def _iam_risk(_args: dict) -> dict:
        client = _client("iam")
        roles = _guard_aws(client.list_roles, MaxItems=MAX_PRINCIPALS).get("Roles", [])

        no_boundary: list[str] = []
        admin: list[str] = []

        for role in roles:
            name = role["RoleName"]
            # Service-linked roles are managed by AWS and cannot carry a
            # boundary. Reporting them is noise that trains people to ignore
            # this tool's output.
            if role.get("Path", "").startswith("/aws-service-role/"):
                continue
            if not role.get("PermissionsBoundary"):
                no_boundary.append(name)
            attached = _guard_aws(
                client.list_attached_role_policies, RoleName=name
            ).get("AttachedPolicies", [])
            if any(p["PolicyName"] in ("AdministratorAccess", "PowerUserAccess") for p in attached):
                admin.append(name)

        return {
            "roles_examined": len(roles),
            "without_permissions_boundary": {
                "count": len(no_boundary),
                "roles": sorted(no_boundary)[:25],
                "why_it_matters": "A boundary is the only IAM control that survives someone attaching a wider policy later.",
            },
            "with_administrative_policy": {
                "count": len(admin),
                "roles": sorted(admin)[:25],
            },
        }

    @server.tool(
        "s3_public_exposure",
        "Report buckets whose public access block is incomplete. Returns bucket "
        "names and which of the four settings are missing.",
        {"type": "object", "properties": {}},
    )
    def _s3_exposure(_args: dict) -> dict:
        client = _client("s3")
        buckets = _guard_aws(client.list_buckets).get("Buckets", [])
        exposed: list[dict[str, Any]] = []

        for bucket in buckets:
            name = bucket["Name"]
            try:
                config = client.get_public_access_block(Bucket=name)
                block = config["PublicAccessBlockConfiguration"]
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "")
                if code in ("NoSuchPublicAccessBlockConfiguration", "NoSuchBucket"):
                    exposed.append({"bucket": name, "missing": ["all — no configuration"]})
                    continue
                # A bucket in another region or without permission is not a
                # finding; recording it as one would be a false positive.
                continue
            missing = [k for k, v in block.items() if not v]
            if missing:
                exposed.append({"bucket": name, "missing": missing})

        return {
            "buckets_examined": len(buckets),
            "buckets_with_incomplete_block": len(exposed),
            "details": exposed[:25],
        }

    @server.tool(
        "kms_key_rotation",
        "Report customer-managed KMS keys without automatic rotation enabled.",
        {"type": "object", "properties": {}},
    )
    def _kms_rotation(_args: dict) -> dict:
        client = _client("kms")
        keys = _guard_aws(client.list_keys, Limit=MAX_PRINCIPALS).get("Keys", [])
        unrotated: list[str] = []
        examined = 0

        for key in keys:
            key_id = key["KeyId"]
            try:
                meta = client.describe_key(KeyId=key_id)["KeyMetadata"]
                # AWS-managed keys rotate on their own schedule and cannot be
                # configured; flagging them is noise.
                if meta.get("KeyManager") != "CUSTOMER":
                    continue
                if meta.get("KeyState") != "Enabled":
                    continue
                examined += 1
                if not client.get_key_rotation_status(KeyId=key_id).get("KeyRotationEnabled"):
                    unrotated.append(key_id)
            except ClientError:
                continue

        return {
            "customer_managed_keys_examined": examined,
            "without_rotation": {"count": len(unrotated), "key_ids": unrotated[:25]},
        }

    @server.tool(
        "config_compliance",
        "Summarise AWS Config rules by compliance state.",
        {"type": "object", "properties": {}},
    )
    def _config(_args: dict) -> dict:
        client = _client("config")
        rules = _guard_aws(client.describe_config_rules).get("ConfigRules", [])
        states: Counter[str] = Counter()
        non_compliant: list[str] = []

        for rule in rules:
            name = rule["ConfigRuleName"]
            try:
                result = client.describe_compliance_by_config_rule(ConfigRuleNames=[name])
                for item in result.get("ComplianceByConfigRules", []):
                    state = item.get("Compliance", {}).get("ComplianceType", "UNKNOWN")
                    states[state] += 1
                    if state == "NON_COMPLIANT":
                        non_compliant.append(name)
            except ClientError:
                continue

        return {
            "rules_examined": len(rules),
            "by_state": dict(states),
            "non_compliant_rules": sorted(non_compliant)[:25],
        }

    return server


def summarise_findings(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Reduce raw GuardDuty findings to counts.

    Pure and separately tested. A raw finding carries instance IDs, IP
    addresses, principal ARNs, and sometimes S3 object keys; returning it
    verbatim would put an inventory of the environment into a third party's
    logs. Only severity bands and type names survive this function.
    """
    by_severity: Counter[str] = Counter()
    by_type: Counter[str] = Counter()
    for finding in findings:
        by_severity[_severity_band(float(finding.get("Severity", 0)))] += 1
        by_type[str(finding.get("Type", "Unknown"))] += 1
    return {
        "findings_examined": len(findings),
        "by_severity": dict(by_severity),
        "top_types": dict(by_type.most_common(10)),
    }


def _severity_band(severity: float) -> str:
    if severity >= 7:
        return "HIGH"
    if severity >= 4:
        return "MEDIUM"
    return "LOW"


def main() -> None:
    audit_path = os.environ.get("MCP_AUDIT_PATH")
    stream = open(audit_path, "a", encoding="utf-8") if audit_path else sys.stderr  # noqa: SIM115
    build_server(audit=AuditLog(stream=stream)).serve(StdioTransport())


if __name__ == "__main__":
    main()
