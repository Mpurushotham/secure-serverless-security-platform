"""Baseline rules: observations in, findings out.

Rules are kept apart from collectors on purpose. A collector answers "what is
configured"; a rule answers "is that acceptable". The second question is the one
people argue about, and separating them means the argument can be had — and
re-had — against a committed snapshot, without re-running a sweep against a live
account.

Each rule is data with one callable field. The alternative considered was YAML
plus JSONPath, which reads better in a policy review but cannot express the
conditions that actually matter here: coverage as a fraction of regions, and
correlations across collectors — the sharpest finding in the first live run was
"343 Config rules exist and the recorder is switched off", which needs two
collectors in one predicate.

Severity follows ``readiness/05-vulnerability-management.md``, and deliberately
not CVSS. Exposure, data sensitivity and blast radius decide it: a control gap
reachable from the internet outranks a more "severe" one that is not.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

Snapshot = dict[str, Any]

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    severity: str
    domain: str
    checklist: tuple[int, ...]
    detail: str
    remediation: str
    references: tuple[str, ...] = ()


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    domain: str
    checklist: tuple[int, ...]
    remediation: str
    #: Returns a detail string when the rule fires, or None when it passes.
    check: Callable[[Snapshot], str | None]
    references: tuple[str, ...] = field(default=())


def data(snapshot: Snapshot, collector: str) -> dict[str, Any]:
    """Collector data, or an empty dict when the collector did not report.

    Returning empty rather than raising means one failed collector suppresses
    its own rules instead of aborting the evaluation. The report states which
    collectors failed separately, so a suppressed rule is visible as a coverage
    gap rather than passing silently.
    """
    entry = snapshot.get("collectors", {}).get(collector, {})
    if entry.get("status") != "observed":
        return {}
    return entry.get("data", {}) or {}


def _plural(items: list[Any], limit: int = 5) -> str:
    shown = ", ".join(str(i) for i in items[:limit])
    return shown + (f" (+{len(items) - limit} more)" if len(items) > limit else "")


# ---------------------------------------------------------------------------
# Organization and identity
# ---------------------------------------------------------------------------


def _no_delegated_admin(s: Snapshot) -> str | None:
    org = data(s, "organizations")
    missing = org.get("security_services_without_delegated_admin") or []
    if not org.get("in_organization") or not missing:
        return None
    return (
        f"{len(missing)} security services have no delegated administrator, so each is "
        f"administered from the management account: {_plural(missing)}"
    )


def _scp_on_empty_ou(s: Snapshot) -> str | None:
    org = data(s, "organizations")
    if not org.get("in_organization"):
        return None

    populated: set[str] = set()
    empty: dict[str, str] = {}

    def walk(ous: list[dict[str, Any]]) -> None:
        for ou in ous:
            has_accounts = bool(ou["account_ids"]) or _descendants_have_accounts(ou)
            (populated.add(ou["id"]) if has_accounts else empty.setdefault(ou["id"], ou["name"]))
            walk(ou["children"])

    for root in org.get("roots", []):
        walk(root.get("organizational_units", []))

    ineffective = []
    for policy_type, policies in (org.get("policies") or {}).items():
        if policy_type != "SERVICE_CONTROL_POLICY":
            continue
        for policy in policies:
            if policy.get("aws_managed"):
                continue
            targets = policy.get("targets") or []
            if targets and all(t["id"] in empty for t in targets):
                ineffective.append(
                    f"{policy['name']} → {', '.join(empty[t['id']] for t in targets)}"
                )

    if not ineffective:
        return None
    return (
        f"{len(ineffective)} service control policies are attached only to organizational "
        f"units that contain no accounts, so they constrain nothing: {_plural(ineffective)}"
    )


def _descendants_have_accounts(ou: dict[str, Any]) -> bool:
    return any(
        child["account_ids"] or _descendants_have_accounts(child)
        for child in ou.get("children", [])
    )


def _scp_does_not_cover_management(s: Snapshot) -> str | None:
    org = data(s, "organizations")
    if not org.get("in_organization"):
        return None

    root_attached = []
    for policy in (org.get("policies") or {}).get("SERVICE_CONTROL_POLICY", []):
        if policy.get("aws_managed"):
            continue
        if any(t["type"] == "ROOT" for t in policy.get("targets") or []):
            root_attached.append(policy["name"])

    if not root_attached:
        return None
    return (
        f"{len(root_attached)} service control policies are attached at the organization "
        f"root ({_plural(root_attached)}). SCPs never apply to the management account, so "
        f"none of these constrain it — the account with the most privilege in the "
        f"organization is the one they do not reach."
    )


def _no_rcps(s: Snapshot) -> str | None:
    org = data(s, "organizations")
    if not org.get("in_organization"):
        return None
    if "RESOURCE_CONTROL_POLICY" not in (org.get("policy_types_enabled") or []):
        return None
    custom = [
        p
        for p in (org.get("policies") or {}).get("RESOURCE_CONTROL_POLICY", [])
        if not p.get("aws_managed")
    ]
    if custom:
        return None
    return (
        "Resource control policies are enabled but none are defined. Only the AWS-managed "
        "RCPFullAWSAccess is attached, so no organization-wide limit exists on who may be "
        "granted access to resources by a resource policy."
    )


def _admin_on_user(s: Snapshot) -> str | None:
    iam = data(s, "iam")
    offenders = [u["name"] for u in iam.get("users", []) if u["has_admin_policy"]]
    if not offenders:
        return None
    return (
        f"Administrator-grade policies are attached directly to IAM user(s): "
        f"{_plural(offenders)}. A user carries no session limit, no permission boundary, "
        f"and no central revocation path."
    )


def _long_lived_keys(s: Snapshot) -> str | None:
    iam = data(s, "iam")
    aged = [
        f"{u['name']} ({k['age_days']}d)"
        for u in iam.get("users", [])
        for k in u["access_keys"]
        if k["status"] == "Active" and (k["age_days"] or 0) >= 0
    ]
    if not aged:
        return None
    admin_users = {u["name"] for u in iam.get("users", []) if u["has_admin_policy"]}
    on_admin = [a for a in aged if a.split(" ")[0] in admin_users]
    suffix = (
        f" {len(on_admin)} of these belong to an administrator: {_plural(on_admin)}."
        if on_admin
        else ""
    )
    return (
        f"{len(aged)} active long-lived access key(s) exist: {_plural(aged)}. A static key "
        f"is a credential that cannot expire and does not appear in a session log.{suffix}"
    )


def _no_permission_boundaries(s: Snapshot) -> str | None:
    iam = data(s, "iam")
    roles = [r for r in iam.get("roles", []) if not r["service_linked"]]
    if not roles:
        return None
    without = [r["name"] for r in roles if not r["permission_boundary"]]
    if len(without) < len(roles):
        return None
    return (
        f"None of the {len(roles)} customer-managed roles has a permissions boundary. A "
        f"boundary is the only IAM control that survives someone attaching a wider policy "
        f"later."
    )


def _admin_execution_role(s: Snapshot) -> str | None:
    iam = data(s, "iam")
    offenders = [
        r["name"]
        for r in iam.get("roles", [])
        if r["has_admin_policy"]
        and any(
            svc in r["trust"]["service_principals"]
            for svc in ("lambda.amazonaws.com", "ec2.amazonaws.com", "ecs-tasks.amazonaws.com")
        )
    ]
    if not offenders:
        return None
    return (
        f"Compute execution role(s) carry administrator access: {_plural(offenders)}. Any "
        f"code that runs under them — including a dependency compromised upstream — has "
        f"the whole account."
    )


def _ci_role_admin(s: Snapshot) -> str | None:
    third = data(s, "third_party")
    admin = third.get("external_granting_admin") or []
    federated = {
        e["role"] for e in third.get("external_trusts", []) if e["federated_principals"]
    }
    offenders = [r for r in admin if r in federated]
    if not offenders:
        return None
    return (
        f"Federated (CI/CD or SSO) role(s) grant administrator access: {_plural(offenders)}. "
        f"A pipeline with organization-wide admin turns any repository compromise into an "
        f"account compromise."
    )


def _root_hardware_mfa(s: Snapshot) -> str | None:
    root = data(s, "root_controls")
    if not root:
        return None
    if not root.get("root_mfa_enabled"):
        return "The root user has no MFA device registered."
    if root.get("root_mfa_is_virtual"):
        return (
            "Root MFA is a virtual (software) device. For the one identity that can undo "
            "every other control, a phishing-resistant hardware key is the appropriate "
            "control."
        )
    return None


def _root_access_keys(s: Snapshot) -> str | None:
    root = data(s, "root_controls")
    if not root or not root.get("root_access_keys"):
        return None
    return (
        f"The root user has {root['root_access_keys']} access key(s). Root should have no "
        f"programmatic credentials at all."
    )


def _identity_center_boundaries(s: Snapshot) -> str | None:
    ic = data(s, "identity_center")
    if not ic.get("enabled"):
        return None
    admin = [
        p
        for p in ic.get("permission_sets", [])
        if p["grants_admin"] and not p["has_permission_boundary"]
    ]
    if not admin:
        return None
    detail = ", ".join(f"{p['name']} ({p['session_duration']})" for p in admin)
    return (
        f"{len(admin)} administrator permission set(s) have no permissions boundary: "
        f"{detail}. Session duration is the only limit on how long that access lasts."
    )


def _identity_center_session_length(s: Snapshot) -> str | None:
    ic = data(s, "identity_center")
    if not ic.get("enabled"):
        return None
    long_sessions = [
        f"{p['name']} ({p['session_duration']})"
        for p in ic.get("permission_sets", [])
        if p["grants_admin"] and _hours(p["session_duration"]) > 4
    ]
    if not long_sessions:
        return None
    return (
        f"Administrator permission set(s) issue sessions longer than four hours: "
        f"{_plural(long_sessions)}. A stolen session token stays valid for that long."
    )


def _hours(duration: str | None) -> float:
    """Parse the ISO-8601 duration Identity Center uses (PT1H, PT12H, PT30M)."""
    if not duration or not duration.startswith("PT"):
        return 0.0
    body = duration[2:]
    hours = 0.0
    number = ""
    for char in body:
        if char.isdigit():
            number += char
        elif char == "H":
            hours += float(number or 0)
            number = ""
        elif char == "M":
            hours += float(number or 0) / 60
            number = ""
    return hours


# ---------------------------------------------------------------------------
# Logging and detection
# ---------------------------------------------------------------------------


def _no_org_trail(s: Snapshot) -> str | None:
    ct = data(s, "cloudtrail")
    if not ct:
        return None
    if ct.get("has_organization_trail"):
        return None
    return (
        "No logging organization CloudTrail exists. Without one, a new account joins the "
        "organization with no audit trail and nobody is notified."
    )


def _trail_not_encrypted(s: Snapshot) -> str | None:
    ct = data(s, "cloudtrail")
    offenders = [
        t["name"] for t in ct.get("trails", []) if t["is_logging"] and not t["kms_key_id"]
    ]
    if not offenders:
        return None
    return (
        f"CloudTrail log files are not encrypted with a customer-managed key: "
        f"{_plural(offenders)}. Anyone with read access to the destination bucket can read "
        f"the full audit history."
    )


def _trail_no_data_events(s: Snapshot) -> str | None:
    ct = data(s, "cloudtrail")
    offenders = [
        t["name"]
        for t in ct.get("trails", [])
        if t["is_logging"] and not t["data_events_configured"]
    ]
    if not offenders or not ct.get("trails"):
        return None
    return (
        f"No trail records data events: {_plural(offenders)}. Management events show that a "
        f"role was assumed; data events show which objects it then read. Only the second "
        f"answers 'what was taken' during an incident."
    )


def _config_not_recording(s: Snapshot) -> str | None:
    cfg = data(s, "config")
    if not cfg:
        return None
    missing = cfg.get("regions_not_recording") or []
    if not missing:
        return None
    orphaned = [
        f"{region} ({v['rule_count']} rules defined)"
        for region, v in (cfg.get("by_region") or {}).items()
        if not v.get("recording") and v.get("rule_count")
    ]
    suffix = (
        f" Rules are defined where nothing is recorded, so they evaluate nothing: "
        f"{_plural(orphaned)}."
        if orphaned
        else ""
    )
    return (
        f"AWS Config is not recording in {len(missing)} of "
        f"{len(cfg.get('by_region') or {})} scanned regions ({_plural(missing)}).{suffix}"
    )


def _guardduty_coverage(s: Snapshot) -> str | None:
    gd = data(s, "guardduty")
    missing = gd.get("regions_not_enabled") or []
    if not missing:
        return None
    return (
        f"GuardDuty is not enabled in {len(missing)} scanned region(s): {_plural(missing)}. "
        f"An attacker chooses the region without a detector."
    )


def _guardduty_features(s: Snapshot) -> str | None:
    gd = data(s, "guardduty")
    uneven = {
        region: v["features_disabled"]
        for region, v in (gd.get("by_region") or {}).items()
        if v.get("enabled") and v.get("features_disabled")
    }
    if not uneven:
        return None
    detail = "; ".join(
        f"{region}: {_plural(features, 4)}" for region, features in uneven.items()
    )
    return (
        f"GuardDuty is enabled but with protection plans switched off, unevenly across "
        f"regions — {detail}. Coverage that differs by region is coverage nobody can reason "
        f"about."
    )


def _securityhub_standards(s: Snapshot) -> str | None:
    sh = data(s, "securityhub")
    incomplete = [
        f"{region}: {st['arn'].rsplit('/', 3)[-3]}"
        for region, v in (sh.get("by_region") or {}).items()
        if v.get("enabled")
        for st in v.get("standards", [])
        if st.get("status") != "READY"
    ]
    if not incomplete:
        return None
    return (
        f"Security Hub standards are not in a READY state: {_plural(incomplete)}. Controls "
        f"that have not finished initialising are not evaluating anything."
    )


def _securityhub_old_cis(s: Snapshot) -> str | None:
    sh = data(s, "securityhub")
    old = [
        f"{region}: CIS {st['arn'].rsplit('/v/', 1)[-1]}"
        for region, v in (sh.get("by_region") or {}).items()
        for st in v.get("standards", [])
        if "cis-aws-foundations-benchmark" in st.get("arn", "")
        and st["arn"].rsplit("/v/", 1)[-1].startswith("1.")
    ]
    if not old:
        return None
    return (
        f"An outdated CIS AWS Foundations Benchmark version is enabled: {_plural(old)}. "
        f"Later versions add controls for services that did not exist when 1.2 was written."
    )


def _no_external_access_analyzer(s: Snapshot) -> str | None:
    aa = data(s, "access_analyzer")
    if not aa:
        return None
    types = aa.get("analyzer_types_present") or []
    if any("UNUSED_ACCESS" not in t for t in types):
        return None
    if not types:
        return "No IAM Access Analyzer is configured in any scanned region."
    return (
        "Only an unused-access analyzer is configured. The external-access analyzer — the "
        "one that finds resources reachable from outside the account or organization — is "
        "not enabled anywhere."
    )


def _analyzer_coverage(s: Snapshot) -> str | None:
    aa = data(s, "access_analyzer")
    by_region = aa.get("by_region") or {}
    missing = [r for r, v in by_region.items() if not v.get("enabled")]
    if not missing or not by_region:
        return None
    return f"IAM Access Analyzer is absent in {len(missing)} scanned region(s): {_plural(missing)}."


# ---------------------------------------------------------------------------
# Network, data and workload
# ---------------------------------------------------------------------------


def _vpc_flow_logs(s: Snapshot) -> str | None:
    vpc = data(s, "vpc")
    missing = vpc.get("without_flow_logs") or []
    if not missing:
        return None
    return (
        f"{len(missing)} VPC(s) have no flow logs: {_plural(missing)}. Network-level "
        f"evidence does not exist retroactively — it is either being recorded now or it is "
        f"not available during the incident."
    )


def _default_vpcs(s: Snapshot) -> str | None:
    vpc = data(s, "vpc")
    defaults = vpc.get("default_vpcs") or []
    if not defaults:
        return None
    return (
        f"{len(defaults)} default VPC(s) are present: {_plural(defaults)}. A default VPC "
        f"ships with an internet gateway, public subnets and a permissive default security "
        f"group in every region, whether or not anyone intends to use it."
    )


def _sg_open(s: Snapshot) -> str | None:
    sg = data(s, "security_groups")
    sensitive = sg.get("groups_exposing_sensitive_ports") or []
    if sensitive:
        rules = [
            f"{r['group_id']} {','.join(r['sensitive_ports_exposed'])}"
            for r in sg.get("internet_open_rules", [])
            if r["sensitive_ports_exposed"]
        ]
        return (
            f"{len(sensitive)} security group(s) expose administrative or database ports to "
            f"the internet: {_plural(rules)}"
        )
    open_groups = sg.get("groups_open_to_internet") or []
    if not open_groups:
        return None
    return (
        f"{len(open_groups)} security group(s) allow ingress from 0.0.0.0/0: "
        f"{_plural(open_groups)}. Confirm each is intended to be public."
    )


def _account_public_access_block(s: Snapshot) -> str | None:
    s3 = data(s, "s3")
    if not s3 or s3.get("account_fully_blocked"):
        return None
    return (
        "S3 account-level public access block is not fully enabled. Per-bucket settings "
        "protect the buckets that exist; the account-level block protects the ones somebody "
        "creates next week."
    )


def _bucket_exposure(s: Snapshot) -> str | None:
    s3 = data(s, "s3")
    public = s3.get("buckets_public_by_policy") or []
    unblocked = s3.get("buckets_not_fully_blocked") or []
    if public:
        return f"{len(public)} bucket(s) are public by policy: {_plural(public)}"
    if unblocked:
        return (
            f"{len(unblocked)} bucket(s) do not have all four public-access-block settings "
            f"enabled: {_plural(unblocked)}"
        )
    return None


def _no_cmks(s: Snapshot) -> str | None:
    kms = data(s, "kms")
    if not kms or kms.get("total"):
        return None
    return (
        "No customer-managed KMS keys exist; everything encrypted relies on AWS-managed "
        "keys. Those cannot carry a key policy, so encryption cannot be used as an access "
        "control boundary and key usage cannot be restricted per workload."
    )


def _kms_rotation(s: Snapshot) -> str | None:
    kms = data(s, "kms")
    without = kms.get("without_rotation") or []
    if not without:
        return None
    return (
        f"{len(without)} customer-managed key(s) do not have rotation enabled: "
        f"{_plural(without)}"
    )


def _api_without_authorizer(s: Snapshot) -> str | None:
    api = data(s, "api_gateway")
    missing = api.get("without_authorizer") or []
    if not missing:
        return None
    return (
        f"{len(missing)} API stage(s) have no authorizer attached: {_plural(missing)}. "
        f"Authorization is then entirely the function's responsibility, with nothing in "
        f"front of it to fail closed."
    )


def _api_without_logging(s: Snapshot) -> str | None:
    api = data(s, "api_gateway")
    missing = api.get("without_access_logging") or []
    if not missing:
        return None
    return f"{len(missing)} API stage(s) have no access logging: {_plural(missing)}"


def _unauthenticated_function_urls(s: Snapshot) -> str | None:
    exposure = data(s, "exposure")
    urls = exposure.get("unauthenticated_function_urls") or []
    if not urls:
        return None
    return (
        f"{len(urls)} Lambda function URL(s) use AuthType NONE: {_plural(urls)}. These are "
        f"public HTTPS endpoints that bypass API Gateway and every control attached to it."
    )


def _public_databases(s: Snapshot) -> str | None:
    exposure = data(s, "exposure")
    dbs = [d["identifier"] for d in exposure.get("public_databases", [])]
    if not dbs:
        return None
    return f"{len(dbs)} database instance(s) are publicly accessible: {_plural(dbs)}"


def _lambda_secrets_in_env(s: Snapshot) -> str | None:
    lam = data(s, "lambda")
    offenders = lam.get("with_secret_shaped_env_vars") or []
    if not offenders:
        return None
    detail = "; ".join(f"{o['function']}: {', '.join(o['variables'])}" for o in offenders)
    return (
        f"{len(offenders)} function(s) have environment variables whose names suggest "
        f"credentials — {detail}. Values were not read. Without a customer-managed key, "
        f"anyone with lambda:GetFunctionConfiguration can read them in plaintext."
    )


def _lambda_deprecated_runtime(s: Snapshot) -> str | None:
    lam = data(s, "lambda")
    offenders = lam.get("deprecated_runtimes") or []
    if not offenders:
        return None
    return (
        f"{len(offenders)} function(s) run a deprecated runtime: {_plural(offenders)}. The "
        f"runtime itself stops receiving security patches, which dependency scanning of the "
        f"function's own code will never surface."
    )


def _secrets_rotation(s: Snapshot) -> str | None:
    sec = data(s, "secrets")
    without = sec.get("secrets_without_rotation") or []
    if not without:
        return None
    return f"{len(without)} secret(s) have no automatic rotation configured: {_plural(without)}"


def _plaintext_parameters(s: Snapshot) -> str | None:
    sec = data(s, "secrets")
    offenders = sec.get("plaintext_parameters_with_secret_names") or []
    if not offenders:
        return None
    return (
        f"{len(offenders)} SSM parameter(s) of type String have credential-shaped names: "
        f"{_plural(offenders)}. Values were not read. A String parameter is stored and "
        f"returned unencrypted."
    )


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------


def _ci_without_oidc(s: Snapshot) -> str | None:
    cicd = data(s, "cicd")
    if not cicd or cicd.get("any_uses_aws_oidc"):
        return None
    return (
        "No GitHub Actions workflow authenticates to AWS via OIDC. Any deployment therefore "
        "depends on a stored credential, which is the artefact OIDC exists to remove."
    )


def _unpinned_actions(s: Snapshot) -> str | None:
    cicd = data(s, "cicd")
    unpinned = cicd.get("total_actions_not_sha_pinned") or []
    if not unpinned:
        return None
    return (
        f"{len(unpinned)} GitHub Action reference(s) are not pinned to a commit SHA: "
        f"{_plural(unpinned)}. A tag can be moved to point at different code after review."
    )


def _no_dependabot(s: Snapshot) -> str | None:
    cicd = data(s, "cicd")
    if not cicd or cicd.get("has_dependabot"):
        return None
    return (
        "No Dependabot configuration is present, so dependency and action updates are not "
        "raised automatically."
    )


# ---------------------------------------------------------------------------
# The catalogue
# ---------------------------------------------------------------------------

SRA = "https://docs.aws.amazon.com/prescriptive-guidance/latest/security-reference-architecture/"
WELL_ARCHITECTED = "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/"

RULES: tuple[Rule, ...] = (
    Rule("ORG-001", "Security services have no delegated administrator", "high", "identity",
         (7,), "Delegate GuardDuty, Security Hub, Config, Access Analyzer, Inspector, Macie "
         "and Detective administration to a dedicated security-tooling account.",
         _no_delegated_admin, (SRA + "organizations.html",)),
    Rule("ORG-002", "SCPs attached only to empty organizational units", "medium", "identity",
         (7,), "Move accounts into the OUs the policies target, or attach the policies "
         "where the accounts actually are. Verify with DescribeEffectivePolicy.",
         _scp_on_empty_ou),
    Rule("ORG-003", "Root-attached SCPs do not constrain the management account", "high",
         "identity", (5, 7), "Move workloads out of the management account, keep it for "
         "organization administration only, and rely on controls that do apply to it: "
         "hardware MFA on root, centralised root credential management, and CloudTrail.",
         _scp_does_not_cover_management, (SRA + "management-account.html",)),
    Rule("ORG-004", "Resource control policies enabled but unused", "medium", "identity",
         (7,), "Define RCPs restricting S3, KMS, STS and SQS resource policies to trusted "
         "organization principals, closing the confused-deputy path SCPs cannot reach.",
         _no_rcps),
    Rule("IAM-001", "Administrator access attached directly to an IAM user", "high",
         "identity", (4,), "Move the access to a role assumed through IAM Identity Center, "
         "with a permissions boundary and a short session duration.",
         _admin_on_user, (WELL_ARCHITECTED + "sec_permissions_least_privileges.html",)),
    Rule("IAM-002", "Active long-lived access keys", "high", "identity", (4,),
         "Replace with short-lived credentials from Identity Center or OIDC federation, "
         "then delete the key. Deactivate before deleting so CloudTrail correlation survives.",
         _long_lived_keys),
    Rule("IAM-003", "No role has a permissions boundary", "medium", "identity", (4,),
         "Define a boundary policy and require it on role creation, enforced by SCP "
         "condition and by the CDK aspect in platform/lib/cdk-security.",
         _no_permission_boundaries),
    Rule("IAM-004", "Compute execution role carries administrator access", "critical",
         "identity", (4, 16), "Replace the managed policy with an enumerated, "
         "resource-scoped policy for exactly what the function calls.",
         _admin_execution_role),
    Rule("IAM-005", "Federated CI/CD or SSO role grants administrator access", "high",
         "identity", (4, 18), "Split into plan and apply roles, scope the OIDC trust to "
         "specific repository, branch and environment claims, and gate production behind "
         "an approval.",
         _ci_role_admin),
    Rule("IAM-006", "Root MFA is absent or software-based", "high", "identity", (5,),
         "Register a phishing-resistant hardware security key for root and store it under "
         "dual control.",
         _root_hardware_mfa),
    Rule("IAM-007", "Root user has access keys", "critical", "identity", (5,),
         "Delete root access keys. There is no supported use case for them.",
         _root_access_keys),
    Rule("IAM-008", "Administrator permission sets have no permissions boundary", "medium",
         "identity", (6,), "Attach a boundary to every admin permission set so its effective "
         "privilege cannot be widened by a later policy change.",
         _identity_center_boundaries),
    Rule("IAM-009", "Administrator sessions last longer than four hours", "medium",
         "identity", (6,), "Reduce admin permission-set session duration to one hour; "
         "re-authentication is cheap and a stolen token's useful life is the whole risk.",
         _identity_center_session_length),
    Rule("LOG-001", "No organization CloudTrail", "critical", "logging", (8,),
         "Create an organization trail in the management account, delivering to a "
         "restricted log-archive account with log file validation and a CMK.",
         _no_org_trail),
    Rule("LOG-002", "CloudTrail logs are not encrypted with a customer-managed key", "medium",
         "logging", (8, 12), "Encrypt the trail with a KMS key whose policy restricts "
         "decryption to the security and audit roles.",
         _trail_not_encrypted),
    Rule("LOG-003", "No CloudTrail data events configured", "medium", "logging", (8,),
         "Enable data events selectively for buckets and functions holding sensitive data, "
         "where the volume and cost are justified.",
         _trail_no_data_events),
    Rule("LOG-004", "AWS Config is not recording", "high", "logging", (11,),
         "Enable the configuration recorder in every region in scope, including global "
         "resource types, before relying on any Config rule or conformance pack.",
         _config_not_recording),
    Rule("DET-001", "GuardDuty not enabled in every region", "high", "logging", (9,),
         "Enable GuardDuty organization-wide with auto-enable for new accounts and regions.",
         _guardduty_coverage),
    Rule("DET-002", "GuardDuty protection plans disabled and uneven across regions", "medium",
         "logging", (9,), "Enable the same protection plans in every region, or record a "
         "written decision for each exclusion.",
         _guardduty_features),
    Rule("DET-003", "Security Hub standards are not READY", "medium", "logging", (10,),
         "Investigate why initialisation has not completed; a standard that is not READY is "
         "evaluating nothing.",
         _securityhub_standards),
    Rule("DET-004", "Outdated CIS benchmark version enabled", "low", "logging", (10,),
         "Enable CIS AWS Foundations Benchmark v3.0 or later alongside AWS FSBP.",
         _securityhub_old_cis),
    Rule("DET-005", "No external-access IAM Access Analyzer", "high", "identity", (4, 22),
         "Create an organization-scoped external-access analyzer; it is the control that "
         "finds resources shared outside the organization.",
         _no_external_access_analyzer),
    Rule("DET-006", "IAM Access Analyzer missing in some regions", "medium", "identity",
         (4,), "Create an analyzer in every region in scope; findings are regional.",
         _analyzer_coverage),
    Rule("NET-001", "VPCs without flow logs", "medium", "infrastructure", (14,),
         "Enable flow logs to a central destination for every VPC carrying workload traffic.",
         _vpc_flow_logs),
    Rule("NET-002", "Default VPCs present", "low", "infrastructure", (14,),
         "Delete unused default VPCs, or record why they are retained. Enforce with a "
         "Config rule so they do not reappear in a newly enabled region.",
         _default_vpcs),
    Rule("NET-003", "Security groups open to the internet", "high", "infrastructure", (15,),
         "Restrict ingress to the specific source security group or prefix list. Where "
         "public access is intended, front it with a load balancer or CloudFront and WAF.",
         _sg_open),
    Rule("DAT-001", "S3 account-level public access block incomplete", "high", "data", (13,),
         "Enable all four settings at the account level, and enforce organization-wide "
         "with an SCP.",
         _account_public_access_block),
    Rule("DAT-002", "Buckets exposed or not fully blocked", "high", "data", (13,),
         "Enable all four public-access-block settings per bucket and remove any public "
         "bucket policy.",
         _bucket_exposure),
    Rule("DAT-003", "No customer-managed KMS keys", "medium", "data", (12,),
         "Introduce customer-managed keys for sensitive data stores so encryption can carry "
         "a key policy and act as an access boundary.",
         _no_cmks),
    Rule("DAT-004", "KMS keys without rotation", "low", "data", (12,),
         "Enable automatic annual rotation on customer-managed keys.",
         _kms_rotation),
    Rule("DAT-005", "Secrets without automatic rotation", "medium", "data", (17,),
         "Configure rotation with a Lambda rotation function, or record why the secret "
         "cannot be rotated automatically.",
         _secrets_rotation),
    Rule("DAT-006", "Plaintext SSM parameters with credential-shaped names", "high", "data",
         (17,), "Move to SecureString parameters or Secrets Manager, then rotate the value: "
         "anything stored as String should be treated as disclosed.",
         _plaintext_parameters),
    Rule("APP-001", "API stages without an authorizer", "high", "code", (16,),
         "Attach a JWT, Cognito or IAM authorizer at the API layer so unauthenticated "
         "requests never reach the function.",
         _api_without_authorizer),
    Rule("APP-002", "API stages without access logging", "medium", "code", (16,),
         "Enable access logging to CloudWatch Logs with a structured format including "
         "identity, source IP and status.",
         _api_without_logging),
    Rule("APP-003", "Unauthenticated Lambda function URLs", "critical", "code", (3, 16),
         "Set AuthType to AWS_IAM, or remove the function URL and route through API Gateway.",
         _unauthenticated_function_urls),
    Rule("APP-004", "Publicly accessible databases", "critical", "data", (3, 14),
         "Set PubliclyAccessible to false and place the instance in private subnets.",
         _public_databases),
    Rule("APP-005", "Credential-shaped Lambda environment variables", "high", "code", (17,),
         "Move the values to Secrets Manager and read them at runtime under a scoped role.",
         _lambda_secrets_in_env),
    Rule("APP-006", "Deprecated Lambda runtimes", "high", "code", (16, 20),
         "Upgrade to a supported runtime; unsupported runtimes stop receiving patches.",
         _lambda_deprecated_runtime),
    Rule("CI-001", "No AWS OIDC federation in CI", "medium", "code", (18,),
         "Wire the existing github-oidc Terraform module into the workflows and remove any "
         "stored AWS credential.",
         _ci_without_oidc),
    Rule("CI-002", "GitHub Actions not pinned to commit SHAs", "medium", "code", (18,),
         "Pin every third-party action to a full commit SHA and let Dependabot raise "
         "updates.",
         _unpinned_actions),
    Rule("CI-003", "No Dependabot configuration", "low", "code", (18, 20),
         "Add .github/dependabot.yml covering pip, npm, terraform and github-actions.",
         _no_dependabot),
)


def evaluate(snapshot: Snapshot, rules: tuple[Rule, ...] = RULES) -> list[Finding]:
    """Run every rule against a snapshot, most severe first."""
    findings: list[Finding] = []
    for rule in rules:
        detail = rule.check(snapshot)
        if detail is None:
            continue
        findings.append(
            Finding(
                rule_id=rule.id,
                title=rule.title,
                severity=rule.severity,
                domain=rule.domain,
                checklist=rule.checklist,
                detail=detail,
                remediation=rule.remediation,
                references=rule.references,
            )
        )
    return sorted(findings, key=lambda f: (SEVERITY_ORDER[f.severity], f.rule_id))
