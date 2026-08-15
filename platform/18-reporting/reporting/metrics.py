"""Security metrics computed from a discovery snapshot.

Implements the indicators defined in ``readiness/02-security-metrics.md``, which
sets two constraints this module has to honour rather than quietly drop:

**Every metric carries its gaming mode.** A metric without one gets gamed, so
the failure mode travels with the number instead of living in a document nobody
opens next to the dashboard.

**There is no overall score.** That document rejects one explicitly — a single
number compresses away every decision worth discussing, and it is the first
thing anyone asks for. Refusing it is the point.

The third constraint is one the document implies and this module makes
explicit: **roughly half those metrics cannot be computed from an AWS snapshot
at all.** Pipeline pass rate needs CI history; MTTR needs incident history;
every "health of the function" signal is a human observation. Reporting only
the computable half and staying quiet about the rest would imply the coverage
is complete, so unmeasurable metrics are emitted with a stated reason and a
named source instead.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

Snapshot = dict[str, Any]


@dataclass(frozen=True)
class Metric:
    """One indicator, with everything needed to argue about it."""

    key: str
    name: str
    #: None when the metric cannot be computed from an AWS snapshot.
    value: float | int | str | None
    target: str
    #: How this number gets gamed. Required — see the module docstring.
    gaming: str
    #: Where the value came from, or where it would have to come from.
    source: str
    #: Set when value is None: why it is not computable here.
    unmeasurable_because: str | None = None
    #: Free-form supporting detail, shown under the number.
    detail: str = ""

    @property
    def measured(self) -> bool:
        return self.value is not None


@dataclass
class MetricSet:
    generated_at: str
    account: str
    regions: int
    metrics: list[Metric] = field(default_factory=list)

    @property
    def measured(self) -> list[Metric]:
        return [m for m in self.metrics if m.measured]

    @property
    def unmeasured(self) -> list[Metric]:
        return [m for m in self.metrics if not m.measured]


def _data(snapshot: Snapshot, collector: str) -> dict[str, Any]:
    entry = snapshot.get("collectors", {}).get(collector, {})
    if entry.get("status") != "observed":
        return {}
    return entry.get("data", {}) or {}


# ---------------------------------------------------------------------------
# Leading indicators — do controls exist and hold?
# ---------------------------------------------------------------------------


def _long_lived_credentials(s: Snapshot) -> Metric:
    iam = _data(s, "iam")
    keys = [
        (u["name"], k["age_days"])
        for u in iam.get("users", [])
        for k in u.get("access_keys", [])
        if k.get("status") == "Active" and k.get("age_days") is not None
    ]
    over_90 = [k for k in keys if k[1] > 90]
    return Metric(
        key="long_lived_credentials",
        name="Active access keys older than 90 days",
        value=len(over_90) if iam else None,
        target="Trending to 0",
        gaming="Rotating without reducing the count — a fresh key is still a static credential.",
        source="discovery: iam.users[].access_keys",
        unmeasurable_because=None if iam else "IAM collector did not report",
        detail=(
            f"{len(keys)} active key(s); oldest is "
            f"{max((k[1] for k in keys), default=0)} days"
            if keys
            else "No active access keys"
        ),
    )


def _permission_boundary_coverage(s: Snapshot) -> Metric:
    iam = _data(s, "iam")
    roles = [r for r in iam.get("roles", []) if not r.get("service_linked")]
    if not roles:
        return Metric(
            key="permission_boundary_coverage",
            name="Customer-managed roles with a permissions boundary",
            value=None,
            target="> 95% within 6 months",
            gaming="Counting roles that do not matter — service-linked roles are excluded here.",
            source="discovery: iam.roles",
            unmeasurable_because="No customer-managed roles observed",
        )
    with_boundary = [r for r in roles if r.get("permission_boundary")]
    return Metric(
        key="permission_boundary_coverage",
        name="Customer-managed roles with a permissions boundary",
        value=round(100 * len(with_boundary) / len(roles), 1),
        target="> 95% within 6 months",
        gaming="Counting roles that do not matter — service-linked roles are excluded here.",
        source="discovery: iam.roles",
        detail=f"{len(with_boundary)} of {len(roles)} roles",
    )


def _detection_coverage(s: Snapshot) -> Metric:
    """Coverage as a fraction of scanned regions, never as a boolean.

    "GuardDuty is enabled" is true and useless if it means one region out of
    seventeen — an attacker picks the region without a detector.
    """
    parts: list[str] = []
    covered = total = 0
    for collector, label, key in (
        ("guardduty", "GuardDuty", "regions_enabled"),
        ("securityhub", "Security Hub", "regions_enabled"),
        ("config", "Config", "regions_recording"),
        ("access_analyzer", "Access Analyzer", "regions_enabled"),
    ):
        data = _data(s, collector)
        by_region = data.get("by_region") or {}
        if not by_region:
            continue
        enabled = len(data.get(key) or [])
        covered += enabled
        total += len(by_region)
        parts.append(f"{label} {enabled}/{len(by_region)}")

    return Metric(
        key="detection_coverage",
        name="Detection services enabled, across scanned regions",
        value=round(100 * covered / total, 1) if total else None,
        target="Documented, with gaps named",
        gaming=(
            "Claiming coverage for a service that is enabled but has its protection plans "
            "switched off — enablement is not detection."
        ),
        source="discovery: guardduty, securityhub, config, access_analyzer",
        unmeasurable_because=None if total else "No detection collectors reported",
        detail=" · ".join(parts),
    )


def _internet_exposure(s: Snapshot) -> Metric:
    exposure = _data(s, "exposure")
    sg = _data(s, "security_groups")
    if not exposure:
        return Metric(
            key="internet_exposure",
            name="Internet-reachable resources",
            value=None,
            target="Every entry justified and owned",
            gaming="Narrowing the definition of internet-facing.",
            source="discovery: exposure, security_groups",
            unmeasurable_because="Exposure collector did not report",
        )
    unauth = len(exposure.get("unauthenticated_function_urls") or [])
    public_db = len(exposure.get("public_databases") or [])
    open_sg = len(sg.get("groups_open_to_internet") or [])
    return Metric(
        key="internet_exposure",
        name="Internet-reachable resources",
        value=exposure.get("total_internet_facing", 0),
        target="Every entry justified and owned",
        gaming="Narrowing the definition of internet-facing.",
        source="discovery: exposure, security_groups",
        detail=(
            f"{open_sg} security group(s) open to 0.0.0.0/0 · "
            f"{unauth} unauthenticated function URL(s) · "
            f"{public_db} public database(s)"
        ),
    )


def _encryption_posture(s: Snapshot) -> Metric:
    s3 = _data(s, "s3")
    kms = _data(s, "kms")
    if not s3:
        return Metric(
            key="encryption_posture",
            name="Buckets without default encryption",
            value=None,
            target="0",
            gaming="Counting default AES256 as equivalent to a customer-managed key.",
            source="discovery: s3, kms",
            unmeasurable_because="S3 collector did not report",
        )
    return Metric(
        key="encryption_posture",
        name="Buckets without default encryption",
        value=len(s3.get("buckets_unencrypted") or []),
        target="0",
        gaming=(
            "Counting SSE-S3 as equivalent to SSE-KMS. An AWS-managed key carries no key "
            "policy, so encryption cannot act as an access boundary."
        ),
        source="discovery: s3, kms",
        detail=(
            f"{s3.get('total', 0)} bucket(s) · "
            f"{kms.get('total', 0)} customer-managed key(s) · "
            f"{len(kms.get('without_rotation') or [])} without rotation"
        ),
    )


def _privileged_identities(s: Snapshot) -> Metric:
    iam = _data(s, "iam")
    totals = iam.get("totals") or {}
    if not totals:
        return Metric(
            key="privileged_identities",
            name="Identities carrying administrator access",
            value=None,
            target="Federated only; zero IAM users",
            gaming="Renaming a policy rather than reducing what it grants.",
            source="discovery: iam.totals",
            unmeasurable_because="IAM collector did not report",
        )
    users = totals.get("users_with_admin", 0)
    roles = totals.get("roles_with_admin", 0)
    return Metric(
        key="privileged_identities",
        name="Identities carrying administrator access",
        value=users + roles,
        target="Federated only; zero IAM users",
        gaming=(
            "Renaming a policy rather than reducing what it grants — this counts the known "
            "administrator-grade managed policies, not every wide inline policy."
        ),
        source="discovery: iam.totals",
        detail=f"{users} IAM user(s) · {roles} role(s)",
    )


# ---------------------------------------------------------------------------
# Lagging indicators — build-time, from the repository
# ---------------------------------------------------------------------------


def _findings_past_sla(ledger_breaches: int | None) -> Metric:
    return Metric(
        key="findings_past_sla",
        name="Findings past their remediation SLA",
        value=ledger_breaches,
        target="0 — enforced in CI, so this is a build metric",
        gaming="Suppressing a finding rather than fixing it; suppressions are excluded here.",
        source="scripts/vuln_sla.py against evidence/vuln-ledger.json",
        unmeasurable_because=None if ledger_breaches is not None else "No SLA report available",
    )


def _expired_exceptions(expired: int | None) -> Metric:
    return Metric(
        key="expired_exceptions",
        name="Expired risk exceptions",
        value=expired,
        target="0 — an exception that renews silently is an allowlist",
        gaming="Extending the expiry instead of re-arguing the acceptance.",
        source="evidence/vuln-exceptions.json",
        unmeasurable_because=None if expired is not None else "No exception register available",
    )


def _pipeline_oidc(s: Snapshot) -> Metric:
    cicd = _data(s, "cicd")
    if not cicd:
        return Metric(
            key="pipeline_oidc",
            name="Workflows authenticating to AWS via OIDC",
            value=None,
            target="100% of workflows that touch AWS",
            gaming="Counting workflows that never needed AWS access.",
            source="repository: .github/workflows",
            unmeasurable_because="CI/CD collector did not report",
        )
    unpinned = len(cicd.get("total_actions_not_sha_pinned") or [])
    return Metric(
        key="pipeline_oidc",
        name="Pipeline uses AWS OIDC federation",
        value="yes" if cicd.get("any_uses_aws_oidc") else "no",
        target="100% of workflows that touch AWS",
        gaming="Counting workflows that never needed AWS access.",
        source="repository: .github/workflows",
        detail=f"{cicd.get('workflow_count', 0)} workflow(s) · {unpinned} action(s) not SHA-pinned",
    )


# ---------------------------------------------------------------------------
# What cannot be computed here, and why
# ---------------------------------------------------------------------------

# Emitted with a stated reason rather than omitted. A metrics page that shows
# only the computable half implies the coverage is complete, and the metrics
# missing here are not the unimportant ones — they are the outcome measures.
UNMEASURABLE: tuple[tuple[str, str, str, str, str], ...] = (
    (
        "regulated_data_paths",
        "% regulated data paths through an allowlisted interface",
        "100%",
        "Redefining 'regulated' narrowly.",
        "Requires a data classification this account does not carry in tags. "
        "Needs the data-flow map in docs/01-threat-model.md applied to real resources.",
    ),
    (
        "pipeline_pass_rate",
        "Pipeline gate pass rate on first attempt",
        "> 85%",
        "Weakening the gates.",
        "Requires GitHub Actions run history, not an AWS snapshot. "
        "Available from the API once the workflow has enough runs.",
    ),
    (
        "mttr_critical",
        "Mean time to remediate, critical",
        "≤ 7 days",
        "Closing tickets without shipping the fix.",
        "Requires remediation history. The vuln-ledger records first-seen dates, "
        "so this becomes computable after findings have been closed as well as opened.",
    ),
    (
        "mttd_tabletop",
        "Mean time to detect (tabletop)",
        "< 30 min",
        "Rehearsing the exercise rather than the response.",
        "Requires running the incident playbooks in docs/05-incident-response/ "
        "as exercises. Cannot be derived from configuration.",
    ),
    (
        "attack_coverage",
        "Detection coverage vs ATT&CK Cloud",
        "Documented, gaps named",
        "Claiming coverage for a rule that never fires.",
        "Requires mapping the eight detections in infra/terraform/detections/ to "
        "technique IDs, and confirming each rule has fired at least once in test.",
    ),
    (
        "function_health",
        "Health of the security function (4 signals)",
        "See readiness/02-security-metrics.md",
        "Reporting the comfortable three and omitting near-misses.",
        "Human observations: design-review invitations, guardrail-to-gate ratio, "
        "bus factor, self-reported near-misses. A zero in the last is the worst "
        "number on that page and no tool can produce it.",
    ),
)


def compute(
    snapshot: Snapshot,
    *,
    sla_breaches: int | None = None,
    expired_exceptions: int | None = None,
) -> MetricSet:
    """Build the full metric set from a snapshot plus repository state."""
    metrics = [
        _privileged_identities(snapshot),
        _long_lived_credentials(snapshot),
        _permission_boundary_coverage(snapshot),
        _detection_coverage(snapshot),
        _internet_exposure(snapshot),
        _encryption_posture(snapshot),
        _findings_past_sla(sla_breaches),
        _expired_exceptions(expired_exceptions),
        _pipeline_oidc(snapshot),
    ]

    for key, name, target, gaming, why in UNMEASURABLE:
        metrics.append(
            Metric(
                key=key,
                name=name,
                value=None,
                target=target,
                gaming=gaming,
                source="not derivable from an AWS snapshot",
                unmeasurable_because=why,
            )
        )

    return MetricSet(
        generated_at=snapshot.get("generated_at", "unknown"),
        account=snapshot.get("assessed_account", "unknown"),
        regions=len(snapshot.get("regions_scanned", [])),
        metrics=metrics,
    )
