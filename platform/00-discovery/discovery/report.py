"""Renders a snapshot plus its findings into a readable assessment.

Written for a reader who was not present for the sweep. Three properties are
non-negotiable:

* **Every checklist item appears**, with an explicit status. An item that could
  not be assessed says so; a blank row is indistinguishable from a pass.
* **Nothing is inferred.** If an API was denied, the report says denied. If a
  collector failed, the report says failed, and the rules it feeds are marked
  as not evaluated rather than passing quietly.
* **The scope caveats are at the top**, not in a footnote. A reader who stops
  after the summary should already know what the assessment did not cover.
"""

from __future__ import annotations

from typing import Any

from .checklist import CHECKLIST
from .rules import RULES, Finding, Snapshot

SEVERITY_BADGE = {
    "critical": "🔴 Critical",
    "high": "🟠 High",
    "medium": "🟡 Medium",
    "low": "⚪ Low",
    "info": "· Info",
}

# From readiness/05-vulnerability-management.md. Repeated here so the report is
# self-contained for a reader who has not opened that file.
SLA_DAYS = {"critical": 7, "high": 30, "medium": 90, "low": 180}


def render(snapshot: Snapshot, findings: list[Finding]) -> str:
    out: list[str] = []
    w = out.append

    w(f"# AWS security assessment — {snapshot['assessed_account']}")
    w("")
    w(_provenance(snapshot))
    w("")
    w(_caveats(snapshot))
    w("")
    w(_summary(snapshot, findings))
    w("")
    w(_top_risks(findings))
    w("")
    w(_org_diagram(snapshot))
    w("")
    w(_checklist_table(snapshot, findings))
    w("")
    w(_findings_detail(findings))
    w("")
    w(_risk_register(findings))
    w("")
    w(_coverage(snapshot))
    return "\n".join(out) + "\n"


def _provenance(s: Snapshot) -> str:
    calls = s["api_calls"]
    return "\n".join(
        [
            "| | |",
            "|---|---|",
            f"| Generated | {s['generated_at']} |",
            f"| Account | `{s['assessed_account']}` |",
            f"| Assessing principal | `{s['assessed_principal']}` |",
            f"| Regions scanned | {len(s['regions_scanned'])} — "
            f"{', '.join(s['regions_scanned'])} |",
            f"| Collectors | {len(s['collectors'])} |",
            f"| AWS API calls | {calls['total']} ({_outcomes(calls['by_outcome'])}) |",
            f"| Duration | {s['duration_seconds']}s |",
        ]
    )


def _outcomes(by_outcome: dict[str, int]) -> str:
    return ", ".join(f"{n} {k}" for k, n in by_outcome.items())


def _caveats(s: Snapshot) -> str:
    lines = ["## Scope and limits", ""]

    lines.append(
        "Every call made by this assessment is a `Describe*` / `List*` / `Get*` "
        "control-plane operation. No object, secret value, parameter value or table row "
        "was read; a runtime guard refuses those operations before they reach AWS. The "
        "full call log is in the snapshot this report was rendered from."
    )
    lines.append("")

    principal = s.get("assessed_principal") or ""
    # Read the flag the runner derived from the unredacted ARN. Re-deriving it
    # from `principal` here would work until redaction rewrote the role name,
    # at which point the caveat would disappear from the report without anyone
    # noticing — which is exactly what happened once.
    if s.get("assessor_is_privileged"):
        lines.append(
            f"**The assessing identity is over-privileged for its own task.** This ran as "
            f"`{principal}`, an administrator. The read-only policy in "
            f"`platform/00-discovery/iam/discovery-readonly.json` is what it *should* run "
            f"under, and until it has, that policy is unproven — it may be missing "
            f"permissions, or granting more than it needs. Re-running under a purpose-built "
            f"role is the test."
        )
        lines.append("")

    denied = s["api_calls"].get("denied") or []
    if denied:
        lines.append(
            f"**{len(denied)} API call(s) were denied** and the corresponding controls could "
            f"not be assessed: {', '.join(sorted(set(denied)))}. These are reported as "
            f"`not-permitted`, never as absent."
        )
        lines.append("")

    failed = [
        name
        for name, c in s["collectors"].items()
        if c["status"] not in {"observed"}
    ]
    if failed:
        lines.append(
            f"**{len(failed)} collector(s) did not complete**: {', '.join(sorted(failed))}. "
            f"Rules depending on them were not evaluated and are shown as `not evaluated` "
            f"rather than passing."
        )
        lines.append("")

    regions = len(s["regions_scanned"])
    lines.append(
        f"Regional services were assessed in **{regions} region(s)**. Findings say nothing "
        f"about regions outside that set — and an unmonitored region is where an attacker "
        f"would prefer to operate."
    )
    return "\n".join(lines)


def _summary(s: Snapshot, findings: list[Finding]) -> str:
    counts = {sev: 0 for sev in SEVERITY_BADGE}
    for f in findings:
        counts[f.severity] += 1

    lines = ["## Summary", ""]
    lines.append("| Severity | Count | Remediate within |")
    lines.append("|---|---:|---|")
    for sev in ("critical", "high", "medium", "low"):
        lines.append(
            f"| {SEVERITY_BADGE[sev]} | {counts[sev]} | {SLA_DAYS[sev]} days |"
        )
    lines.append(f"| **Total** | **{len(findings)}** | |")
    lines.append("")

    by_domain: dict[str, int] = {}
    for f in findings:
        by_domain[f.domain] = by_domain.get(f.domain, 0) + 1
    if by_domain:
        lines.append("Findings by domain: " + ", ".join(
            f"**{d}** {n}" for d, n in sorted(by_domain.items(), key=lambda kv: -kv[1])
        ))
    return "\n".join(lines)


def _top_risks(findings: list[Finding]) -> str:
    lines = ["## Top risks", ""]
    if not findings:
        lines.append("No findings.")
        return "\n".join(lines)

    lines.append(
        "Ordered by severity, which here is assigned from exposure, blast radius and data "
        "sensitivity rather than from a scoring formula."
    )
    lines.append("")
    lines.append("| # | Finding | Severity | Domain |")
    lines.append("|---:|---|---|---|")
    for i, f in enumerate(findings[:10], 1):
        lines.append(
            f"| {i} | [{f.rule_id}](#{f.rule_id.lower()}) {f.title} "
            f"| {SEVERITY_BADGE[f.severity]} | {f.domain} |"
        )
    return "\n".join(lines)


def _org_diagram(s: Snapshot) -> str:
    org = (s["collectors"].get("organizations") or {}).get("data", {})
    lines = ["## Organization as observed", ""]

    if not org.get("in_organization"):
        lines.append("This account is not a member of an AWS Organization.")
        return "\n".join(lines)

    lines.append("```mermaid")
    lines.append("flowchart TD")
    for root in org.get("roots", []):
        rid = _node(root["id"])
        accounts = len(root.get("account_ids", []))
        lines.append(f'    {rid}["Root: {root["name"]}<br/>{accounts} account(s) direct"]')
        _emit_ous(lines, rid, root.get("organizational_units", []))
    lines.append("```")
    lines.append("")

    lines.append(
        f"Organization `{org['organization_id']}`, feature set {org['feature_set']}, "
        f"{len(org.get('accounts', []))} account(s)."
    )
    lines.append("")
    lines.append("| Account | Name | Management | Status |")
    lines.append("|---|---|---|---|")
    for account in org.get("accounts", []):
        lines.append(
            f"| `{account['id']}` | {account['name']} | "
            f"{'yes' if account['is_management_account'] else ''} | {account['status']} |"
        )
    lines.append("")
    lines.append(
        f"Policy types enabled: {', '.join(org.get('policy_types_enabled', [])) or 'none'}. "
        f"Disabled: {', '.join(org.get('policy_types_disabled', [])) or 'none'}."
    )
    return "\n".join(lines)


def _emit_ous(lines: list[str], parent: str, ous: list[dict[str, Any]]) -> None:
    for ou in ous:
        nid = _node(ou["id"])
        count = len(ou["account_ids"])
        label = f"{ou['name']}<br/>{count} account(s)"
        # An OU with no accounts anywhere beneath it constrains nothing, and the
        # diagram is where that is most obvious.
        shape = f'{nid}["{label}"]' if count or ou["children"] else f'{nid}("{label}")'
        lines.append(f"    {parent} --> {shape}")
        _emit_ous(lines, nid, ou["children"])


def _node(identifier: str) -> str:
    return identifier.replace("-", "_")


def _checklist_table(s: Snapshot, findings: list[Finding]) -> str:
    lines = ["## Baseline checklist coverage", ""]
    lines.append(
        "The 25-point current-state baseline from "
        "`docs/aws_security_engineering_plan.md` §3. Every item has a status: nothing is "
        "left blank, because a blank row and a passing row look identical."
    )
    lines.append("")
    lines.append("| # | Item | Status | Source | Findings |")
    lines.append("|---:|---|---|---|---|")

    by_item: dict[int, list[Finding]] = {}
    for f in findings:
        for item in f.checklist:
            by_item.setdefault(item, []).append(f)

    collector_by_item: dict[int, list[str]] = {}
    for name, entry in s["collectors"].items():
        for item in entry["checklist"]:
            collector_by_item.setdefault(item, []).append(name)

    for number, item in CHECKLIST.items():
        collectors = collector_by_item.get(number, [])
        statuses = {
            s["collectors"][c]["status"] for c in collectors if c in s["collectors"]
        }
        repo_sourced = any(
            (s["collectors"].get(c, {}).get("data") or {}).get("source") == "repo"
            for c in collectors
        )

        if not collectors:
            status, source = "judgement", item.source
        elif statuses == {"observed"}:
            status = "observed"
            source = "repository" if repo_sourced else "AWS API"
        elif "not-permitted" in statuses:
            status, source = "not-permitted", "AWS API"
        else:
            status, source = "error", "AWS API"

        hits = by_item.get(number, [])
        ids = ", ".join(f.rule_id for f in hits) if hits else "—"
        lines.append(f"| {number} | {item.title} | `{status}` | {source} | {ids} |")

    return "\n".join(lines)


def _findings_detail(findings: list[Finding]) -> str:
    lines = ["## Findings", ""]
    if not findings:
        lines.append("No findings.")
        return "\n".join(lines)

    remediation_by_id = {r.id: r for r in RULES}
    for f in findings:
        lines.append(f"### {f.rule_id}")
        lines.append("")
        lines.append(f"**{f.title}** — {SEVERITY_BADGE[f.severity]} · {f.domain} · "
                     f"checklist {', '.join(str(c) for c in f.checklist)}")
        lines.append("")
        lines.append(f"{f.detail}")
        lines.append("")
        lines.append(f"**Remediation.** {remediation_by_id[f.rule_id].remediation}")
        if f.references:
            lines.append("")
            lines.append("References: " + ", ".join(f"<{r}>" for r in f.references))
        lines.append("")
    return "\n".join(lines)


def _risk_register(findings: list[Finding]) -> str:
    lines = ["## Risk register", ""]
    lines.append(
        "In the shape of `docs/aws_security_engineering_plan.md` §3 Step 2. Treatment is "
        "the proposed action; ownership and acceptance are decisions for the risk owner, "
        "not for this tool."
    )
    lines.append("")
    lines.append("| ID | Risk | Severity | SLA | Treatment |")
    lines.append("|---|---|---|---:|---|")
    remediation_by_id = {r.id: r for r in RULES}
    for f in findings:
        treatment = remediation_by_id[f.rule_id].remediation.split(".")[0]
        lines.append(
            f"| {f.rule_id} | {f.title} | {SEVERITY_BADGE[f.severity]} "
            f"| {SLA_DAYS[f.severity]}d | {treatment} |"
        )
    return "\n".join(lines)


def _coverage(s: Snapshot) -> str:
    lines = ["## Assessment coverage", ""]
    lines.append("| Collector | Domain | Status | Note |")
    lines.append("|---|---|---|---|")
    for name in sorted(s["collectors"]):
        entry = s["collectors"][name]
        lines.append(
            f"| {name} | {entry['domain']} | `{entry['status']}` "
            f"| {entry.get('note', '') or ''} |"
        )

    errors = s["api_calls"].get("errors") or []
    if errors:
        lines.append("")
        lines.append("### API errors")
        lines.append("")
        for error in sorted(set(errors)):
            lines.append(f"- `{error}`")
    return "\n".join(lines)
