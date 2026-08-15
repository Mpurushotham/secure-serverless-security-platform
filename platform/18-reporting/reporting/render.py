"""Renders the posture report.

Written for someone deciding where to spend the next two weeks, not for someone
proving that work happened. Three rules follow from that:

* **No overall score.** ``readiness/02-security-metrics.md`` rejects one, and it
  is the first thing anybody asks for. A single number compresses away every
  decision worth discussing and moves the conversation to the number.
* **The gaming mode sits next to the number**, not in an appendix.
* **The unmeasured metrics are a section, not an omission.** Showing only what
  is computable implies the coverage is complete, and the missing ones are the
  outcome measures.
"""

from __future__ import annotations

from typing import Any

from .delta import Delta
from .metrics import MetricSet

SEVERITY_BADGE = {
    "critical": "🔴 Critical",
    "high": "🟠 High",
    "medium": "🟡 Medium",
    "low": "⚪ Low",
}


def render(metrics: MetricSet, findings: list[Any], delta: Delta | None) -> str:
    out: list[str] = []
    w = out.append

    w(f"# Security posture — {metrics.account}")
    w("")
    w(
        f"Snapshot `{metrics.generated_at}` · {metrics.regions} region(s) · "
        f"{len(findings)} open finding(s)"
    )
    w("")
    w(
        "> There is no overall score in this report. "
        "[`readiness/02-security-metrics.md`](../../../readiness/02-security-metrics.md) "
        "rejects one deliberately: a single number compresses away every decision worth "
        "discussing, and the conversation becomes about the number."
    )
    w("")

    if delta is not None:
        w(_delta_section(delta))
        w("")

    w(_severity_section(findings))
    w("")
    w(_measured_section(metrics))
    w("")
    w(_unmeasured_section(metrics))
    return "\n".join(out) + "\n"


def _delta_section(d: Delta) -> str:
    lines = ["## Since the last snapshot", ""]
    lines.append(f"Comparing `{d.previous_at}` → `{d.current_at}`.")
    lines.append("")
    lines.append("| | Count |")
    lines.append("|---|---:|")
    lines.append(f"| New findings | {len(d.new_findings)} |")
    lines.append(f"| Resolved | {len(d.resolved_findings)} |")
    lines.append(f"| Unchanged | {len(d.unchanged_findings)} |")
    lines.append("")

    if d.new_findings:
        lines.append("**New:**")
        lines.append("")
        for f in d.new_findings:
            badge = SEVERITY_BADGE.get(f.severity, f.severity)
            lines.append(f"- `{f.rule_id}` {badge} — {f.title}")
        lines.append("")

    if d.resolved_findings:
        lines.append("**Resolved:**")
        lines.append("")
        for f in d.resolved_findings:
            lines.append(f"- `{f.rule_id}` {f.title}")
        lines.append("")

    if not d.resolutions_are_trustworthy:
        reasons = []
        if d.collectors_degraded:
            reasons.append(f"collectors stopped reporting ({', '.join(d.collectors_degraded)})")
        if d.regions_removed:
            reasons.append(f"regions left scope ({', '.join(d.regions_removed)})")
        lines.append(
            "> ⚠️ **Treat the resolutions above as unconfirmed.** Scope moved between "
            f"these "
            f"two runs — {'; '.join(reasons)}. A finding that disappears because nobody "
            f"looked is indistinguishable, from the finding list alone, from one that was "
            f"fixed. Re-run with the same scope before claiming these are closed."
        )
        lines.append("")
    elif d.scope_changed:
        widened = []
        if d.regions_added:
            widened.append(f"{len(d.regions_added)} region(s) added")
        if d.collectors_recovered:
            widened.append(f"collectors recovered ({', '.join(d.collectors_recovered)})")
        lines.append(
            f"Scope widened between runs ({'; '.join(widened)}), so new findings may be "
            f"pre-existing issues now visible for the first time rather than regressions."
        )

    return "\n".join(lines)


def _severity_section(findings: list[Any]) -> str:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    lines = ["## Open findings", "", "| Severity | Count |", "|---|---:|"]
    for severity in ("critical", "high", "medium", "low"):
        lines.append(f"| {SEVERITY_BADGE[severity]} | {counts.get(severity, 0)} |")
    lines.append("")
    lines.append(
        "Full detail, with remediation for each, is in "
        "[`../00-discovery/report/assessment.md`](../00-discovery/report/assessment.md)."
    )
    return "\n".join(lines)


def _measured_section(m: MetricSet) -> str:
    lines = [
        "## Measured", "",
        "| Metric | Value | Target | How it gets gamed |",
        "|---|---:|---|---|",
    ]
    for metric in m.measured:
        detail = f"<br/><sub>{metric.detail}</sub>" if metric.detail else ""
        lines.append(
            f"| {metric.name}{detail} | **{metric.value}** | {metric.target} | {metric.gaming} |"
        )
    return "\n".join(lines)


def _unmeasured_section(m: MetricSet) -> str:
    lines = ["## Not measured, and why", ""]
    lines.append(
        "These are defined in `readiness/02-security-metrics.md` and are **not** computable "
        "from an AWS snapshot. They are listed rather than omitted because a metrics page "
        "showing only the computable half implies the coverage is complete — and these are "
        "the outcome measures, not the leftovers."
    )
    lines.append("")
    lines.append("| Metric | Target | Why not here |")
    lines.append("|---|---|---|")
    for metric in m.unmeasured:
        lines.append(f"| {metric.name} | {metric.target} | {metric.unmeasurable_because} |")
    return "\n".join(lines)
