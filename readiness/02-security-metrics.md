# Security metrics

The question every hiring manager asks and most candidates fumble: *how will we
know you are working?*

**The trap:** metrics that measure security *activity* rather than security
*outcomes*. Findings raised, tickets closed, scans run — all go up when you are
busy and tell you nothing about whether risk fell. Worse, they create an
incentive to generate findings.

Every metric below has a stated failure mode, because a metric without one gets
gamed.

## Leading indicators — do controls exist and hold?

| Metric | Target | How it gets gamed |
|---|---|---|
| % production workloads under an IaC permission boundary | > 95% in 6 months | Counting workloads that do not matter |
| % regulated data paths through an allowlisted interface | 100% | Redefining "regulated" narrowly |
| Long-lived credentials (age > 90 days) | Trending to 0 | Rotating without reducing count |
| Secret age distribution (p95) | < 90 days | Rotating the easy ones |
| Pipeline gate pass rate on first attempt | > 85% | Weakening the gates |
| Detection coverage vs ATT&CK Cloud | Documented, gaps named | Claiming coverage for a rule that never fires |

That last one matters most: a coverage map with honest gaps is more useful than
one claiming 90%.

## Lagging indicators — what actually happened?

| Metric | Target | Notes |
|---|---|---|
| MTTR, critical | ≤ 7 days | Matches the SLA in `scripts/vuln_sla.py` |
| MTTR, high | ≤ 30 days | |
| Findings past SLA | 0 | Enforced in CI, so this is a *build* metric |
| Expired risk exceptions | 0 | An exception that renews silently is an allowlist |
| Mean time to detect (tabletop) | < 30 min | Exercised, since real incidents are too rare to measure |
| Incidents where a control worked as designed | Rising share | The one worth celebrating |

## Health of the function, not the controls

Uncomfortable and worth tracking anyway:

| Signal | Healthy | Unhealthy |
|---|---|---|
| Teams inviting security to design discussions | Rising | Falling — I have become a gate |
| Ratio of guardrails shipped to gates added | Guardrails dominant | Gates dominant — friction without safety |
| Controls only I can explain | Trending to 0 | Rising — bus factor of one |
| Self-reported near-misses | Non-zero and stable | Zero — people have stopped telling me |

**A zero in the last row is the worst number on this page.** Zero self-reported
near-misses does not mean none happened; it means reporting became expensive.

## What I would not report to a board

- Number of vulnerabilities found (goes up when scanning improves)
- Number of blocked attacks (mostly internet background noise)
- Training completion percentage (measures clicking, not behaviour)
- A single "security score" (compresses away every decision worth discussing)
