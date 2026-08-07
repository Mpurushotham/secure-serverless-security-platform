# Detection engineering

## Detection as code

Rules live in version control, are reviewed like code, and ship through the same
pipeline. `infra/terraform/detections/` is the implementation.

Every rule carries three things, and the third is the one usually missing:

1. **ATT&CK mapping** — what technique it addresses
2. **A runbook link** — what to do when it fires
3. **A false-positive profile** — what benign activity also triggers it

A rule without (3) will be muted by whoever is on call the first week it
misfires, and muting is invisible. A false-positive budget makes tuning a
scheduled activity rather than an act of frustration.

## The design principle

**Alert on the control being exercised, not on the data being touched.**

"Someone read the prescriptions table" fires constantly and gets ignored. "The
guardrail refused eleven times in five minutes" fires when something is actually
wrong, because legitimate use produces almost no refusals.

## Current coverage

| ID | Detection | ATT&CK | FP profile |
|---|---|---|---|
| D-001 | Guardrail refusal burst | T1190, TA0007 | Low — a confused model or a new developer exploring |
| D-002 | Unmask capability used | T1005 | None — expected volume is zero |
| D-003 | Bulk read volume | T1530, TA0010 | **Medium** — a legitimate analytics batch. Most in need of tuning against real traffic. |
| D-004 | Off-hours agent activity | T1078 | High — deliberately routed away from paging |
| D-005 | Database auth failures | T1110, T1078 | Low |
| D-006 | Bedrock guardrail intervention | T1567 | Low |
| D-007 | GuardDuty on agent role | Multiple | Filtered to severity ≥ 4 |
| D-008 | IAM change to agent role | T1098 | Low |

## Named gaps

More useful than a coverage percentage:

- **No lateral movement detection** — single-workload scope
- **No data-staging detection** (T1074) — would need S3 write monitoring
- **No credential-access coverage** beyond the agent's own path
- **No endpoint coverage at all** — see below
- **Detections are untested against real traffic.** Thresholds are starting points, not recommendations.

## EDR — a genuine gap

Endpoint is the thinnest area of my experience and I would rather name it than
produce a vendor opinion I cannot back.

**What I know:** EDR belongs in the detection strategy; endpoint telemetry
answers questions cloud logs cannot; deployment coverage and tuning are the hard
parts, not selection.

**What I have not done:** run an EDR fleet at scale, owned its false-positive
budget, or navigated the organisational friction of agents on developer laptops.

**How I would approach it:** a structured evaluation against the actual endpoint
estate — how many laptops, servers, warehouse systems, what OS mix, what
management tooling exists. Pilot on a small cohort with a defined success metric.
Arriving with a vendor preference before knowing the estate would be the wrong
move, and would also be bluffing.

## Tuning cadence

- **Weekly:** review firing volume per rule. Any rule with a >20:1 false-positive ratio gets tuned or retired.
- **Monthly:** ATT&CK coverage review; what changed in the architecture that we now cannot see?
- **Quarterly:** purple-team exercise against one detection. A detection nobody has tried to evade is untested.
- **After every incident:** did a detection fire? If a human noticed first, that is the finding.
