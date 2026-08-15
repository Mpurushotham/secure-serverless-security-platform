# Security posture — acct_78e004

Snapshot `2026-08-15T12:13:29Z` · 17 region(s) · 29 open finding(s)

> There is no overall score in this report. [`readiness/02-security-metrics.md`](../../../readiness/02-security-metrics.md) rejects one deliberately: a single number compresses away every decision worth discussing, and the conversation becomes about the number.

## Since the last snapshot

Comparing `2026-08-15T12:08:22Z` → `2026-08-15T12:13:29Z`.

| | Count |
|---|---:|
| New findings | 0 |
| Resolved | 0 |
| Unchanged | 29 |


## Open findings

| Severity | Count |
|---|---:|
| 🔴 Critical | 1 |
| 🟠 High | 10 |
| 🟡 Medium | 15 |
| ⚪ Low | 3 |

Full detail, with remediation for each, is in [`../00-discovery/report/assessment.md`](../00-discovery/report/assessment.md).

## Measured

| Metric | Value | Target | How it gets gamed |
|---|---:|---|---|
| Identities carrying administrator access<br/><sub>1 IAM user(s) · 4 role(s)</sub> | **5** | Federated only; zero IAM users | Renaming a policy rather than reducing what it grants — this counts the known administrator-grade managed policies, not every wide inline policy. |
| Active access keys older than 90 days<br/><sub>1 active key(s); oldest is 2 days</sub> | **0** | Trending to 0 | Rotating without reducing the count — a fresh key is still a static credential. |
| Customer-managed roles with a permissions boundary<br/><sub>0 of 15 roles</sub> | **0.0** | > 95% within 6 months | Counting roles that do not matter — service-linked roles are excluded here. |
| Detection services enabled, across scanned regions<br/><sub>GuardDuty 17/17 · Security Hub 13/17 · Config 0/17 · Access Analyzer 1/17</sub> | **45.6** | Documented, with gaps named | Claiming coverage for a service that is enabled but has its protection plans switched off — enablement is not detection. |
| Internet-reachable resources<br/><sub>1 security group(s) open to 0.0.0.0/0 · 0 unauthenticated function URL(s) · 0 public database(s)</sub> | **1** | Every entry justified and owned | Narrowing the definition of internet-facing. |
| Buckets without default encryption<br/><sub>6 bucket(s) · 0 customer-managed key(s) · 0 without rotation</sub> | **0** | 0 | Counting SSE-S3 as equivalent to SSE-KMS. An AWS-managed key carries no key policy, so encryption cannot act as an access boundary. |
| Findings past their remediation SLA | **0** | 0 — enforced in CI, so this is a build metric | Suppressing a finding rather than fixing it; suppressions are excluded here. |
| Expired risk exceptions | **0** | 0 — an exception that renews silently is an allowlist | Extending the expiry instead of re-arguing the acceptance. |
| Pipeline uses AWS OIDC federation<br/><sub>1 workflow(s) · 9 action(s) not SHA-pinned</sub> | **no** | 100% of workflows that touch AWS | Counting workflows that never needed AWS access. |

## Not measured, and why

These are defined in `readiness/02-security-metrics.md` and are **not** computable from an AWS snapshot. They are listed rather than omitted because a metrics page showing only the computable half implies the coverage is complete — and these are the outcome measures, not the leftovers.

| Metric | Target | Why not here |
|---|---|---|
| % regulated data paths through an allowlisted interface | 100% | Requires a data classification this account does not carry in tags. Needs the data-flow map in docs/01-threat-model.md applied to real resources. |
| Pipeline gate pass rate on first attempt | > 85% | Requires GitHub Actions run history, not an AWS snapshot. Available from the API once the workflow has enough runs. |
| Mean time to remediate, critical | ≤ 7 days | Requires remediation history. The vuln-ledger records first-seen dates, so this becomes computable after findings have been closed as well as opened. |
| Mean time to detect (tabletop) | < 30 min | Requires running the incident playbooks in docs/05-incident-response/ as exercises. Cannot be derived from configuration. |
| Detection coverage vs ATT&CK Cloud | Documented, gaps named | Requires mapping the eight detections in infra/terraform/detections/ to technique IDs, and confirming each rule has fired at least once in test. |
| Health of the security function (4 signals) | See readiness/02-security-metrics.md | Human observations: design-review invitations, guardrail-to-gate ratio, bus factor, self-reported near-misses. A zero in the last is the worst number on that page and no tool can produce it. |
