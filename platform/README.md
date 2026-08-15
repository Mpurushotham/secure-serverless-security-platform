# `platform/` — AWS security platform

The rest of this repository is one deep case study: an AI agent reading regulated data, controlled
end to end. This directory is the other half of the same job — the **organisation-wide security
platform** that case study would sit inside.

It implements §3 (the 25-point current-state baseline) and §36 (the control-domain tree) of
[`docs/aws_security_engineering_plan.md`](../docs/aws_security_engineering_plan.md), which until now
described both in prose and neither in code.

## Status

Directories appear here only when they contain working code. This table is the honest index; it is
updated in the same change that makes something real, never after.

| Domain | Status |
|---|---|
| `lib/cdk-security/` — shared synth-time Aspects | **Runs** — 8 tests, each proving an Aspect fires |
| `docs/references.md` — what was studied upstream | **Written** |
| `00-discovery/` — inventory + live assessment | **Runs against a real AWS Organization** — 21 collectors, 41 rules, 106 tests. See [`00-discovery/report/assessment.md`](00-discovery/report/assessment.md) |
| `01-organization/` — SCPs, RCPs, delegated admin | **Validated statically** — plan-only, closes ORG-001/002/004. See [BASELINE.md](BASELINE.md) |
| `04-logging/` — org CloudTrail with CMK, Object-Lock archive | **Validated statically** — closes LOG-002, LOG-003 |
| `05-detection/` — GuardDuty, Security Hub, Config, Access Analyzer | **Validated statically** — closes LOG-004, DET-001…006 |
| `11-serverless/` — golden-path API + test pyramid | Not yet built |
| `13-devsecops/` — reusable workflows, OIDC wiring | Not yet built |
| `18-reporting/` — posture report, metrics, snapshot delta | **Runs, 13 tests** — `make posture`. No overall score, by design |
| `19-observability/` — Prometheus, Grafana, Alertmanager | Not yet built |
| `20-notifications/` — Slack app, redaction, IR workflow | Not yet built |

## Rules this directory holds itself to

1. **Read-only means read-only.** Discovery calls only `Describe*` / `List*` / `Get*` control-plane
   APIs, under a policy that explicitly *denies* data-plane reads — no object contents, no secret
   values, no table rows.
2. **A fresh clone verifies without credentials.** Live assessment is a separate, explicitly
   invoked target. `make test` and `make validate` never need an AWS account.
3. **Nothing is deployed without specific approval.** Everything here is static validation or
   read-only API calls until someone decides otherwise, deliberately.
4. **No fabricated findings.** Absent is reported as absent; `AccessDenied` is reported as
   `AccessDenied`. Nothing is inferred to fill a gap in a table.
5. **Redaction before commit.** Account IDs, ARNs and emails from a live run are hashed before any
   artifact reaches git. Raw snapshots stay gitignored.
6. **Sending to an external service is publishing.** Exactly one redaction layer sits between a
   finding and any outbound Slack message, and it carries a pointer — never a payload.

## Relationship to the existing tree

Nothing here replaces `infra/`, `mcp-servers/`, `docs/` or `readiness/`. Two deliberate links exist:

- `infra/cdk/lib/aspects/security-aspects.ts` now re-exports from `lib/cdk-security/`, so both CDK
  apps enforce the same controls from the same source.
- `infra/terraform/detections/` (detections D-001…D-008) is referenced by the observability and
  notification work rather than duplicated. Its SNS topic has had no subscriber since it was
  written; `20-notifications/` gives it one.
