# Responsibility playbooks

`docs/aws_security_engineering_plan.md` states sixteen responsibilities and
describes each one well. This directory answers a different question about the
same list: **where is it, and how would you check?**

Each row below points at a path that exists in this repository, an artifact that
was generated rather than written, and a command that verifies it. The
"Evidence" column is the one that matters — it is what separates a plan from a
platform.

Where a responsibility is only partly implemented, the row says so. A coverage
table that reports full coverage is a table nobody trusts twice.

| # | Responsibility | Implementation | Evidence | Verify |
|---|---|---|---|---|
| 1 | Security leadership: current-state baseline | `platform/00-discovery/` — 21 collectors, 25-point checklist | `platform/00-discovery/report/assessment.md` — a real org, 17 regions, 29 findings | `make assess-offline` |
| 2 | Translate business & regulatory requirements | `docs/06-compliance-map.md`, `docs/01-threat-model.md` | Compliance map: GDPR / ISO 27001 / NIS2 → controls | Read; **not automated** |
| 3 | Guardrails & reference implementations | `platform/01-organization/` SCPs + RCPs; `platform/lib/cdk-security/` aspects | `terraform plan` output in `platform/BASELINE.md`; 14 aspect-fire tests | `make validate` |
| 4 | Hands-on secure serverless architecture | `platform/11-serverless/` | 52 tests, 18 security-e2e, clean synth under 6 aspects + cdk-nag | `cd platform/11-serverless && npm test` |
| 5 | Secure data architecture | `platform/04-logging/` (CMK, Object Lock), `infra/terraform/modules/aurora-secure/` | `evidence/db-privilege-proof.txt` — Postgres itself refusing 19 attempts | `make evidence` |
| 6 | IAM & zero trust | `platform/00-discovery/iam/discovery-readonly.json`; trust-policy analysis in `collectors/iam.py` | **812 calls, 0 denied** under a purpose-built read-only role | `make assess` |
| 7 | Secrets management | `secrets` collector; Secrets Manager in `aurora-secure` | Findings DAT-005, DAT-006 in the assessment | `make assess-offline` |
| 8 | Vulnerability management | `scripts/vuln_sla.py`, `scripts/severity_gate.py` | `evidence/vuln-sla-report.md`; both wired into CI | `make vuln-gate` |
| 9 | Secure DevSecOps pipeline | `.github/workflows/security-pipeline.yml` — 5 jobs, all actions SHA-pinned | Every gate runs on every PR; `.github/dependabot.yml` keeps pins fresh | Push a branch |
| 10 | Monitoring, SIEM & detection | `platform/05-detection/`, `infra/terraform/detections/` (D-001…D-008) | Coverage as a fraction: GuardDuty 17/17, Config **0/17** | `make posture` |
| 11 | Detection engineering | `infra/terraform/detections/` | 8 detections as code, each with a stated trigger | `make validate` |
| 12 | Incident response | `docs/05-incident-response/` — 3 playbooks | Containment steps are executable commands, not prose | Read; **exercises not run** |
| 13 | Incident playbooks | As above | 3 of the 14 the plan lists | — |
| 14 | Governance & compliance | `docs/06-compliance-map.md`, `evidence/checkov-suppressions.md` | 26 suppressions, every one justified; build fails on an unjustified one | `make validate` |
| 15 | AI security | `mcp-servers/` — the whole agent case study | `evidence/guardrail-bypass-report.md` — 37 attacks refused | `make evidence` |
| 16 | Collaboration & culture | `readiness/07-security-culture.md` | **Written only.** Not something a repository can evidence | — |

## What this table is honest about

**Four rows have no automated evidence** — 2, 12, 13 and 16. Regulatory
interpretation, incident exercises and security culture are not properties of a
codebase, and claiming otherwise would be the exact failure mode
`readiness/02-security-metrics.md` warns about: measuring activity because it is
measurable.

**Row 13 is 3 of 14.** The plan lists fourteen playbooks worth having. Three
exist. The other eleven are named in `docs/05-incident-response/README.md` and
not written.

**Row 10's evidence is a number that looks bad, and that is the point.** Config
recording 0 of 17 regions is the finding; a coverage report that rounded it away
would be worse than no report.
