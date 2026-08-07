# Compliance map

Regulatory obligations mapped to the specific controls in *this* repository.
Self-contained: official control IDs cited directly, no shared schema with any
other project.

**How to read the Evidence column.** A file path means the control is
implemented. An `evidence/` path means it is also *demonstrated* — regenerate it
with `make evidence`. A control with no evidence artifact is a design assertion,
and is labelled as such.

---

## GDPR

| Article | Obligation | Control | Evidence |
|---|---|---|---|
| **5(1)(b)** purpose limitation | Agent access is analytics only | RLS restricts to `consent_analytics = true` | `evidence/db-privilege-proof.txt` §6 |
| **5(1)(c)** data minimisation | Agent receives the minimum needed | Masked views; no grant on base tables; mandatory `LIMIT` | `evidence/mcp-demo-transcript.jsonl` |
| **5(1)(e)** storage limitation | Bounded retention | 90-day log retention; S3 lifecycle; `RequireLogRetentionAspect` | `evidence/cdk-synth.txt` |
| **5(1)(f)** integrity & confidentiality | Read-only, encrypted, TLS-forced | `mcp_readonly` role; KMS CMK; `rds.force_ssl=1` | `evidence/db-privilege-proof.txt` |
| **6** lawful basis | Consent enforced, not assumed | RLS policy on `prescriptions` | `evidence/db-privilege-proof.txt` §6 |
| **9** special category data | Health data never reaches a model unmasked | Column-level grants withhold `prescriber_hsa_id`; masked view; Bedrock PII filter | `evidence/guardrail-bypass-report.md` |
| **25** data protection by design | Controls in the schema, not a checklist | Consent as a row filter; masking as a view | `sql/01-roles.sql`, `sql/02-masked-views.sql` |
| **30** records of processing | Who read what, when | `mcp_core/audit.py` — per-invocation JSONL | `evidence/mcp-demo-transcript.jsonl` |
| **32(1)(a)** pseudonymisation | Named explicitly in the Article | `mask_token()` / `mask_email()`, salt in Secrets Manager | `evidence/mcp-demo-session.txt` |
| **32(1)(b)** ongoing confidentiality | Defence in depth, tested | 3 layers; 37-payload bypass suite | `evidence/guardrail-bypass-report.md` |
| **32(1)(d)** regular testing | Controls re-verified every build | CI regenerates and diffs evidence | `.github/workflows/security-pipeline.yml` |
| **33** breach notification | 72-hour path defined | IR playbooks with the Art. 33 decision point | `docs/05-incident-response/` |
| **28** processors | An AI vendor processing personal data needs a DPA | AI secure-coding policy §5 | *design assertion* |

### The Article 9 argument, stated plainly

If an agent reads only `v_prescriptions_masked`, it obtains: a surrogate ID, a
medication name, a dosage, and a month. It does **not** obtain the personnummer,
the name, the email, the prescriber, or the exact date — and only for data
subjects who consented to analytics processing.

That is pseudonymised special-category data under Art. 4(5). It remains personal
data (Recital 26), so this is a reduction in exposure, not an exemption. The
argument holds **only while the masking salt is unreachable**, which is why the
agent role carries an explicit deny on that secret and why the threat model
names salt exposure as the primary residual risk.

---

## ISO/IEC 27001:2022 Annex A

| Control | Implementation |
|---|---|
| **A.5.15** access control | `mcp_readonly` least privilege; IAM permission boundary |
| **A.5.16** identity management | Dedicated identity per agent; session tagging |
| **A.5.18** access rights | Column-level grants; `ALTER DEFAULT PRIVILEGES REVOKE` so new tables opt in |
| **A.8.2** privileged access | Explicit deny on IAM self-modification and superuser assumption |
| **A.8.3** information access restriction | Relation allowlist; RLS |
| **A.8.5** secure authentication | IAM database authentication — no long-lived password exists |
| **A.8.9** configuration management | All controls in Terraform/CDK; drift fails CI |
| **A.8.11** data masking | Named explicitly in the standard; `sql/02-masked-views.sql` |
| **A.8.12** data leakage prevention | Row and byte caps; unmask capability off by default |
| **A.8.15** logging | `mcp_core/audit.py`; Aurora and Bedrock logs |
| **A.8.16** monitoring activities | 8 detections with ATT&CK mappings |
| **A.8.25** secure development lifecycle | The CI pipeline gates this repo's own code |
| **A.8.26** application security requirements | Threat model; bypass suite |
| **A.8.28** secure coding | AI secure-coding policy; SAST in CI |
| **A.5.24–5.26** incident management | Three IR playbooks with severity and role definitions |

---

## NIS2 (Directive 2022/2555)

Applicability to a pharmacy retailer depends on classification — a question for
legal, not for this document. Mapped on the assumption it applies:

| Article | Requirement | Control |
|---|---|---|
| **21(2)(a)** risk analysis | `docs/01-threat-model.md` — STRIDE + attack tree |
| **21(2)(b)** incident handling | `docs/05-incident-response/` |
| **21(2)(d)** supply chain security | SBOM; pinned MCP servers; dependency audit |
| **21(2)(e)** secure acquisition & development | The CI pipeline; IaC policy gates |
| **21(2)(f)** effectiveness assessment | Evidence regenerated and diffed every build |
| **21(2)(g)** cyber hygiene & training | AI-usage training framework in `readiness/07-security-culture.md` |
| **21(2)(h)** cryptography | KMS CMK with rotation; forced TLS |
| **21(2)(i)** access control & asset management | Permission boundaries; least-privilege roles |
| **23** reporting obligations | Playbook severity model maps to the 24h early-warning / 72h notification structure |

---

## What this map does not claim

- **It is not an audit.** It is the author's mapping, unreviewed by an assessor.
- **Swedish pharmacy-specific regulation is absent.** Läkemedelsverket requirements and the Swedish pharmacy register are named as a gap in `readiness/00-jd-coverage-matrix.md` rather than guessed at here.
- **Several rows are design assertions, not demonstrated controls** — every one is labelled. Presenting an assertion as evidence is the failure mode this column exists to prevent.
- **Applicability is a legal determination.** Whether NIS2 or the EU AI Act binds a given entity is not an engineering question.
