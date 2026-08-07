# JD coverage matrix

One row per requirement in the Lead Security Engineer posting (Core Technology,
Apotea, Stockholm). This is the repository's acceptance test: **a requirement with
an empty Evidence column means the work is not finished.**

## How to read the confidence column

| Rating | Meaning |
|---|---|
| `Strong` | Demonstrable now — running code, or work I have led end to end |
| `Workable` | Have done it, but not at this scale or in this regulatory context |
| `Gap` | Would be learning on the job. Named deliberately. |

> ⚠️ **These ratings are provisional and must be corrected by the candidate before
> this document is shown to anyone.** They were drafted from repository evidence,
> which shows what has been *built* — it cannot show what has been operated at 3am
> during a real incident, defended to an auditor, or carried through an
> organisational disagreement. Only you can rate those. **An inflated rating here
> is worse than a `Gap`**: a `Gap` you volunteered reads as self-awareness, and an
> overstatement the panel probes for ninety seconds reads as bluffing — with a
> mandatory pharmacy-sector background check still to come.

---

## 1. Security Leadership

| Requirement | Evidence | Confidence | Closing action |
|---|---|---|---|
| Own and evolve security strategy across cloud, applications, infrastructure | `docs/02-security-strategy.md`; `readiness/01-day-one-operating-plan.md` | Workable | Strategy owned for a *team* is not strategy owned for an *organisation*. Prepare one worked example of a strategy you changed and why. |
| Translate business and regulatory requirements into sustainable practices | `docs/06-compliance-map.md` maps GDPR Art. 9/30/32 to specific controls in this repo | Workable | Rehearse the reverse direction: a business asks to ship in two weeks, the regulation says otherwise — what do you actually do? |
| Define guardrails, best practices, reference implementations | The whole repository is a reference implementation: `sql/01-roles.sql`, `guardrails.py`, `infra/terraform/` | **Strong** | — |

## 2. Hands-On Security Engineering

| Requirement | Evidence | Confidence | Closing action |
|---|---|---|---|
| Design and implement secure AWS serverless and data-driven systems | `infra/cdk/` reference app; `infra/terraform/modules/aurora-secure` | Workable | Serverless *at Apotea's traffic profile* is the unknown, not serverless. |
| Lead IAM practices — least privilege, zero trust | `sql/01-roles.sql` (NOINHERIT, column grants, RLS); `terraform/modules/agent-data-access` (permission boundary, session tags) | **Strong** | — |
| Vulnerability management, penetration testing, patching | `readiness/05-vulnerability-management.md`; `scripts/vuln_sla.py` enforces the SLA matrix in CI | Workable | **Pen testing is the weak half.** I can run and triage scanners; commissioning and scoping a pen test, and arguing findings with a vendor, is thinner. |
| Secure DevSecOps pipelines and IaC security | `.github/workflows/security-pipeline.yml` — gates this repo's own code; a passing bypass fails the build | **Strong** | — |

## 3. Monitoring & Incident Response

| Requirement | Evidence | Confidence | Closing action |
|---|---|---|---|
| Build and operate monitoring, detection, alerting (SIEM, GuardDuty, Security Hub) | `terraform/detections/`; `readiness/06-detection-engineering.md` | Workable | Have built detections; have not owned a SIEM's signal-to-noise budget over a year. |
| …**EDR** specifically | `readiness/06-detection-engineering.md` states a selection rationale | **Gap** | Fleet-scale EDR (deployment, tuning, endpoint politics) is genuinely outside my experience. Say so, then describe how I would select and pilot one. |
| Lead incident response: investigate, contain, recover | `docs/05-incident-response/` — three playbooks | **Gap** | I have *written* IR playbooks and participated in incidents. I have not been incident commander for a regulated Swedish entity with notification duties. This is the single largest gap and the most likely interview probe. |
| Maintain and test playbooks for emerging threats | Playbook 3 (PII exfiltration via a compromised AI agent) covers a threat most orgs have no playbook for | **Strong** | — |

## 4. Governance & Compliance

| Requirement | Evidence | Confidence | Closing action |
|---|---|---|---|
| GDPR compliance | `sql/01-roles.sql` makes consent an engine-enforced row filter; `masking.py` classifies by Article; `docs/06-compliance-map.md` | **Strong** | — |
| Healthcare regulation / Swedish pharmacy law | — | **Gap** | Läkemedelsverket requirements, the Swedish pharmacy register, and e-health specifics are unknown to me. Read before interview; do not bluff — the panel works under these daily. |
| Embed security and privacy by design | Consent as an RLS policy is privacy-by-design in the strict sense: the control is in the schema, not in a review checklist | **Strong** | — |
| Partner with legal, compliance, business for regulatory readiness | `readiness/01-day-one-operating-plan.md` stakeholder map | Workable | Prepare an example of a time legal and engineering disagreed and how it resolved. |
| Provide training and frameworks for safe AI usage | `docs/04-ai-secure-coding-policy.md` + `readiness/07-security-culture.md` training outline | **Strong** | The repository *is* the worked example. |

## 5. Collaboration & Culture

| Requirement | Evidence | Confidence | Closing action |
|---|---|---|---|
| Work with engineers, architects, product to integrate security early | `readiness/07-security-culture.md` — threat-modelling-as-a-service | Workable | — |
| Mentor engineers in secure coding and infrastructure | `readiness/07-security-culture.md` curriculum | Workable | Prepare a concrete mentoring story, including one where it did not work. |
| Advocate for a strong security culture | — | Workable | Hardest thing to evidence in a repository. Comes down to interview stories. |

## 6. Stated qualifications

| Requirement | Evidence | Confidence |
|---|---|---|
| Extensive experience as an organisation's main security expert | Portfolio breadth across AWS/Azure/GCP DevSecOps | Workable — *"main expert for an organisation"* is the phrase to be honest about |
| AWS: IAM, networking, serverless, encryption, monitoring | This repo + prior AWS platform work | **Strong** |
| Secure, scalable cloud-native design | `docs/03-architecture.md` | **Strong** |
| SIEM, EDR, vulnerability scanners, secrets management | Scanners and secrets: strong. SIEM: workable. **EDR: gap** | Mixed |
| DevSecOps and IaC (CDK, Terraform, CloudFormation) | CI pipeline, Terraform modules, CDK app | **Strong** |
| Programming: Go, TypeScript, .NET, Python | Python throughout, TypeScript in CDK. **Go and .NET are not evidenced here** | Mixed |
| *Nice to have:* regulated industries | Pharmacy data model, GDPR Art. 9 controls | Workable |
| *Nice to have:* ISO 27001, NIST, PCI-DSS | `docs/06-compliance-map.md` | Workable |
| *Nice to have:* red/blue team | `evidence/guardrail-bypass-report.md` — 37 attack payloads, adversarial by construction | Workable |

---

## The four gaps, stated plainly

Volunteer these before the panel finds them. Each is paired with what I would
actually do, because a gap without a plan is just a weakness.

1. **Incident command in a regulated Swedish entity.** I can run the technical
   side. What I have not owned is the 72-hour GDPR notification clock with
   Integritetsskyddsmyndigheten and a pharmacy regulator in the room. *Plan:* run
   a tabletop in month two with legal present, and have the notification decision
   tree written before it is needed rather than during.

2. **EDR at fleet scale.** Endpoint is my thinnest area. *Plan:* treat selection as
   a structured evaluation against Apotea's actual endpoint estate rather than
   arriving with a vendor preference.

3. **Swedish pharmacy regulation.** Läkemedelsverket, the pharmacy register, and
   Swedish e-health specifics. *Plan:* this is reading, not experience — do it
   before the technical interview. The panel lives in these rules and will notice
   both bluffing and preparation.

4. **Go and .NET.** Apotea's backend is Go and .NET; my working languages are
   Python and TypeScript. *Plan:* be straightforward that I would be reviewing Go
   before writing it in month one. For a security lead, reading code critically
   matters more than shipping features in it — but do not pretend the gap is not
   there.

---

## What this repository does *not* evidence

Worth saying out loud, because the repository is a build artifact and the role is
majority judgment:

- Operating a control for a year and watching it decay
- Saying no to a shipping deadline and living with the consequences
- Running a security function under budget pressure
- Being wrong publicly and recovering the team's trust

Those come from the interview, not from GitHub. This document exists to make sure
the interview is spent on them, rather than on things the code can already answer.
