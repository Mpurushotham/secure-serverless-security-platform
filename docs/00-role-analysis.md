# Role analysis

Why this repository exists, what it is evidence *for*, and what it deliberately
is not.

## The posting

**Lead Security Engineer, Core Technology Team — Apotea, Stockholm (on-site).**
Sweden's largest online pharmacy. AWS serverless-first; Go, .NET, Python; an
explicitly AI-first architecture with agentic platforms interacting natively
with APIs and data.

Five domains: Security Leadership · Hands-On Engineering · Monitoring & IR ·
Governance & Compliance · Collaboration & Culture. The process ends in a
background check, mandatory for the pharmacy sector.

One line in the posting is unlike anything in a typical security JD:

> *"Develop secure practices for coding with AI assistants, ensuring generated
> code meets security standards, avoids data leakage, and aligns with
> regulations."*

Most candidates will answer that with a policy document. This repository answers
it with running code, because the requirement is an authorisation problem
wearing a policy costume.

## Why this scope and not a broader one

I surveyed my own 60 public repositories before starting. `Cloud-AWS-Platform-Management`
already carries 30 Terraform modules including GuardDuty, Security Hub, Config,
CloudTrail, SCPs and OpenSearch-as-SIEM. Building a 61st repository containing a
31st GuardDuty module would demonstrate nothing that already-published work does
not.

Three things were missing from all sixty:

1. **No MCP server implementation anywhere** — only prose about MCP
2. **Aurora nowhere** — only plain `aws_db_instance`
3. **No Bedrock security controls** — the one Bedrock repository has no CI and no security controls

All three intersect at exactly the JD's differentiating requirement. Hence the
thesis: **securing AI agent access to regulated production data on AWS.**

Depth over breadth was a deliberate trade. A panel reads three repositories, not
sixty, and a thing that runs beats a thing that is described.

## What this repository is evidence for

| Claim | Evidence |
|---|---|
| I can design authorisation, not just write policy | Three enforcement layers, ordered by who enforces them |
| I think adversarially | 37 documented bypass techniques, each refused for a structural reason |
| I build controls that survive their own author's mistakes | Two real bugs found and documented rather than quietly fixed |
| I can operate DevSecOps | A pipeline gating this repo's own code, where a passing bypass fails the build |
| I understand GDPR as engineering, not paperwork | Consent as an RLS row filter; masking in the engine |
| I am honest about limits | Gaps named in `readiness/00-jd-coverage-matrix.md`; suppressions justified individually |

The third row is the one I would point at first. `evidence/db-privilege-proof.txt`
exists because the RLS policy I wrote *looked correct in DDL and enforced
nothing* — a Postgres view executes with its owner's privileges, the owner was a
superuser, and superusers bypass RLS unconditionally. The proof caught it on its
first run. That is the argument for evidence-generating controls in one example.

## Self-audit of my own estate

Auditing your own work is the job. Findings, reported rather than acted on:

| # | Finding | Recommended action |
|---|---|---|
| 1 | **`SecurityChallenge` is public** and contains `www.nc.com.pem` + `www.nc.com.key`, a `slackbot/.env`, and a SQLite database | **Rotate at the issuer first.** A private key is compromised the moment it is public; deleting the file is not remediation. Then purge history. |
| 2 | `github-recovery-codes.txt` sat untracked in the repositories directory | Move outside any git tree; add to a global gitignore. One `git add .` from exposure. |
| 3 | `aws-fcp-ai-platform/` has **no `.git`**, and has diverged from a copy inside `AIML-Datapiplines-AWS` | Pick a canonical copy |
| 4 | `aws-pam-infrastructure/` directory maps to a remote named `aws-pam-platform` | Cosmetic, but the kind of drift that makes an inventory wrong |
| 5 | 60 public repositories with heavy duplication (`devsecops-aws` ⊂ `Cloud-AWS-Platform-Management`) | Signal dilution. Archive superseded repositories. |

Finding 1 is the one that matters and it is not hypothetical.

## What this repository is *not*

- **Not a product.** It is a demonstration, scoped to one threat surface.
- **Not deployed.** Nothing has touched a live AWS account. IaC is validated statically so anyone can verify it without credentials or spend.
- **Not a production MCP implementation.** The protocol is hand-written to demonstrate understanding; production should use the official SDK, and the README says so.
- **Not proof I can run an incident.** It contains playbooks, not scars. `readiness/00-jd-coverage-matrix.md` rates incident command in a regulated Swedish entity as a `Gap`.
- **Not affiliated with Apotea.** The pharmacy schema is entirely synthetic — every personnummer is deliberately invalid, every email is on `example.com`. Seeding it with real data would contradict its own thesis.
