# Role analysis

Why this repository exists, what it is evidence *for*, and what it deliberately
is not.

## The posting

**Lead Security Engineer, Core Technology Team — APT, Stockholm (on-site).**
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

| # | Finding | Status |
|---|---|---|
| 1 | `SecurityChallenge` contains TLS material and a `.env` | **Closed — no action.** Purpose-built fixtures for a deliberately vulnerable CORS demonstration, not credentials to a live system. Recorded because triage is the point: an inventory that cannot distinguish a demo fixture from a real credential produces noise, and a function that cries wolf on its own estate gets ignored on the one that matters. |
| 2 | `github-recovery-codes.txt` sat untracked in the repositories directory | **Remediated.** Moved outside every git tree to a `700` directory with `600` permissions. A global gitignore now covers `*.pem`, `*.key`, `*recovery-codes*`, `.env`, `*.tfvars` and similar across every repository on the machine, verified with `git check-ignore`. Longer term these belong in a password manager, not a file. |
| 3 | `aws-fcp-ai-platform/` had **no `.git` at all** — 31 files with no history and no recovery path | **Remediated.** Placed under version control unmodified. It has diverged from a copy inside `AIML-Datapiplines-AWS` (36 files differ), and reconciliation is deferred deliberately: the work is now recoverable, so the decision can be made on its merits rather than under time pressure. |
| 4 | `aws-pam-infrastructure/` mapped to a remote named `aws-pam-platform` | **Remediated.** Local directory renamed to match. Cosmetic on its own, but name drift is how an asset inventory quietly becomes wrong. |
| 5 | 60 public repositories with heavy duplication | **Open by decision.** Candidates identified; archiving is a judgement about how a portfolio reads, not a technical fix, so it is the owner's call rather than something to automate. |

Finding 2 was the one that mattered — a file one `git add .` away from
publication, in a directory that is itself a git repository. Finding 1
illustrates the other half of the job: triage. Flagging every secret-shaped
string as an incident is how a scanner's output stops being read.

The remediation worth generalising is the global gitignore rather than the file
move. Moving one file fixes one file; a machine-wide ignore rule means the next
`.pem` or `.env` — in a repository that does not exist yet — is covered by
default. Controls that work by default beat controls that work when remembered.

## What this repository is *not*

- **Not a product.** It is a demonstration, scoped to one threat surface.
- **Not deployed.** Nothing has touched a live AWS account. IaC is validated statically so anyone can verify it without credentials or spend.
- **Not a production MCP implementation.** The protocol is hand-written to demonstrate understanding; production should use the official SDK, and the README says so.
- **Not proof I can run an incident.** It contains playbooks, not scars. `readiness/00-jd-coverage-matrix.md` rates incident command in a regulated Swedish entity as a `Gap`.
- **Not affiliated with APT.** The pharmacy schema is entirely synthetic — every personnummer is deliberately invalid, every email is on `example.com`. Seeding it with real data would contradict its own thesis.
