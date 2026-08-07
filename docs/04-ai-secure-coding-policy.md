# Secure practices for coding with AI assistants

> *"Develop secure practices for coding with AI assistants, ensuring generated code
> meets security standards, avoids data leakage, and aligns with regulations."*
> — Lead Security Engineer job posting, Apotea

This is the policy that requirement asks for. It is deliberately short and
enforceable: a fourteen-page AI policy nobody reads protects nothing, and every
rule below either maps to a control in this repository or is honestly labelled as
depending on people.

**Scope:** any AI assistant with access to Apotea source code, infrastructure
definitions, or production data — IDE assistants, CLI agents, autonomous agents,
and anything reachable over MCP.

---

## The threat model in one paragraph

An AI coding assistant is a **principal with broad credentials that takes
instructions from whatever text it most recently read.** That is the whole
problem. It is not that models write insecure code — they sometimes do, and code
review catches that. It is that an agent reading a ticket, a log line, a webpage,
or a database row can be *instructed* by that content, and it acts with the
permissions you gave it. Prompt injection is not a model flaw to be patched; it is
a property of the architecture. Design as if the model will eventually follow
hostile instructions, because eventually it will.

**Consequence:** every control below is about *bounding what the agent can do*,
not about *what it can be persuaded to want*.

---

## 1. What may reach a model

| Category | Rule | Enforcement |
|---|---|---|
| Source code | Permitted for approved assistants | Tooling allowlist |
| Infrastructure code | Permitted | Tooling allowlist |
| **Production personal data** | **Never**, in any form | Masked views; agent role has no grant on base tables |
| Art. 9 health data | Never, including in test fixtures | RLS + column grants |
| Secrets, keys, tokens | Never — including "just to debug" | Secret scanning in CI, pre-commit hooks |
| Customer support transcripts | Only pseudonymised | Data pipeline responsibility |
| Synthetic data resembling production | Permitted, and preferred | See `sql/00-seed-schema.sql` |

**The rule that carries the most weight:** *if a human would need a business
justification to query it, an agent may not query it unmasked.* Agents do not get
a lower bar than people because they are convenient.

**Why masking lives in the database, not the prompt.** A prompt-level instruction
not to read personal data is a request. A database role with no `SELECT` grant on
the base table is a control. This repository implements the second — see
`evidence/db-privilege-proof.txt`, where PostgreSQL itself refuses.

---

## 2. Agent least privilege

Non-negotiable, and all four are implemented in this repository:

1. **A dedicated identity per agent.** Never a shared service account, never a
   human's credentials. Attribution is impossible otherwise, and attribution is
   the whole basis of the audit trail.
2. **Read-only by default.** Write access is a separate, justified, time-bounded
   grant — not a default that happens to be unused.
3. **A permission boundary.** Caps the agent's maximum privilege regardless of
   what policy is later attached. Prevents privilege creep by a well-meaning
   future engineer.
4. **Session tagging.** Every action attributable to a specific agent run, so an
   incident can be scoped rather than guessed at.

---

## 3. MCP server approval

MCP servers are how agents reach real systems. An unreviewed MCP server is an
unreviewed authorisation boundary.

**Approval requirements — a server may be enabled only if it:**

- is pinned to a specific version and integrity-checked (no floating `latest`)
- declares every tool it exposes; no dynamic tool registration at runtime
- runs as a dedicated least-privilege identity
- writes a structured audit record per tool invocation
- has a documented refusal path — the agent must be able to *read* why it was
  refused and change approach, rather than see an opaque failure and retry
- has been threat-modelled for what a *malicious* caller could do with its tools,
  not only what a cooperative one would

**Third-party MCP servers are treated as supply-chain dependencies**, because that
is what they are: pinned, reviewed, and re-reviewed on upgrade. A server that can
read your database is more sensitive than a library that can, not less.

**Standing prohibitions:**
- No MCP server holds a credential it does not need for its declared tools
- No server exposes a general "run this command" or "run this SQL" tool without a
  guardrail layer (see `mcp-servers/rds_readonly_mcp/guardrails.py`)
- No server is enabled for production data without a named owner

---

## 4. Generated code review gates

Generated code is reviewed **as unfamiliar third-party code**, because that is
what it is. It was not written by someone you can ask "why?".

| Gate | Applies to | Rationale |
|---|---|---|
| Human review before merge | All AI-generated code | Non-negotiable. Volume is not a reason to weaken it. |
| SAST (semgrep, bandit) | All code | Catches the recurring classes |
| Dependency audit | Any new import | Models suggest plausible-sounding packages that do not exist — a slopsquatting vector |
| Secret scanning | All commits | Models reproduce credential-shaped strings from context |
| IaC policy scan | Terraform/CDK | Generated IaC defaults to permissive far more often than to restrictive |

**Two failure modes specific to generated code**, worth naming because they do not
look like normal review findings:

- **Plausible-but-wrong security code.** Hand-rolled crypto, a JWT check missing
  signature verification, an IAM policy that looks scoped but has a `*`. It reads
  fluently, which is exactly why it survives a skim.
- **Hallucinated dependencies.** A confidently imported package that does not
  exist — and that an attacker may have registered. This is why dependency audit
  is a gate and not a warning.

**Review-effort rule:** reviewer attention should scale with the *blast radius* of
the code, not with the difficulty of writing it. AI makes writing cheap and
reviewing exactly as expensive as it was before. That asymmetry is where the risk
actually accumulates.

---

## 5. Regulatory alignment

| Obligation | What it means for AI usage |
|---|---|
| **GDPR Art. 5** (minimisation) | Agents receive the minimum data for the task. Masked views are the default path. |
| **GDPR Art. 9** (special category) | Health data never reaches a model unmasked. Consent enforced as an RLS row filter. |
| **GDPR Art. 28** (processors) | An AI vendor processing personal data is a processor and needs a DPA. Check before enabling, not after. |
| **GDPR Art. 30** (records) | The audit log of agent data access *is* part of the record of processing. |
| **GDPR Art. 32** (security of processing) | Pseudonymisation is named in the Article; masked views implement it. |
| **EU AI Act** | A coding assistant is limited-risk, but transparency obligations still apply. Track it; do not assume exemption. |
| **Data residency** | Confirm where the model provider processes and retains data before it sees anything regulated. |

---

## 6. Training framework

The JD asks for training, not just policy. Four sessions, deliberately short:

1. **Why prompt injection is architectural** (45 min) — hands-on: inject
   instructions into data an agent reads, watch it comply. Nobody who has seen
   this once argues the point afterwards.
2. **Least privilege for agents** (45 min) — walk `sql/01-roles.sql`, then run
   `make evidence` and read the engine refusing.
3. **Reviewing generated code** (60 min) — the two failure modes above, with real
   examples from our own codebase.
4. **What may reach a model** (30 min) — the table in §1, and how to ask when
   unsure.

Refreshed when the tooling changes materially, not annually — annual training is
calibrated to audit cycles rather than to risk.

---

## 7. What this policy does *not* solve

Stated so nobody mistakes the policy for the mitigation:

- **Prompt injection is not solved.** It is bounded. The controls limit what a
  successfully-injected agent can reach; they do not prevent injection.
- **A determined insider with agent access is not stopped**, only logged. Detection
  is the control there, not prevention.
- **Model providers change behaviour without notice.** A control that depends on
  the model behaving a certain way is not a control. Nothing here does.
- **Developers will paste things into consumer chatbots.** Policy addresses this
  weakly. Making the sanctioned path genuinely easier addresses it better.

---

## Enforcement summary

| Rule | Enforced by | Depends on people |
|---|---|---|
| No unmasked PII to agents | DB grants + RLS + masked views | No |
| Read-only agent access | DB role + permission boundary | No |
| No writes via SQL tools | AST guardrail + DB grants | No |
| Every tool call audited | `mcp_core/audit.py` | No |
| MCP server approval | Review process | **Yes** |
| Generated code reviewed | Branch protection + CI | Partly |
| What may reach a model | Policy + tooling allowlist | **Yes** |

The right-hand column is the honest part. Four of seven rules hold without human
diligence; three do not, and those three are where this policy will fail first.
Knowing which is which is what makes it a policy rather than a wish.
