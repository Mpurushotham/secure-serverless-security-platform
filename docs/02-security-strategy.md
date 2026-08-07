# Security strategy

The twelve-month arc and target architecture. The execution detail for the first
ninety days lives in `readiness/01-day-one-operating-plan.md` — strategy and
operating plan are different documents and a panel reads them differently.

## Strategic position

An organisation that is **AI-first, serverless-first, and regulated** has a
different risk profile from one that is any two of those:

- **Serverless-first** removes most host-level attack surface and moves nearly all risk into **identity and configuration**. There is no server to patch; there is an IAM policy to get wrong.
- **AI-first** introduces a principal that acts on instructions from text it reads. Its blast radius is whatever you granted it.
- **Regulated** means the cost of a data event is not reputational but legal, with a 72-hour clock.

The intersection is where I would spend a security budget: **identity, data-plane
authorisation, and evidence**. Not endpoint. Not perimeter.

## Twelve-month arc

**Quarter 1 — make the current state legible and stop the bleeding.**
Inventory. Guardrails that need no migration: SCPs, IAM boundaries, detection routing, secret rotation, an AI-usage policy. Nothing requiring re-architecture.

**Quarter 2 — detection engineering and IR readiness.**
Detection as code with a false-positive budget. ATT&CK coverage map. First tabletop with legal present. On-call that actually pages someone.

**Quarter 3 — evidence automation.**
Art. 30 records and ISO 27001 evidence as pipeline output rather than a quarterly scramble. This is where compliance stops consuming engineering time.

**Quarter 4 — scale through others.**
Security champions with allocated time. Threat-modelling-as-a-service. The measure of success is that I am no longer the bottleneck.

## Target architecture

Same three planes as `docs/03-architecture.md`, applied organisation-wide:

| Plane | Principle | Twelve-month goal |
|---|---|---|
| **Guardrail** | Make the wrong thing hard to express | Every production workload under a permission boundary; every regulated data path through an allowlisted interface |
| **Data** | Least privilege enforced by the engine, not the app | IAM database auth everywhere; no long-lived database credentials |
| **Detection** | Alert on controls being exercised, not on data being touched | ATT&CK coverage map with named gaps; every detection carrying a false-positive budget |

## Principles I would actually hold to

**Prevention that cannot be measured is decoration.** Every control ships with a
way to demonstrate it works. This repository's `evidence/` directory is the
pattern.

**The engine beats the application.** Where a control can be enforced by
PostgreSQL, IAM, or an SCP rather than by code we maintain, it should be. Our
code will have bugs; grants will not.

**A control that gets switched off protects nothing.** This constrains design
more than any threat model. It is why unmasking is off-by-default rather than
blocked, why off-hours alerting does not page, and why a severity budget is a
count rather than zero.

**Guardrails over gates.** A gate stops work and creates an incentive to route
around security. A guardrail makes the wrong thing hard to express in the first
place — the Aurora module has no ingress-CIDR variable at all, so no deadline
can produce `0.0.0.0/0`.

**Write down risk acceptances.** Not to allocate blame, but because an
undocumented acceptance becomes policy within a year, and nobody can point at
when the decision was made.

## What I would push back on

Being explicit about this, because a security lead who never says no is not
doing the job — and one who says no reflexively gets routed around:

- **A broad AI content filter on a coding assistant.** Engineers doing legitimate security work discuss injection and exploits. A strong filter produces constant false refusals and the tool gets abandoned. Bound the agent's authorisation instead.
- **Logging every database statement for "audit".** Against Article 9 data this creates a second copy in a store with weaker access controls. It trades a privacy obligation for a security checkbox.
- **A formal risk register in month one.** It produces a document nobody reads. Fix the top five risks first; the register is for when there are more risks than attention.
- **Mandatory security review as a merge gate on every PR.** It makes security the bottleneck and trains people to batch changes. Gate on automated checks; review by risk.
