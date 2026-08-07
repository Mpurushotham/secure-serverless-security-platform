# Security culture

The domain hardest to evidence in a repository, and the one most likely to
determine whether the role succeeds.

**Governing constraint:** APT's Tech department is explicitly proud of being
flat, agile and low-bureaucracy. A security function that adds process will be
routed around — not defied, just quietly bypassed. Everything here assumes
influence must be earned before authority is usable.

## Security champions

One engineer per team, **with allocated time**. Without allocated time it is a
title, and titles do not review code.

- **What they get:** early access to threat models, a direct line to me, training budget, and their name on the security work in their team's demos.
- **What they do:** first review on security-relevant PRs, run threat-modelling sessions with my facilitation, bring me the things I would otherwise learn too late.
- **What they are not:** a way to offload security work onto people with other jobs. If the programme becomes that, it dies within two quarters.

## Threat modelling as a service

I facilitate; the team owns the output. The moment threat models become something
security *does to* teams, they stop being read.

Format: 90 minutes, four questions — what are we building, what can go wrong,
what will we do about it, did we do a good job? Output is a page in the team's
own repository, not in mine.

Trigger on new services, on new data classes, and on architecture changes.
Explicitly *not* on every PR.

## Secure coding curriculum

Short and specific. Generic OWASP training measures clicking, not behaviour.

| Session | Length | Content |
|---|---|---|
| Authorisation in serverless | 60 min | IAM evaluation, boundaries, the failure modes I have seen |
| Data protection in practice | 60 min | Art. 9 handling, why masking lives in the database, hands-on with this repo |
| Reviewing generated code | 60 min | The two failure modes: plausible-but-wrong security code, hallucinated dependencies |
| Threat modelling | 90 min | Run as a real session on their own service |

## AI usage training — the JD's explicit ask

Four sessions, from `docs/04-ai-secure-coding-policy.md` §6:

1. **Why prompt injection is architectural** (45 min) — hands-on: inject instructions into data an agent reads, watch it comply. Nobody who has seen this once argues the point afterwards. This is the session that changes minds.
2. **Least privilege for agents** (45 min) — walk `sql/01-roles.sql`, then run `make evidence` and read the engine refusing.
3. **Reviewing generated code** (60 min) — real examples from our own codebase.
4. **What may reach a model** (30 min) — the data table, and how to ask when unsure.

Refreshed when tooling changes materially, not annually. Annual training is
calibrated to audit cycles rather than to risk.

## How I would actually build credibility

Ordered by what works, from experience of what does not:

1. **Fix something that annoys engineers in the first month.** A slow gate, a noisy alert, a permissions request that takes three days. Spend the credibility later.
2. **Be the person who reads the code.** A security lead who reviews PRs is a colleague. One who reviews documents is overhead.
3. **Never surprise someone in public.** A finding goes to the owner before it goes to a dashboard.
4. **Say the risk out loud, then support the decision.** Once a decision is made and written down, back it. Re-litigating is how security becomes something to work around.
5. **Publish what you get wrong.** This repository documents two of my own bugs. That is the norm I would want.

## The uncomfortable honest note

I can describe all of this. What a repository cannot show is whether I can hold
it for a year when a release is late and the pressure is on. That is an
interview conversation, and `readiness/00-jd-coverage-matrix.md` marks the
culture domain as `Workable` rather than `Strong` for exactly that reason.
