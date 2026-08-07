# Whiteboard-cold set

Eight diagrams to draw from memory, with a 60-second narration each.

**The honest self-test: draw it on paper before reading the description.** If you
read these instead, you will feel prepared and will not be. That failure mode is
the reason this file exists.

---

**1. AWS multi-account guardrail topology.**
Org root → OUs (security, workloads, sandbox) → accounts. SCPs at OU level; delegated admin for GuardDuty/Security Hub in the security account; log archive account nobody can write to.
*Narration:* "Separation is a blast-radius decision, not an org-chart one. SCPs sit at OU level so a new account inherits the guardrails rather than needing to be onboarded."

**2. Serverless request path with trust boundaries.**
Client → CloudFront/WAF → API Gateway (authz) → Lambda in isolated subnet → VPC endpoint → Aurora. Boundaries marked at each hop.
*Narration:* "No NAT gateway. The function that reaches Article 9 data should not be able to reach the internet — that is the exfiltration path that bypasses everything else."

**3. IAM policy evaluation.**
Explicit deny → SCP → permission boundary → identity policy → resource policy → session policy. Deny wins everywhere; boundary and identity policy intersect.
*Narration:* "The one people get wrong: a boundary grants nothing. Access requires *both* the boundary and an attached policy to allow it."

**4. Detection pipeline.**
GuardDuty + Config + app audit log → EventBridge → Security Hub → responder Lambda → SNS/ticket. Suppression and tuning loop drawn as a feedback arrow.
*Narration:* "The feedback arrow is the part that decides whether this survives a year. Without a false-positive budget, everything gets muted."

**5. GDPR data flow for Article 9 pharmacy data.**
Subject → application → Aurora (base tables) → masked views → agent. Consent as an RLS gate. Salt in Secrets Manager, off to one side, explicitly not reachable.
*Narration:* "Consent is a row filter, not a WHERE clause — it cannot be forgotten by a query that omits it."

**6. CI/CD gate sequence.**
Commit → secret scan → SAST → dependency audit → IaC policy → tests incl. bypass suite → SBOM → deploy. Severity gate and SLA check drawn as separate diamonds.
*Narration:* "Two different questions: is this bad enough to block now, and has this been open too long. Conflating them produces a gate that gets disabled."

**7. MCP / agent data-access threat model.**
Untrusted content → agent → MCP server → AST guardrail → masked view → database role. Three enforcement layers labelled with who enforces each.
*Narration:* "Layers one and two are my code and will have bugs. Layer three is PostgreSQL. That ordering is the entire design."

**8. Incident command structure.**
IC (decisions, not keyboard) · Technical Lead · Comms · Scribe. Parallel track for legal/DPO with the 72-hour clock on it.
*Narration:* "The IC does not debug. The moment they do, nobody is running the incident."

---

## Drill

Set a timer for five minutes. Draw one at random. Then narrate it out loud to
nobody. The narration is the part that fails first under interview pressure —
the diagram is easy; explaining *why* while drawing is not.
