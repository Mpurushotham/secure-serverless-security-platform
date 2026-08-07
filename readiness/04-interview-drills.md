# Interview drill bank

Questions this specific panel is likely to ask. Written answers, because "I know
this" and "I can say this clearly at 4pm in a second language" are different
skills.

**Format note:** for scenario questions, lead with the *decision*, then the
reasoning. Panels interrupt; front-load the answer.

## AWS and IAM

**1. Walk me through IAM policy evaluation.**
Explicit deny anywhere wins. Then: SCP must allow, permission boundary must allow, identity policy must allow. Resource policy can grant cross-account independently. A boundary grants nothing on its own — access needs boundary *and* identity policy.

**2. When would you use a permission boundary over an SCP?**
SCP for organisational invariants that apply regardless of who creates the role. Boundary for delegating role creation safely — it caps what a team can grant itself. Different questions: "may this account ever do X" vs "may this role ever exceed Y".

**3. How do you give an application database access with no credential?**
IAM database authentication. The role calls `generate-db-auth-token` and presents a 15-minute token. Nothing long-lived exists to leak. Scope `rds-db:connect` to the cluster **resource ID** and one database user — the resource ID, because a cluster name can be recreated.

**4. Least privilege for a serverless function that must read one S3 prefix?**
Actions `s3:GetObject` only, resource `arn:.../prefix/*`, condition on `s3:ExistingObjectTag` if applicable, plus a boundary. Then check the KMS key policy — this is where people stop too early and the function fails at runtime.

## Detection and response

**5. GuardDuty reports crypto-mining on a Lambda. First five minutes?**
Contain first: reserved concurrency to zero. It is reversible and preserves the function for forensics. Then revoke the role's sessions with a token-issue-time deny. Then ask whether it is real. The mining is the symptom; the execution role's data access is the incident.

**6. How do you stop a SIEM becoming noise?**
A false-positive budget per rule, and alert on *controls being exercised* rather than on data being touched. "Someone read the prescriptions table" fires constantly. "The guardrail refused eleven times in five minutes" fires when something is wrong.

**7. A developer pasted production data into an AI assistant. What now?**
Scope: what data, which assistant, retention terms. If personal data, engage the DPO immediately — the 72-hour clock may be running. Then the harder question: why was that the easy path? If the sanctioned route was slower, policy will not fix it.

## GDPR and regulated data

**8. Is pseudonymised data still personal data?**
Yes — Recital 26. It reduces risk and is named in Art. 32(1)(a), but re-identification with additional information keeps it in scope. Which is why the masking salt lives in Secrets Manager with an explicit deny for the agent role: the argument holds only while the key is unreachable.

**9. When does the 72-hour clock start?**
At awareness — reasonable certainty a breach occurred, not the end of your investigation. Art. 33(4) permits phased information, so notify partially rather than late. Teams turn a notifiable breach into a late notification by waiting for certainty.

**10. Article 9 data in logs — how do you handle it?**
Do not log it. This is why full query logging is off on the Aurora cluster: a log of every statement against health data is a second copy in a store with weaker access controls. A security benchmark and Art. 5(1)(e) genuinely conflict here; I resolved it toward privacy and compensated with pgaudit DDL/role events and slow-query logging.

## Judgment and leadership

**11. How would you say no to a shipping deadline?**
Rarely as "no". Name the risk, the blast radius, and the cheapest mitigation that lets it ship. If it ships anyway, write the acceptance down with an owner and a revisit date. The undocumented acceptance is what becomes policy.

**12. First 30 days as the first dedicated security lead?**
Assess and change nothing in week one. Then only reversible controls needing no migration — SCPs, detection routing, credential hygiene, an AI-usage policy. Month-one re-architecture proposals are how new security leads lose credibility before they have any.

**13. An engineer resents security and blocks your changes.**
Find out what security has cost them before. Usually a real story about being blocked late by someone who did not understand their work. Fix one thing they care about first. Authority does not survive being used early.

**14. Something you were wrong about.**
The RLS policy in this repository. It looked correct in DDL and enforced nothing: a Postgres view executes with its owner's privileges, the owner was a superuser, and superusers bypass RLS unconditionally. Caught by the privilege proof on first run. The lesson is that reviewing a control is not the same as demonstrating it — which is why the repo generates evidence rather than asserting.

**15. What are you weakest at?**
Fleet-scale EDR, and incident command in a regulated Swedish entity. I have written playbooks and participated in incidents; I have not owned the notification decision with a regulator in the room. Also Läkemedelsverket specifics — that is reading, and I would do it before starting rather than during.

## Questions to ask them

- Who currently holds production AWS access, and how is it granted?
- What is the AI-assistant footprint today, and has anyone inventoried what it reads?
- When was the last incident, and what changed as a result?
- Where does security sit when a deadline is at risk?
- What would make you say, twelve months in, that this hire worked?
