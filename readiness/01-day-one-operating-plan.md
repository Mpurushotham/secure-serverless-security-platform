# Day-one operating plan

Not a generic 30/60/90. A plan for taking the driver's seat as the first
dedicated security lead in an engineering organisation that already ships fast.

**The governing constraint:** Apotea's Tech department is explicitly proud of being
flat, agile, and low-bureaucracy. A security lead who arrives with a control
framework and a change-approval board will be routed around within a quarter — not
defied, just quietly bypassed. Everything below assumes influence has to be earned
before authority is usable.

---

## Days 1–5: assess, change nothing

The deliverable for week one is **a written baseline assessment**, not a fix. Any
control shipped before understanding why the current state exists is a guess, and
a wrong guess in week one costs a year of credibility.

### Inventory

| Area | Question to answer |
|---|---|
| AWS accounts | How many, what separates them, who can reach production, is there an org with SCPs? |
| Identity | SSO or IAM users? Any long-lived access keys? How are humans separated from workloads? |
| Detection | Is GuardDuty on in *every* region including unused ones? Where do Security Hub findings actually go — a queue someone reads, or a dashboard nobody opens? |
| Secrets | Secrets Manager, SSM, or `.env` files? Any secrets in git history? |
| Pipelines | What can reach production and with whose credentials? Are there gates, and can they be skipped? |
| Data | Where does Art. 9 health data live, who can query it, and is that logged? |
| **AI usage** | Which assistants are in use, with what context, against what data? *Almost certainly nobody has asked yet.* |

### People

Meet, and ask each what they think the biggest risk is:

- Core Technology engineers — what does security currently cost them?
- Platform/infra owners — who holds the AWS keys today?
- Data/AI team — what is the agent architecture, what does it read?
- Legal / DPO — what is already committed to a regulator?
- Logistics/warehouse tech — the OT-adjacent estate is usually the forgotten one

### Output

A short document: current state, top five risks ranked by *likelihood × regulated
impact*, and what I intend to do first. Circulated, not presented. Being visibly
wrong about something in week one is cheap; being silently wrong for a quarter is
not.

---

## Days 6–30: stop the bleeding, nothing that needs re-architecture

Ship only controls that are **reversible, invisible to developers, and require no
migration**. Month-one re-architecture proposals are how new security leads lose
credibility before they have any.

| Control | Why first | Developer cost |
|---|---|---|
| SCPs: deny root use, deny disabling GuardDuty/CloudTrail, region restriction | Prevents the worst outcomes; no workload changes | Zero |
| GuardDuty + Security Hub in all regions, findings to a channel a human reads | Detection with no owner is theatre | Zero |
| Kill long-lived IAM access keys; enforce SSO + short-lived roles | Highest-likelihood breach path in most orgs | One-time |
| Branch protection + required checks on production repos | Cheap, unarguable | Low |
| Secret scanning across git history, with a rotation plan for whatever it finds | It will find something. It always does. | Low |
| **Interim AI usage guidance** — one page, not a policy document | Every day without it is uncontrolled data flow to third parties | Low |

**Explicitly deferred to later:** IaC refactors, workload re-architecture, new
mandatory tooling in the developer path, a formal risk register. None of them are
wrong; all of them are premature.

---

## Days 31–60: detection engineering and IR readiness

- **Detection as code.** Rules in version control, reviewed like code, with a
  false-positive budget. A rule nobody tunes becomes a rule everybody mutes.
- **Coverage map against MITRE ATT&CK Cloud.** Not for completeness theatre — to
  make "what can we not see?" answerable in a sentence.
- **First tabletop, with legal in the room.** Scenario: exposed customer data.
  The exercise is the *notification decision*, not the technical containment —
  because the 72-hour GDPR clock is the part that actually goes wrong.
- **Agent/AI data access under monitoring.** By now the inventory has shown what
  the agents touch; instrument it (this repository is the reference).
- **On-call reality check.** Who gets paged at 3am today? If the answer is "nobody
  specific", that is the finding.

---

## Days 61–90: make it stick

- **Compliance evidence automation.** Turn Art. 30 records and ISO 27001 evidence
  into pipeline output rather than a quarterly scramble.
- **Security champions.** One engineer per team, with real time allocated. Without
  allocated time it is a title, and titles do not review code.
- **Threat modelling as a service.** I facilitate, the team owns the output. The
  moment threat models become something security *does to* teams, they stop being
  read.
- **Publish the metrics.** See `02-security-metrics.md`. A security function that
  cannot show its trend line gets budgeted on vibes.

---

## Stakeholder map

| Who | They need from me | I need from them | Failure mode if neglected |
|---|---|---|---|
| Core Technology engineers | Guardrails that do not slow them down | Adoption, honest friction reports | They route around security silently |
| Platform / infra | Clear ownership boundaries | AWS org control, IaC access | Duplicated, conflicting controls |
| Data / AI team | Freedom to build agents safely | Architecture visibility, model inventory | Shadow AI on production data |
| Legal / DPO | Defensible evidence, honest risk | Regulatory interpretation | Discovering an obligation during an incident |
| Engineering leadership | Risk in business terms | Air cover for unpopular calls | Security becomes a veto, not a partner |
| Warehouse / logistics tech | Pragmatism about OT constraints | Access to the estate | The forgotten attack surface |

---

## Decision log

Every non-obvious security decision gets an ADR: context, options, decision,
consequences, revisit date. Three reasons, in order of how often they matter:

1. **"Own and evolve the security strategy"** means a successor must understand
   why, not just what. Undocumented controls get removed by the next person.
2. Auditors ask *why* this control and not another. "It seemed sensible" is not an
   answer that survives an ISO audit.
3. It forces me to write down when I am accepting risk rather than mitigating it —
   which is the decision most likely to be quietly forgotten.

Format: `docs/adr/NNNN-title.md`. Kept short. An ADR nobody writes because the
template is long is worse than no template.

---

## RACI — where security decides vs. advises

| Decision | Security | Engineering |
|---|---|---|
| Cloud guardrails (SCPs, org policy) | **Accountable** | Consulted |
| Production IAM policy | **Accountable** | Responsible |
| Application architecture | Consulted | **Accountable** |
| Accepting a specific risk to ship | Consulted | **Accountable** (with written acceptance) |
| Incident declaration and severity | **Accountable** | Consulted |
| Vendor / tool selection touching prod data | **Accountable** | Consulted |
| AI assistant usage rules | **Accountable** | Consulted |

The row that prevents most conflict is *"accepting a specific risk to ship"*.
Security does not own delivery trade-offs — but the acceptance is written down and
signed by someone with the authority to make it. That single convention removes
most of the adversarial dynamic between security and engineering.

---

## What would tell me this is going badly

Honest failure signals, worth writing down before I am invested in the outcome:

- Teams stop inviting me to design discussions → I have become a gate
- Findings rise but remediation does not → I am producing noise, not outcomes
- I am the only person who can explain a control → I have built a bus factor of one
- The tabletop keeps being rescheduled → leadership support is nominal
