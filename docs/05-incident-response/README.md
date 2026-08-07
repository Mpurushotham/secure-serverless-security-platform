# Incident response playbooks

Three playbooks, written to be usable at 03:00 by someone who did not write them.

| # | Scenario | Why this one |
|---|---|---|
| [01](01-leaked-aws-credential.md) | Leaked AWS credential | The most common cloud incident. Everyone thinks they know it; most teams get the *order* wrong. |
| [02](02-guardduty-cryptomining.md) | GuardDuty crypto-mining on Lambda | Tests whether you can distinguish a real finding from a noisy one under pressure. |
| [03](03-agent-data-exfiltration.md) | **PII exfiltration via a compromised AI agent** | The one almost nobody has written, and the one this architecture makes likely. |

## Conventions used in all three

**Severity is decided first, and out loud.** A responder who starts containing before declaring severity ends up making regulatory decisions implicitly, by running out of time.

| Severity | Meaning | Response |
|---|---|---|
| SEV1 | Confirmed personal data exposure, or production unavailable | Page immediately. Incident commander named within 15 minutes. Legal/DPO engaged from the start. |
| SEV2 | Credible compromise, no confirmed data exposure | Page during business hours; contain immediately regardless. |
| SEV3 | Suspicious activity requiring investigation | Ticket, investigate within one business day. |

**Roles are named at declaration, not assumed.**

- **Incident Commander** — owns decisions and the timeline. Does not perform technical work; the moment the IC is also debugging, nobody is running the incident.
- **Technical Lead** — executes containment and investigation.
- **Communications** — internal updates and, if it comes to it, the regulator.
- **Scribe** — the timeline. Under-valued and the thing you will most regret not having.

**Preserve before you contain, unless containment cannot wait.** Terminating an instance destroys memory; revoking a session destroys the ability to watch what the attacker does next. Both are sometimes correct. Make it a decision rather than a reflex, and write down which you chose.

## The GDPR clock

Article 33: notify the supervisory authority (in Sweden, **Integritetsskyddsmyndigheten**) within **72 hours of becoming aware** of a personal data breach, unless it is unlikely to result in a risk to individuals.

Three things teams get wrong, in order of how expensive they are:

1. **"Becoming aware" is earlier than you would like.** It starts at reasonable certainty a breach occurred, not at the end of your investigation. The clock is usually already running by the time someone asks whether it is.
2. **A partial notification is permitted.** Article 33(4) allows information in phases. Teams delay notifying because the investigation is incomplete, and turn a notifiable breach into a late notification — a second, entirely avoidable finding.
3. **Article 9 data raises the stakes on Article 34.** Health data exposure makes notifying the affected individuals directly far more likely to be required.

**This decision is not the Technical Lead's to make.** Engage the DPO on declaration of any SEV1, before knowing whether it qualifies. Waiting until you are sure is how the 72 hours gets spent.

## Testing

A playbook that has never been exercised is fiction. Cadence:

- Tabletop each playbook **quarterly**, with legal present for at least one per year
- After each exercise, record what was *wrong* in the playbook — a tabletop that finds no gaps was not a real tabletop
- Rotate the incident commander; a team with one person who can run an incident does not have incident response, it has one person

## Honest limitation

These are written from architectural knowledge of this system, not from having run these exact incidents in a regulated Swedish pharmacy. Playbooks 01 and 02 are well-trodden ground. Playbook 03 is genuinely novel and correspondingly less battle-tested — its containment steps are reasoned from the control design, and the first tabletop will find things wrong with it. See `readiness/00-jd-coverage-matrix.md`, where incident command in a regulated entity is listed as a `Gap` rather than claimed.
