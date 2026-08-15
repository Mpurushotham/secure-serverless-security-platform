# Checkov suppression register

Every `checkov:skip` in `infra/` and `platform/`, with the reasoning that
justifies it.

An undocumented suppression is a disabled control that nobody decided to
disable. This file exists so each one can be re-argued at review time rather
than inherited — and so a reviewer can disagree with a specific line instead of
with a clean scan result.

Suppressions fall into two classes, and the distinction matters:

- **False positive** — the check misreads the construct (a permission boundary
  scored as a grant; a deny statement scored by its action list without its
  effect). Nothing is being accepted.
- **Deliberate deviation** — the check is correct about the general case and we
  are choosing otherwise, with a reason. These are risk acceptances and should
  be revisited when the context changes.


**26 suppressions across 5 files.**

| Check | Location | Justification |
|---|---|---|
| `CKV_AWS_111` | `infra/terraform/modules/agent-data-access/main.tf:50` | False positive by category. This document is a PERMISSION BOUNDARY, not a grant. A boundary defines a privilege CEILING and must enumerate actions against "*" — it grants nothing on its own; a principal receives access only where an attached policy AND this boundary both allow it. Constraining the resources here would narrow the ceiling in ways that silently break the role while making it no safer. |
| `CKV_AWS_107` | `infra/terraform/modules/agent-data-access/main.tf:51` | As above — no credential exposure is granted; the boundary is intersected with the attached policy. |
| `CKV_AWS_109` | `infra/terraform/modules/agent-data-access/main.tf:52` | The iam:* entry is inside a DENY statement. Checkov reads the action list without the effect. A deny on permissions management is the opposite of the risk this check describes. |
| `CKV_AWS_356` | `infra/terraform/modules/agent-data-access/main.tf:53` | Boundaries are inherently unscoped by resource; see the first note. |
| `CKV_AWS_109` | `infra/terraform/modules/aurora-secure/main.tf:57` | The account-root statement is required by KMS. Omitting it makes the key permanently unmanageable — AWS documents this as mandatory. |
| `CKV_AWS_111` | `infra/terraform/modules/aurora-secure/main.tf:58` | Same statement; scoping it defeats its purpose. |
| `CKV_AWS_356` | `infra/terraform/modules/aurora-secure/main.tf:59` | KMS key policies are scoped by the key they attach to, not by a resource ARN in the statement. |
| `CKV2_AWS_27` | `infra/terraform/modules/aurora-secure/main.tf:194` | Query logging is deliberately NOT enabled. A log of every statement against Art. 9 health data becomes a second copy of that data, in a store with weaker access controls than the table it came from. Slow-query logging (log_min_duration_statement) is enabled instead, and pgaudit records DDL and role changes — the events that matter for detection — without copying patient data into CloudWatch. |
| `CKV2_AWS_8` | `infra/terraform/modules/aurora-secure/main.tf:195` | Automated backups are retained for 30 days with a mandatory final snapshot and deletion protection. An AWS Backup plan is the right next step for cross-account backup isolation, but it is a change-managed decision about where regulated data may be copied to, not a module default. |
| `CKV2_AWS_57` | `infra/terraform/modules/aurora-secure/main.tf:308` | Automatic rotation is deliberately off. The salt is an input to a DETERMINISTIC mask: rotating it changes every masked value, breaking joins against previously exported analytics and destroying the ability to correlate historical findings. Rotation here is an incident response action (see docs/01-threat-model.md, branch 2a), executed with a re-masking plan — not a scheduled background job. |
| `CKV_AWS_109` | `infra/terraform/modules/bedrock-guardrails/main.tf:161` | The account-root statement is mandatory for KMS; without it the key cannot be administered ever again. |
| `CKV_AWS_111` | `infra/terraform/modules/bedrock-guardrails/main.tf:162` | Same statement — constraining it would lock the account out of its own key. |
| `CKV_AWS_356` | `infra/terraform/modules/bedrock-guardrails/main.tf:163` | KMS key policies scope to the key they are attached to; a resource ARN inside the statement is not how KMS works. |
| `CKV_AWS_338` | `infra/terraform/modules/bedrock-guardrails/main.tf:200` | The check wants >= 1 year retention. Retention here is bounded by var.log_retention_days (default 90) because these logs contain prompt text that may include personal data, and GDPR Art. 5(1)(e) requires storage limitation. Keeping prompts for a year to satisfy a generic logging benchmark would trade a privacy obligation for a security one; the security need is met by shipping detections, not raw prompts, to long-term storage. |
| `CKV_AWS_144` | `infra/terraform/modules/bedrock-guardrails/main.tf:208` | Cross-region replication is deliberately NOT enabled. These logs contain prompt and completion text that may include Art. 9 data; replicating them to a second region is a data-residency decision that must be made explicitly, not inherited from a module default. Durability is covered by versioning. |
| `CKV_AWS_18` | `infra/terraform/modules/bedrock-guardrails/main.tf:209` | S3 server access logging would write access records for a log bucket into another log bucket, which is a recursion that adds storage and little signal. CloudTrail S3 data events give the same visibility with better fidelity and central retention. |
| `CKV2_AWS_5` | `infra/terraform/modules/bedrock-guardrails/main.tf:394` | False positive. This group is attached to aws_vpc_endpoint.bedrock_runtime below; checkov's graph check does not resolve the count-indexed reference. |
| `CKV_AWS_111` | `platform/04-logging/main.tf:71` | False positive by category. This is a KMS KEY POLICY, not an identity policy. KMS refuses a key whose policy leaves no principal able to administer it, so the account-root statement is mandatory — without it the key becomes unmanageable and unrecoverable. The risk the check describes (unconstrained write access granted to a principal) does not apply: a key policy grants only on this key, and the mitigation is that this account is a log archive nobody operates in day to day. |
| `CKV_AWS_356` | `platform/04-logging/main.tf:72` | As above. Resource "*" inside a key policy means "this key" — there is no other resource it could name, and KMS rejects an ARN here. |
| `CKV_AWS_109` | `platform/04-logging/main.tf:73` | As above. kms:* in the root statement is key administration, which is the documented and required pattern for a customer-managed key. |
| `CKV_AWS_18` | `platform/04-logging/main.tf:132` | Deliberate risk acceptance. Access logging on the log archive writes access logs to another bucket, which itself needs access logging — the recursion has to terminate somewhere. CloudTrail data events on this bucket record reads with more identity detail than S3 access logs carry, and are configured on the trail below. |
| `CKV_AWS_144` | `platform/04-logging/main.tf:133` | Deliberate risk acceptance. Cross-region replication doubles storage cost for a bucket already protected by versioning and COMPLIANCE-mode Object Lock. The threat this addresses is regional loss of the archive; the threats actually in this model are tampering and deletion, both of which Object Lock covers and replication does not. Revisit if a regulator requires geographic redundancy of audit records. |
| `CKV2_AWS_62` | `platform/04-logging/main.tf:134` | False positive by category. Event notifications on the archive would fire on every log file CloudTrail delivers, which is thousands per day and carries no security signal. Deletion — the event worth knowing about — is already denied by the bucket policy and prevented by Object Lock. |
| `CKV_AWS_252` | `platform/04-logging/main.tf:291` | Deliberate design choice. SNS notification on trail delivery is the pre-EventBridge mechanism and delivers one message per log file, not per event — it cannot carry a detection. Detections are built on EventBridge and on the CloudWatch Logs destination below, both of which see individual events. |
| `CKV2_AWS_10` | `platform/04-logging/main.tf:292` | Conditional, not absent. cloudwatch_log_group_arn is a variable on this module and wiring it is the caller's decision, because the CloudWatch copy costs per ingested GB on top of S3. The variable documents that without it there is no near-real-time path and detections must come from EventBridge. Set it for any environment where detection latency matters. |
| `CKV2_AWS_48` | `platform/05-detection/main.tf:196` | Deliberate design choice, and correct at organization scale. all_supported is true; the check also wants include_global_resource_types true, but global resources (IAM users, roles, policies) are identical in every region. Recording them everywhere means paying N times to record the same entities and receiving N copies of every IAM finding. Exactly one region should set record_global_resource_types = true, which the variable documents. Setting it true here would make the module wrong wherever it is used more than once. |

## Deliberate deviations worth re-reading periodically

These are risk acceptances, not false positives.

- **`CKV2_AWS_27` (query logging off)** — logging every statement against Art. 9
  data would create a second copy of that data in a store with weaker access
  controls than the table it came from. A security benchmark and a privacy
  obligation genuinely conflict here; we resolved it toward privacy and
  compensated with pgaudit DDL/role logging plus slow-query logging.
- **`CKV_AWS_338` (90-day log retention, not one year)** — the same tension.
  Prompt logs may contain personal data, and GDPR Art. 5(1)(e) requires storage
  limitation. Long-term retention holds detections, not raw prompts.
- **`CKV_AWS_144` (no cross-region replication)** — data residency. Replicating
  Art. 9 data to a second region must be an explicit decision, never inherited
  from a module default.
- **`CKV2_AWS_57` (no automatic salt rotation)** — rotating a deterministic
  mask's salt changes every masked value and breaks joins against previously
  exported analytics. Rotation is an incident-response action with a re-masking
  plan (see `docs/01-threat-model.md`, branch 2a), not a scheduled job.
- **`CKV2_AWS_8` (no AWS Backup plan)** — the weakest justification in this file
  and the one most likely to be worth fixing. Automated backups, a mandatory
  final snapshot, and deletion protection are all in place, but cross-account
  backup isolation is a real gap rather than a false positive.
