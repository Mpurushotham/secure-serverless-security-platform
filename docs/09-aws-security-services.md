# AWS security services: what each one is for

A catalogue with opinions. The failure mode this document exists to prevent is
enabling everything, routing none of it, and calling that a security programme.

**Security Hub is the aggregation layer, not a detector.** Almost nothing here
produces findings *for* Security Hub; they produce findings that Security Hub
collects. Treating it as the thing that finds problems leads to the classic
outcome: a dashboard with 4,000 findings that nobody has opened since the day it
was switched on.

---

## The layer model

```
DETECT        GuardDuty · Inspector · Macie · Config rules · CloudTrail
                              ↓ all findings normalised to ASFF
AGGREGATE     Security Hub  ──→ EventBridge ──→ responder / ticket / page
                              ↑
INVESTIGATE   Detective · CloudTrail Lake · Athena over the log archive
PREVENT       SCPs · IAM boundaries · Control Tower · resource policies
```

---

## Detection

| Service | Detects | Enable when | Honest note |
|---|---|---|---|
| **GuardDuty** | Compromised credentials, crypto-mining, C2 DNS, anomalous API use | **Always. Every region, including unused ones** | Unused regions are where an attacker operates precisely because nobody looks. Enable the Lambda, EKS, RDS and S3 protection plans separately — they are not on by default. |
| **Inspector v2** | CVEs in Lambda, ECR images, EC2 | Any container or Lambda estate | Continuous, agentless for Lambda/ECR. Replaces a separate image-scan step in most pipelines. |
| **Macie** | Personal data in S3 | You have a data lake and are regulated | Expensive at scale — sample first, then target buckets. Its real value is finding Article 9 data in a bucket nobody knew about. |
| **Config** | Resource configuration drift | Always, with a bounded rule set | Enabling 200 managed rules produces noise nobody triages. Start with ~20 that map to your actual obligations. |
| **CloudTrail** | Every API call | Always, org trail, log archive account | Data events (S3 object reads, Lambda invokes) are **off by default** and are the ones that answer "what did they actually read". They also cost the most — enable per-bucket, not globally. |
| **VPC Flow Logs** | Network flows | On regulated subnets | Answers "did the compromised function call out?" — unanswerable without them |
| **Security Lake** | Normalises all of the above to OCSF | Multi-account with a real SIEM | Genuinely useful, genuinely a project. Not month one. |

## Aggregation and response

| Service | Role |
|---|---|
| **Security Hub** | Single pane. Normalises to ASFF, runs standards (CIS, AWS FSBP, PCI DSS), and — the part that matters — **emits every finding to EventBridge**. That is the integration point. |
| **EventBridge** | Routing and automation. `infra/terraform/detections/` uses it for all eight detections. |
| **Systems Manager Automation / Lambda** | Auto-remediation. Start with *reversible* actions only: quarantine a security group, disable an access key, isolate an instance. Auto-deleting resources during an incident destroys evidence. |
| **Detective** | Graph-based investigation. Earns its cost once you have real incidents, not before. |

**The single most valuable configuration:** delegated administrator for GuardDuty
and Security Hub in a dedicated security account, with all member accounts
auto-enrolled. Without it, a new account joins the org with no detection and
nobody notices for a quarter.

## Prevention

| Service | Role | The one to get right |
|---|---|---|
| **SCPs** | Organisation-wide ceilings | Deny root use, deny disabling CloudTrail/GuardDuty, deny regions outside your footprint. SCPs deny; they never grant. |
| **IAM permission boundaries** | Per-role ceilings | The only control that survives someone attaching a wider policy later |
| **Control Tower** | Landing zone and guardrails | Worth it for a new org; retrofitting to an existing one is a migration project |
| **Resource policies** | Cross-account and endpoint controls | An S3 bucket policy denying `aws:SecureTransport: false` and a VPC endpoint policy denying foreign accounts are two lines each and close real paths |
| **KMS** | Encryption with an auditable policy | Customer-managed keys where you need provable rotation and independent revocation; AWS-managed where you do not |
| **WAF / Shield** | Edge filtering | WAF earns its place on public endpoints. On an internal IAM-authorised API it costs money and finds nothing. |

---

## What this repository implements

| Service | Where | Status |
|---|---|---|
| GuardDuty, Security Hub, IAM, Config, S3, KMS — **read** | `mcp-servers/aws_posture_mcp/` | Working, moto-tested |
| Detection routing (8 rules → SNS) | `infra/terraform/detections/` | Validated |
| KMS CMK with rotation and explicit key policy | `modules/aurora-secure`, `modules/bedrock-guardrails` | Validated |
| Bedrock guardrails + invocation logging | `modules/bedrock-guardrails` | Validated |
| VPC endpoint policy denying unguarded inference | `modules/bedrock-guardrails` | Validated |
| Permission boundaries | `modules/agent-data-access`, `modules/github-oidc` | Validated |
| GuardDuty/Config/Security Hub **enablement** | — | **Not implemented.** `Cloud-AWS-Platform-Management` already has these modules; duplicating them here would add nothing. |

---

## Sequencing, if starting from nothing

Ordered by value per unit of effort, not by completeness:

1. **CloudTrail org trail → log archive account.** Without it, no incident is investigable. Everything else is optional by comparison.
2. **GuardDuty, all regions, delegated admin.** Highest signal per configuration effort of anything AWS sells.
3. **SCPs for the catastrophic cases.** Root use, disabling logging, region sprawl.
4. **Security Hub + EventBridge routing to a channel a human reads.** Detection with no owner is theatre.
5. **Config, ~20 rules mapped to actual obligations.** Not 200.
6. **Inspector v2** if you run containers or Lambda.
7. **Macie**, targeted at buckets you suspect.
8. **Security Lake / Detective** when you have the volume to justify them.

Steps 1–4 are days of work and cover most of the realistic risk. Steps 5–8 are
where programmes stall, usually because 1–4 were skipped in favour of the more
interesting tools.
