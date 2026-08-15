# `00-discovery` — AWS inventory and security assessment

Implements the 25-point current-state baseline from
[`docs/aws_security_engineering_plan.md`](../../docs/aws_security_engineering_plan.md) §3 as running
code. Twenty-one collectors read an AWS account, a rule set turns observations into findings, and a
renderer produces an assessment a reader can check.

```bash
make assess                  # live, read-only, needs credentials
make assess-offline          # re-render from the committed snapshot, needs nothing
```

## Read-only is enforced, not promised

Three layers, in the order that matters:

| Layer | Mechanism | Holds when |
|---|---|---|
| 1 | Collectors call only configuration APIs | the code is correct |
| 2 | [`readonly_guard.py`](discovery/readonly_guard.py) refuses on `before-call` | a collector has a bug |
| 3 | [`iam/discovery-readonly.json`](iam/discovery-readonly.json) | everything above is compromised |

Layer 3 is the one that actually holds — the same ordering as the SQL guardrail and the
`mcp_readonly` database role elsewhere in this repository. Layers 1 and 2 are application code and
can have bugs; layer 3 is enforced by AWS.

Layer 2 exists because the first live run happens under an *existing* admin credential — creating
the purpose-built role is itself a change to the account being assessed, and that needs approval.
Under an admin credential, IAM will happily allow `s3:GetObject`. The guard is what stops a
collector bug from reading customer data during an assessment that was only meant to look at
configuration.

The guard applies two tests, and an operation must pass both:

1. **Structural** — the operation name must begin with a read-only verb. `PutBucketPolicy` fails
   here, and so does any future API AWS ships with a mutating verb, without anyone editing this
   file.
2. **Data-plane** — the operation must not be in `DATA_PLANE_READS`. This exists because the first
   test is not sufficient: `GetObject`, `GetSecretValue`, `GetParameter` and `Decrypt` are all
   read-only in the sense that they change nothing, and all four return exactly the data an
   inventory tool has no business seeing.

The distinction is *configuration versus content*. This reads how a bucket is configured. It never
reads what is in it.

`tests/test_readonly_guard.py` drives every collector against a recording stub and asserts that not
one of them attempts an operation the guard would refuse — a statement about the whole tool, not
about the guard in isolation. A second test asserts the guard and the IAM policy have not drifted
apart, since two controls that disagree mean one of them is wrong.

The IAM policy is validated with IAM Access Analyzer, which caught three real errors on first
write: two action names that do not exist, and a `NotAction` block using service-position wildcards
that IAM does not support.

## Four outcomes, never three

Every API call is recorded as `ok`, `absent`, `denied`, `unsupported`, or `error`. Collapsing these
is how an assessment ends up claiming a control is missing when it was only ever invisible:

- **absent** — the thing is not configured. A Lambda with no function URL answers
  `ResourceNotFoundException`. That is an answer, not a failure.
- **denied** — the assessing identity could not look. Reported as `not-permitted`, never as absent.
- **unsupported** — the service or API does not exist here. Includes APIs missing from the
  installed botocore, so an older SDK degrades rather than crashes.
- **error** — a real problem, and the only bucket worth reading top to bottom.

## Redaction

The raw snapshot is an accurate description of how to attack the estate it describes. It stays in
`snapshots/raw/`, which is gitignored. Everything committed — the redacted snapshot and the report
rendered from it — has account IDs, organization identifiers, emails, resource IDs and access-key
IDs replaced with stable salted pseudonyms.

Stable matters: `acct_4f2a91` is the same account throughout the document, so a finding can be
followed from the account table to the role that caused it, and the diff between two snapshots
shows real change rather than noise.

Resource **names** are not redacted. A report where every bucket is `bucket_a91f2c` is unreadable,
and a name is not a credential. If that trade-off is wrong for a given estate, the redactor is one
file.

This is pseudonymisation to keep identifiers out of a public index. It is not a control against
someone who already knows the account ID — the salt is derived from it.

## Layout

```
discovery/
  run.py               runner, thread pool, snapshot writing
  session.py           boto3 session, region enumeration, call audit trail
  readonly_guard.py    layer 2
  redact.py            pseudonymisation
  rules.py             41 rules: observations in, findings out
  report.py            markdown + mermaid renderer
  checklist.py         the 25 baseline items, verbatim
  collectors/          21 collectors, one domain each
iam/                   the policy this should run under
snapshots/             redacted (committed) and raw (gitignored)
report/                assessment.md
tests/                 96 tests
```

## Why rules are Python and not YAML

The plan called for YAML plus JSONPath, which reads better in a policy review. It cannot express
the conditions that turned out to matter: coverage as a fraction of regions, and correlations
across collectors. The sharpest finding in the first live run was *"343 Config rules are defined
and the recorder is switched off"* — two collectors in one predicate.

Rules are therefore data with one callable field. Each carries an id, severity, domain, checklist
mapping, remediation and references; only the condition is code.

## What this does not do

- **Single account per run.** Cross-account discovery needs a read role in each member account.
  `--assume-role` is not implemented yet.
- **No Security Hub or GuardDuty *findings*.** Coverage of those services is assessed; their
  findings are Phase 5's job.
- **Five checklist items are judgement, not observation** — vulnerability process, incident
  procedures, data flows, regulatory scope, and the top-ten list. They are assembled from documents
  already in this repository and marked as such in the coverage table, rather than quietly missing.
- **Severity is opinionated.** It follows
  [`readiness/05-vulnerability-management.md`](../../readiness/05-vulnerability-management.md) and
  deliberately not CVSS: exposure, blast radius and data sensitivity decide it.

## Credential resolution

`--profile` accepts any profile the AWS CLI can resolve. If boto3 cannot resolve it directly — as
with a profile that role-chains from an `aws login` session — the session falls back to
`aws configure export-credentials`, which returns short-lived STS credentials held in the process
and never written to disk.
