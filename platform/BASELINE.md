# Baseline IaC — what it fixes, and what it cannot

Three Terraform roots, written against what `platform/00-discovery` actually
found in this organization rather than against a generic template.

| Root | Closes |
|---|---|
| `01-organization/` | ORG-001, ORG-002, ORG-004 · surfaces ORG-003 |
| `04-logging/` | LOG-002, LOG-003 |
| `05-detection/` | LOG-004, DET-001…DET-006 |

**Nothing here has been applied.** Every root is validated statically —
`terraform validate`, `terraform fmt`, `tflint`, `checkov` — and `make validate`
runs all of it without an AWS account.

## Finding → resource

| Finding | Severity | Resource |
|---|---|---|
| ORG-001 no delegated administrators | High | `aws_organizations_delegated_administrator.security` (8 services) |
| ORG-002 SCPs on empty OUs | Medium | `checks.tf` cannot see account membership; `example.tfvars` documents verifying it, and the discovery rule stays the detector |
| ORG-003 root-attached SCPs miss the management account | High | **No resource. There is no fix.** `check "root_attached_policies_do_not_cover_the_management_account"` forces an explicit acknowledgement instead |
| ORG-004 RCPs enabled but unused | Medium | `aws_organizations_policy.rcp` — organization boundary and TLS |
| LOG-002 trail not encrypted with a CMK | Medium | `aws_kms_key.trail`, decrypt granted to named roles only |
| LOG-003 no data events | Medium | `advanced_event_selector` blocks, scoped to named buckets and functions |
| LOG-004 Config not recording | High | `aws_config_configuration_recorder_status.this` — the resource that was missing |
| DET-001/002 GuardDuty coverage and features | High/Medium | `aws_guardduty_organization_configuration_feature`, every plan listed explicitly |
| DET-003/004 standards not READY, CIS 1.2.0 | Medium/Low | `aws_securityhub_standards_subscription`, CIS pinned to v3.0.0 |
| DET-005/006 no external-access analyzer | High/Medium | `aws_accessanalyzer_analyzer.external` alongside `.unused` |

## Three things worth arguing with

**An SCP attached at the root does not cover the management account.** This is a
property of Organizations, not a gap in the configuration, and no policy in this
directory changes it. The treatment is operational: hold nothing in the
management account worth reaching. The module makes you say so — `terraform
plan` fails the check until `acknowledge_management_account_exemption = true`.

**Every policy carries a `breaks` string, and it is required.** Not
documentation for its own sake. An SCP whose blast radius nobody can describe
gets detached during an incident and never reattached, and authoring time is the
only moment anyone actually knows. It is also a tag on the policy and a
`terraform output`, so an incident responder can answer "what does detaching
this cost me" without reading JSON.

**Every deny that protects a security control exempts one named break-glass
role.** A guardrail with no exit is removed the first time it is genuinely in
the way, under pressure, by someone who will not put it back. The role is named
rather than wildcarded so the exemption is auditable and its use is a CloudTrail
event worth alerting on.

## Two things the toolchain got wrong

**checkov cannot parse a multi-line parenthesised condition.** Terraform accepts

```hcl
condition = (
  !var.x
  || var.y != var.z
)
```

checkov reports `Parsing errors: 1`, scans **zero** checks in that file, and
exits clean — so a file nothing scanned is indistinguishable from a clean one.
`checks.tf` was unscanned until the conditions were rewritten with `anytrue()`.

Worse: given several `-d` flags, checkov stops reporting parse errors at all.
`make validate` therefore scans one root per invocation and fails on any
unparsed file. Verified by introducing an unparseable file and watching the
gate exit non-zero.

**Policy documents are `.json.tftpl`, not `.json`.** They are templates — the
break-glass role name and the organization ID are interpolated — so a `.json`
extension makes checkov try to parse `${...}` as a value and fail, which was the
second source of silent non-scanning.

## Planned against the live organization

`terraform plan` was run against the real organization. Two things came out of
it that static validation had not:

**The roots had no provider block.** `terraform validate` passes without one —
so a configuration can clear every static check in CI and still fail at plan
with *"provider requires explicit configuration"*. These are root
configurations, not shared modules, so each now declares its provider.
`providers.tf` in each root exists because of that gap.

**The `check` block fired, correctly, against real infrastructure.** With
defaults, the plan proposes `8 to add, 0 to change, 0 to destroy` — eight
delegated administrators — and the check refuses:

> `security_tooling_account_id` is unset, so delegated administration would
> point at the management account, which is where the services already are.
> This is finding ORG-001 restated, not fixed.

That is the correct answer. **The blocker is organisational, not technical:
there is no security-tooling account yet.** Delegating to the management
account would satisfy the resource and not the finding.

With `delegate_security_services = false` the plan is clean — zero changes —
which is the honest interim state until an account exists.

## Applying this

In order, because the dependencies are real:

1. Create a security-tooling account and set `security_tooling_account_id`.
2. `01-organization` **without** the SCP/RCP attachments — delegation first.
3. `05-detection` from the security account with
   `is_delegated_administrator = true`.
4. `04-logging` in the log-archive account.
5. `01-organization` again, this time with attachments — and read every `breaks`
   string first.

Order matters most at step 5. Attaching `protect-security-controls` before
`05-detection` exists means the SCP denies the API calls that would create it.

## What is not here

- **OUs as code.** The 14 OUs discovery found already exist and are correct.
  Adopting them into Terraform state is a `terraform import` per OU, which is an
  operator action against a live organization — not something to encode blind.
- **Config conformance packs.** The variable exists; choosing a pack is a
  decision about which controls you intend to answer for.
- **Multi-region.** `05-detection` covers one region per provider. Looping
  regions inside a module makes the blast radius of an apply invisible, so it is
  the caller's job via provider aliases or a stack per region.
