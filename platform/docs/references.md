# Upstream references — what was studied, what was taken, what was not

Four AWS sample repositories were read in full before any code in `platform/` was written.
**None of them is vendored into this repository.** They are cloned into `.reference/`, which is
gitignored, and nothing from them is committed.

## Why study rather than vendor

The obvious alternative — commit trimmed copies under `reference/` — was rejected for three reasons:

1. **Licence mixing.** Three of the four are MIT-0; the fourth carries CC BY-SA 4.0 on its
   documentation and a modified MIT licence on its sample code. This repository is MIT. Copying
   CC BY-SA prose into an MIT repository creates a share-alike obligation over whatever it is
   combined with, for no engineering benefit.
2. **Size.** The four clones total ~170 MB. Committing even a trimmed subset makes every clone of
   this repository slower to serve a purpose that a URL serves better.
3. **Verifiability.** A vendored copy rots silently. A cited URL plus a stated pattern can be
   checked against upstream by anyone, at any time, and is honest about what is borrowed thinking
   versus borrowed code.

Everything under `platform/` is first-party code. Where a design decision came from one of these
repositories, the decision is credited below rather than the code being copied.

To reproduce the study environment:

```bash
mkdir -p .reference && cd .reference
for r in aws-serverless-security-workshop serverless-test-samples \
         serverless-samples aws-serverless-ecommerce-platform; do
  git clone --depth 1 "https://github.com/aws-samples/$r.git"
done
```

---

## 1. `aws-samples/aws-serverless-security-workshop`

<https://github.com/aws-samples/aws-serverless-security-workshop> — docs CC BY-SA 4.0, sample code
modified MIT (`LICENSE-SAMPLECODE`).

A deliberately insecure Lambda + API Gateway + Aurora application, with modules that close each gap
in turn. Its module list is effectively a curriculum:

```
01-add-authentication   02-add-secrets-manager   03-input-validation
04-ssl-in-transit       05-usage-plan            06-waf
07-dependency-vulnerability                      08-xray
```

**Taken — the five-domain framing.** The workshop organises serverless security as *identity &
access management · infrastructure · data · code · logging & monitoring*. `platform/00-discovery`
groups its collectors and findings on those five axes rather than by AWS service, because a report
organised by service tells you what is broken and a report organised by domain tells you who fixes it.

**Taken — the insecure-baseline-first method.** The workshop's premise is that you cannot evaluate a
control you have never seen fail. That is the same argument behind this repository's existing
`evidence/guardrail-bypass-report.md`, and it is why `platform/11-serverless/tests/security/`
asserts the *refusal* of specific attacks rather than only the success of the happy path.

**Not taken — the architecture.** The workshop uses Aurora behind Lambda with a NAT path. The
golden path here is DynamoDB with a CMK and no NAT, because the workload does not need relational
semantics and a NAT gateway is an egress path that has to be justified, not defaulted to.

**Not taken — its IAM.** The workshop states plainly that it does not cover least privilege and
defers that to an "Extra Credit" section. Least privilege is the first-class concern here, so the
execution-role design owes nothing to it.

---

## 2. `aws-samples/serverless-test-samples`

<https://github.com/aws-samples/serverless-test-samples> — MIT-0.

The most directly useful of the four. `typescript-test-samples/apigw-lambda-dynamodb` is the same
shape as our golden path.

**Taken — one Jest config per test layer.** The sample ships `jest.unit.config.ts`,
`jest.integration.config.ts` and a base `jest.config.ts` rather than one config with tags. This
matters more here than there: it lets `platform/11-serverless` run unit and infra-invariant tests
on a credential-free clone while integration, e2e and security-e2e stay excluded by configuration
rather than by a runtime skip that can be silently miscounted as a pass.

**Taken — checked-in event fixtures.** `src/events/event-data.ts` holds real API Gateway proxy
event shapes as typed constants. Hand-rolled event objects drift from the real envelope and produce
handlers that pass tests and fail in production.

**Taken, with a caveat — "test in the cloud".** `Serverless-Testing-Principles.md` argues for
testing against real AWS rather than emulators, because only that exercises IAM policies, service
quotas and current API signatures. That is correct, and it is precisely why the e2e and
security-e2e layers here are written to run against a deployed stack. It is also why they are
**not** run by default: this repository's standing invariant is that a fresh clone verifies without
credentials or spend. Both things are true, and the resolution is layering, not choosing a side.

**Not taken — the emulator scepticism, wholesale.** The same document advises using emulators
sparingly. For the integration layer we do use DynamoDB Local / LocalStack, because the alternative
is no integration coverage at all on a fork with no AWS account. The trade-off is stated in
`platform/11-serverless/tests/README.md` rather than hidden.

---

## 3. `aws-samples/serverless-samples`

<https://github.com/aws-samples/serverless-samples> — MIT-0. Specifically
`owasp-api-security-controls-demo/`.

A coffee-shop microservice set (order · payment · fulfillment · rewards) demonstrating mitigations
for four OWASP API Security Top 10 risks:

| Risk | |
|---|---|
| API1:2023 | Broken Object Level Authorization |
| API2:2023 | Broken Authentication |
| API3:2023 | Broken Object Property Level Authorization |
| API5:2023 | Broken Function Level Authorization |

**Taken — object-level authorization as a test, not a claim.** API1 (BOLA/IDOR) is the risk that
static analysis cannot see: the code is syntactically fine, the IAM is fine, and the bug is that
user A can read user B's order by changing an ID. The only control that demonstrates it is a test
that authenticates as one tenant and requests another tenant's resource. That test is
`platform/11-serverless/tests/security/` case 3, and it asserts **403, not 200** — the assertion
most API test suites forget to write.

**Taken — property-level authorization.** API3 says the response shape must depend on the caller,
not only on the record. The golden-path handlers project fields by role rather than filtering in the
client, which mirrors the column-level grants already used in
`mcp-servers/rds_readonly_mcp/sql/02-masked-views.sql`. Same principle, different enforcement point.

**Taken — the explicit scope disclaimer.** The demo states that its controls "must be used in
conjunction with perimeter security controls". The equivalent statement lives in
`platform/11-serverless/README.md`, because a reference architecture that does not say what it
excludes will be deployed as though it excludes nothing.

**Not taken — SAM.** The demo is SAM-based. Adding SAM alongside Terraform and CDK would mean a
third IaC toolchain to scan, govern and keep patched. The CDK app expresses the same controls.

---

## 4. `aws-samples/aws-serverless-ecommerce-platform`

<https://github.com/aws-samples/aws-serverless-ecommerce-platform> — MIT-0. Specifically
`docs/testing.md`.

**Taken — the three-layer definition, stated precisely.** Its distinction is sharper than the usual
pyramid diagram: *unit* tests validate code inside a function; *integration* tests validate that a
**single service honours its contract**; *end-to-end* tests use **only external APIs** to act and to
assert. The middle definition is the useful one — it makes "integration test" mean something
falsifiable rather than "a test that touches AWS".

**Taken — the reason unit tests cover unreachable branches.** The repository argues that a Lambda
behind an IAM-authorized API should *still* check for credentials in its own code, and that unit
tests should cover that branch even though API Gateway makes it unreachable in normal operation.
That is defence in depth expressed as test coverage, and it is the same argument this repository
makes for its three enforcement layers in `docs/03-architecture.md`. Adopted directly.

**Taken — lint rules as architecture enforcement.** It ships project-specific CloudFormation lint
rules — every Lambda must have a log group; every async function must have a failure destination.
That is the same job the CDK Aspects in `platform/lib/cdk-security` do, and it confirmed the choice
to add `RequireDeadLetterQueueAspect` rather than rely on review.

**Noted, not adopted — the 90% coverage floor.** A single global coverage number is a weak proxy:
it is satisfiable by testing the easy paths. The gates here are behavioural (a documented attack
must be refused) rather than a coverage percentage. Reasonable people differ; this is a judgement,
not a correction.

**Not taken — the service-mesh structure.** Ten independently deployed services with per-service
pipelines is the right shape for that project and far more machinery than one golden path needs.

---

## Summary of what actually crossed over

| Pattern | Source | Where it lives here |
|---|---|---|
| Five security domains for reporting | security-workshop | `platform/00-discovery/rules/` |
| Insecure baseline → prove the refusal | security-workshop | `platform/11-serverless/tests/security/` |
| One Jest config per test layer | serverless-test-samples | `platform/11-serverless/` |
| Typed, checked-in event fixtures | serverless-test-samples | `platform/11-serverless/tests/fixtures/` |
| Test in the cloud, for the top layers only | serverless-test-samples | `tests/e2e/`, `tests/security/` |
| BOLA/IDOR asserted as 403 | serverless-samples (OWASP demo) | `tests/security/` case 3 |
| Response projection by caller role | serverless-samples (OWASP demo) | `platform/11-serverless/src/` |
| Contract-scoped integration tests | ecommerce-platform | `tests/integration/` |
| Unit-test the unreachable defence branch | ecommerce-platform | `tests/unit/` |
| Structural rules as synth-time errors | ecommerce-platform | `platform/lib/cdk-security/` |

No file in this repository is a copy of, or a derivative work of, any file in those four
repositories.
