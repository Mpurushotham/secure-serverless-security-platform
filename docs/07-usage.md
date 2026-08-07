# How to use this repository

Everything here runs without an AWS account. That is deliberate: a security
demonstration you cannot reproduce is an assertion.

---

## 1. Prerequisites

| Tool | Why | Install |
|---|---|---|
| Docker | Real PostgreSQL 17 to prove the database controls against | [docs.docker.com](https://docs.docker.com/get-docker/) |
| [uv](https://github.com/astral-sh/uv) | Python env and dependency resolution | `curl -LsSf https://astral.sh/uv/install.sh \| sh` |
| Terraform ≥ 1.5 | `terraform validate` on the modules | `brew install terraform` |
| Node ≥ 20 | CDK synth and its tests | `brew install node` |

No AWS credentials. No cloud spend.

---

## 2. Run everything

```bash
git clone https://github.com/Mpurushotham/secure-serverless-security-platform
cd secure-serverless-security-platform

make setup      # uv venv + dependencies
make db-up      # Postgres 17 + schema + roles + masked views
make test       # 134 tests
make mcp-demo   # live stdio MCP session against the database
make evidence   # regenerate every artifact in evidence/
make validate   # terraform + checkov + CDK synth + cdk-nag
make db-down
```

`make` with no target lists everything.

### What each target proves

| Target | Proves |
|---|---|
| `test` | Protocol conformance, 37 refused SQL attacks, PII leak assertions, AWS posture tools against moto |
| `mcp-demo` | An agent can read masked pharmacy data and is refused four different ways |
| `evidence` | Every claim in the README regenerates from source |
| `validate` | All IaC is valid and policy-compliant, statically |
| `scan` | SAST, dependency audit, secret scanning |

---

## 3. Wire the MCP servers into an agent

The servers speak MCP over stdio, so any MCP client can use them. For Claude
Code, create `.mcp.json` in your project root:

```json
{
  "mcpServers": {
    "pharmacy-readonly": {
      "command": "/absolute/path/to/repo/.venv/bin/python",
      "args": ["-m", "rds_readonly_mcp.server"],
      "cwd": "/absolute/path/to/repo/mcp-servers",
      "env": {
        "MCP_DB_DSN": "postgresql://mcp_readonly@aurora-reader.internal:5432/pharmadb",
        "MCP_PRINCIPAL": "claude-code-local",
        "MCP_AUDIT_PATH": "/var/log/mcp/pharmacy-audit.jsonl"
      }
    },
    "aws-posture": {
      "command": "/absolute/path/to/repo/.venv/bin/python",
      "args": ["-m", "aws_posture_mcp.server"],
      "cwd": "/absolute/path/to/repo/mcp-servers",
      "env": { "AWS_REGION": "eu-north-1", "AWS_PROFILE": "security-readonly" }
    }
  }
}
```

### Configuration that is load-bearing

| Variable | Notes |
|---|---|
| `MCP_DB_DSN` | Point at the **reader** endpoint. Analytics traffic on the writer competes with transactions it has no business affecting. In AWS, omit the password entirely — the role uses IAM auth. |
| `MCP_AUDIT_PATH` | Ship this somewhere the agent's own identity cannot write to. An audit log the subject can edit is not an audit log. |
| `MCP_PRINCIPAL` | Appears in every audit record. Make it identify the *agent instance*, not the human. |
| `MCP_ALLOW_UNMASK` | Leave unset. Setting it to `true` is a deployment decision requiring a documented reason. |

### Things that will not work, by design

- Pointing `MCP_DB_DSN` at a superuser account — the role validation refuses it
- Asking the agent to run an `UPDATE` — refused at the AST layer before the database is contacted
- Asking for `SELECT * FROM customers` — the base table is not in the allowlist, and the role has no grant on it either
- Setting `MCP_ALLOW_UNMASK` as a tool argument — it is not a tool argument

---

## 4. Tech stack, and why each piece

| Layer | Choice | Why this and not the alternative |
|---|---|---|
| Protocol | Hand-written JSON-RPC 2.0 over stdio, **zero dependencies** | Demonstrates the wire format and its trust boundaries are understood. A repo arguing for supply-chain discipline should not pull 40 transitive packages to parse JSON. **Production should use the official MCP SDK** — stated in the README rather than left for a reviewer to notice. |
| SQL safety | `sqlglot` AST parsing | The single most important control. Regex blocklists lose to comment injection, CTE writes, and stacked statements — and fail *open*. `evidence/guardrail-bypass-report.md` shows 14 of 37 attacks passing a representative regex filter. |
| DB driver | `psycopg` 3 | Server-side parameter binding: injection prevented at the driver, not by string hygiene. |
| Database | PostgreSQL 17 in Docker | Guardrails must be proven against a real engine. A mock cannot prove `mcp_readonly` is denied `INSERT` — the engine has to say no. |
| AWS mocking | `moto` 5 | Proves the posture server with no credentials, keeping the repo reproducible. |
| IaC | Terraform 1.5+ and AWS CDK 2 | The JD names both. Terraform for data-plane controls, CDK for the serverless app and its enforcing Aspects. |
| Policy | `checkov`, `tflint`, `cdk-nag` | Three different rule sets; none subsumes the others. |
| SAST/SCA | `semgrep`, `bandit`, `pip-audit`, `gitleaks` | Four distinct failure classes. |
| Supply chain | CycloneDX SBOM | Answers "secure DevSecOps pipelines" concretely. |

---

## 5. The GitHub Actions pipeline, step by step

`.github/workflows/security-pipeline.yml`. Four parallel jobs; every one gates
this repository's own code rather than serving as a template.

### Job 1 — `guardrails` (the load-bearing one)

1. **Start PostgreSQL 17** as a service container with a health check.
2. **Apply the security baseline** — the same three SQL files a developer runs locally, so CI and local cannot drift.
3. **Run the test suite** — protocol conformance, the 37-payload bypass suite, and the PII leak assertions. *A passing bypass fails the build.* That is the contract.
4. **Drive a live MCP session** — a real subprocess over stdio, not a mock.
5. **Regenerate the bypass report** and fail if a control weakened.
6. **Assert evidence is current** — if `evidence/guardrail-bypass-report.md` differs from what the code produces now, the build fails. Evidence that drifts from the code asserts a property the code no longer has, which is worse than no evidence.

### Job 2 — `sast`

`bandit` · `pip-audit` · `ruff` (with security rules) · `semgrep` · `gitleaks` with
full history (`fetch-depth: 0` — a shallow clone misses secrets in older commits,
which is where they usually are).

### Job 3 — `iac`

`terraform fmt -check` · `validate` per module · `checkov` with SARIF upload to
code scanning · then CDK: `npm ci`, strict `tsc`, 11 security invariant tests,
and `cdk synth`. **Synth is a security gate here, not a build step** — the
Aspects in `infra/cdk/lib/aspects/` raise *errors* on wildcard IAM, missing log
retention, and unattached Lambdas.

### Job 4 — `supply-chain`

CycloneDX SBOM via `anchore/sbom-action`.

### Adding the severity gate to your own pipeline

```yaml
- name: Severity budget
  run: |
    .venv/bin/python scripts/severity_gate.py results/*.sarif \
      --max-critical 0 --max-high 0 --max-medium 10

- name: Vulnerability SLA
  run: .venv/bin/python scripts/vuln_sla.py results/*.sarif --update-ledger
```

`--update-ledger` should run on `main` only. On pull requests, omit it: PR runs
should *evaluate* against the ledger, not write to it, or every new branch resets
the clock on every finding.

---

## 6. Deploying the infrastructure (not done in this repo)

Nothing here has been applied to a live account. If you want to:

```bash
cd infra/terraform/modules/aurora-secure
terraform init
terraform plan -var-file=your.tfvars   # review every line
```

**Read this before you apply:**

- **Cost.** Aurora with two `db.r6g.large` instances is roughly USD 400–500/month before storage and I/O. The Bedrock module is near-zero at rest; invocation logging costs by volume.
- **Order.** `aurora-secure` first (it outputs `cluster_resource_id`), then `agent-data-access`, which consumes it. `bedrock-guardrails` is independent. `detections` needs log group names from the first two.
- **`deletion_protection` defaults on.** Destroying requires disabling it first — deliberate friction on a regulated dataset.
- **Apply the SQL separately.** `sql/01-roles.sql` and `02-masked-views.sql` are not run by Terraform: schema changes to a regulated database belong in a migration tool with review, not in an infrastructure apply.

---

## 7. Reading order

If you have ten minutes and want to judge this repository, in order:

1. `evidence/db-privilege-proof.txt` — PostgreSQL itself refusing 19 attempts
2. `evidence/guardrail-bypass-report.md` — 37 attacks, and what a regex would have let through
3. `mcp-servers/rds_readonly_mcp/sql/01-roles.sql` — the controls that actually hold
4. `docs/01-threat-model.md` — the attack tree, including the residual risk
5. `readiness/00-jd-coverage-matrix.md` — the honest gaps
