# DevSecOps: the control at every stage

Every gate between a developer's keystroke and production. For each: the tool,
what it catches, **what it misses**, and where it runs.

The "what it misses" column is the point. A control catalogue that only lists
strengths produces a false sense of coverage, and the gaps are where incidents
come from.

---

## The pipeline, left to right

```
IDE ──► pre-commit ──► PR (GitHub Actions) ──► merge ──► deploy (OIDC) ──► runtime
 │          │                  │                            │               │
 │          │                  │                            │               └─ GuardDuty, Inspector, Config
 │          │                  │                            └─ no static creds; short-lived token
 │          │                  └─ 4 jobs, ~12 tools, evidence freshness check
 │          └─ fast, high-signal only: secrets, format, lint
 └─ workspace trust, telemetry off, secret files excluded from index
```

**Economics of shifting left.** A secret caught in the IDE costs seconds. In
pre-commit, seconds. In CI, a rotation. After push to a public repo, an incident
with a disclosure timeline — the credential is scraped within seconds, and
deleting the commit does not un-scrape it. Every stage left is roughly an order
of magnitude cheaper.

---

## Stage 1 — IDE (`.vscode/`)

| Control | Purpose | Misses |
|---|---|---|
| `files.exclude` / `search.exclude` on `*.pem`, `.env` | Keeps secret-shaped files out of the editor index — which is what most AI assistants read for context | A secret pasted inline into source |
| Workspace trust enabled | Opening an untrusted repo must not auto-run tasks or extensions | Nothing, if the developer clicks "trust" reflexively |
| `task.allowAutomaticTasks: off` | A malicious repo's `tasks.json` is a code-execution primitive | Manually run tasks |
| Telemetry off | Editor telemetry can carry file paths and, in some extensions, snippets | Extension-specific telemetry |
| `git.allowNoVerifyCommit: false` | Stops the reflexive `--no-verify` that bypasses every pre-commit hook | A developer editing the setting |
| `extensions.json` recommendations | An extension runs with full developer privileges and reads every open file — the least-governed supply chain most orgs have | Extensions installed anyway |

**Checked in deliberately.** An IDE control each developer must configure
themselves is a control most developers will not have.

## Stage 2 — pre-commit (`.pre-commit-config.yaml`)

Deliberately **not** the same tool set as CI. Hooks that duplicate the pipeline
get bypassed because they are slow and redundant. Fast, high-signal only.

| Hook | Purpose | Misses |
|---|---|---|
| `detect-private-key` | The single highest-value hook here | Keys in unusual encodings |
| `detect-aws-credentials` | AKIA-shaped strings | Session tokens, non-AWS credentials |
| `gitleaks` | Broad secret patterns | Novel formats; needs a baseline or the first run floods and everyone learns `--no-verify` |
| `check-added-large-files` | A 100MB blob is usually a leaked dump | Small data files |
| `ruff`, `bandit` | Lint and Python SAST, fast subset | Anything needing cross-file analysis |
| `terraform_fmt/validate/checkov` | Wildcard IAM is cheaper to fix before review than after | Runtime misconfiguration |
| `conventional-pre-commit` | Machine-readable history for release notes and audit | Nothing security-relevant; it is hygiene |

## Stage 3 — pull request (`.github/workflows/security-pipeline.yml`)

Four parallel jobs. **These gate this repository's own code** — a passing bypass
attempt fails the build.

### Job: `guardrails`

| Step | Tool | Purpose | Misses |
|---|---|---|---|
| Postgres service + apply baseline | `psql` | CI and local use the same three SQL files, so they cannot drift | — |
| Conformance + bypass + leak suites | `pytest` | 37 attack payloads must stay refused; PII must not reach the transcript | Attacks nobody thought of — which is why the suite grows after every finding |
| Live MCP session | `scripts/mcp_demo.py` | Real subprocess over stdio, not a mock | — |
| Bypass report regeneration | `scripts/bypass_report.py` | Fails if a control weakened | — |
| **Evidence freshness** | `git diff` | Evidence that drifts from code asserts a property the code no longer has | Evidence nobody reads |

### Job: `sast`

| Tool | Purpose | Misses |
|---|---|---|
| `bandit` | Python security patterns | Logic flaws; framework-specific issues |
| `semgrep` | Cross-language rules, custom patterns | Anything requiring data-flow across services |
| `ruff` (security rules) | Fast lint incl. `S` ruleset | Deep analysis |
| `pip-audit` | Known-vulnerable dependencies | Zero-days; a malicious package with no advisory yet — the real SCA limit |
| `gitleaks` **with `fetch-depth: 0`** | Secrets across full history | Secrets in a fork's history |

**The `fetch-depth: 0` matters.** A shallow clone scans only the latest commit,
and secrets are usually in *older* ones.

### Job: `iac`

| Tool | Purpose | Misses |
|---|---|---|
| `terraform fmt -check` | Formatting drift; a proxy for un-reviewed edits | — |
| `terraform validate` | Syntax and provider schema | Anything only apparent at plan time against real state |
| `checkov` | ~1,000 policy checks, SARIF to code scanning | Business context — hence 17 justified suppressions |
| `tflint` | Provider-specific correctness | Policy |
| `tsc --noEmit` (strict) | CDK type errors | Logic |
| CDK **Aspects** | Wildcard IAM, missing log retention, unattached Lambdas — as **errors** | Only what the aspects check |
| `cdk-nag` | AWS Solutions rules against synthesised CFN | Same class as checkov |
| `jest` | 11 security invariants on the synthesised template | Deploy-time behaviour |

**`cdk synth` is a security gate here, not a build step.** The Aspects raise
errors, so a regression fails synth rather than producing a warning nobody reads.

### Job: `supply-chain`

| Tool | Purpose | Misses |
|---|---|---|
| `anchore/sbom-action` (CycloneDX) | Inventory for "are we affected by X?" | An SBOM nobody queries |

### Optional gates (`scripts/`)

| Script | Question it answers |
|---|---|
| `severity_gate.py` | Is this bad enough to block the merge **now**? |
| `vuln_sla.py` | Has this been open **too long**? |

Separate on purpose. Conflating them produces a gate that either blocks
everything or ages everything, and teams disable whichever it is.

## Stage 4 — merge protection (`.github/rulesets/`)

| Rule | Purpose |
|---|---|
| `bypass_actors: []` | **The most important line.** Protection with admin bypass guards against accident, not intent — and privileged accounts are the ones most worth compromising |
| `require_last_push_approval` | Closes the approve-then-amend-then-merge window |
| `dismiss_stale_reviews_on_push` | An approval applies to the reviewed diff, not the branch name |
| `required_signatures` | Authorship is otherwise a self-asserted string |
| `require_code_owner_review` + `CODEOWNERS` | Security-relevant paths need a security reviewer specifically |
| `non_fast_forward` | Blocks the force-push that rewrites evidence |

**Verify the required-check context names match the job names exactly.** A typo
silently disables the gate rather than failing loudly — the check simply never
becomes required.

## Stage 5 — deploy (`modules/github-oidc`)

| Control | Purpose |
|---|---|
| OIDC, no static keys | Deletes the most common cloud-breach path rather than managing it |
| `sub` pinned to repo **and** ref | A trust policy scoped to `repo:org/*` lets any workflow in any branch assume the role, including a PR branch |
| Environment subjects | Turns a GitHub required-reviewer gate into an AWS authorisation condition |
| Permission boundary | Caps the pipeline regardless of attached policy |
| Deny production secret reads | A pipeline that can read a secret can print it to a build log |
| `max_session_duration` ≤ 2h | Bounds a leaked token's window |

## Stage 6 — runtime

GuardDuty, Inspector v2, Config, and the eight detections in
`infra/terraform/detections/`. See `docs/09-aws-security-services.md`.

---

## What no gate in this pipeline catches

Stated plainly, because the gaps are the useful part:

- **Business-logic flaws.** No scanner knows that a refund endpoint should not accept negative amounts.
- **A malicious dependency with no advisory yet.** SCA is retrospective by construction.
- **A compromised maintainer account with valid signing.** Rulesets and signatures verify identity, not intent.
- **Design errors.** The inert RLS policy this repository found in itself passed every scanner — it was caught by a *test that exercised the control*, which is a different category of thing entirely.

That last one is the argument for evidence generation over scanning.
