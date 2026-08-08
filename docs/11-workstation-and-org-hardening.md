# Workstation, endpoint, and GitHub organisation hardening

The controls that sit outside AWS: developer machines, the identity fabric, and
the GitHub organisation itself.

**Why this belongs in a cloud-security repository.** The strongest AWS
authorisation model in the world is bypassed by a developer laptop with a
compromised extension and a valid SSO session. The workstation is where source
code, cloud credentials, and AI assistants all meet — it is the most privileged
endpoint most engineering organisations have, and typically the least governed.

---

## 1. GitHub Enterprise / organisation

### Organisation settings that carry the weight

| Setting | Value | Why |
|---|---|---|
| **SAML/OIDC SSO + SCIM** | Enforced | Without SCIM, deprovisioning is manual. Ex-employees keep access until someone remembers. |
| **2FA required** | Org-wide, hardware keys for admins | Phishing-resistant factors specifically; TOTP is better than nothing and not much more |
| **Personal access tokens** | Restricted; fine-grained only, org approval required | A classic PAT is a bearer credential with the user's full access and often no expiry |
| **GitHub Apps** | Approval required; audited quarterly | An installed App with write access bypasses branch protection entirely |
| **Default repo permission** | `none` or `read` | `write` by default means every new hire can push to everything |
| **Repo creation** | Restricted to owners, or org-wide rulesets applied automatically | Otherwise a repo created tomorrow has no protection |
| **Repo deletion / transfer** | Owners only | Transfer moves code out of the org and out of scanning |
| **Forking of private repos** | Disabled | A fork escapes org rulesets and scanning |
| **Actions** | Allowlisted actions only; **no third-party actions by SHA-less tag** | An action pinned to `@v3` is a moving target the author controls |
| **Actions default token** | Read-only | Write-by-default lets a compromised workflow push to `main` |
| **Secret scanning + push protection** | Enabled org-wide | Push protection blocks the commit rather than reporting it after |
| **Dependabot** | Alerts + security updates | Merge by a human; a supply-chain compromise arrives as a legitimate-looking bump |
| **Audit log streaming** | To S3 / SIEM | The org audit log is 180 days in the UI; an investigation often needs older |
| **IP allow list** | If the workforce shape allows | High friction; only where genuinely warranted |

### The three most commonly missed

1. **`GITHUB_TOKEN` defaults to write.** A compromised third-party action in any workflow can then push to the default branch. Set read-only at org level and grant per-job.
2. **Actions pinned by tag, not SHA.** `uses: some/action@v3` resolves to whatever the author last tagged. Pin to a full commit SHA for anything outside your org.
3. **GitHub Apps bypass branch protection.** An App with `contents: write` is not subject to rulesets. Audit installations as carefully as you audit human admins.

### Repository level

See `.github/rulesets/` — protection as a checked-in artifact rather than a
settings page somebody clicked once. UI-configured protection has no history, no
review, and no diff; "who removed the required review, and when?" is
unanswerable. Apply at **organisation** level so new repos inherit rather than
needing onboarding.

---

## 2. Identity and MDM

MDM is the control plane for everything below it. Without device management,
"only managed devices may access production" is an aspiration.

| Control | Purpose |
|---|---|
| **Device enrolment mandatory** (Jamf / Intune / Kandji) | Nothing else on this list is enforceable without it |
| **Conditional access: managed + compliant device required** | Ties the AWS/GitHub session to a device you control, not just to a password and a token |
| **Full-disk encryption**, key escrowed | A lost laptop is a lost credential store otherwise |
| **Screen lock ≤ 5 min**, password policy | Unglamorous; still how most in-office compromise happens |
| **OS patch SLA enforced by policy** | Non-compliant device loses access rather than generating a ticket nobody actions |
| **Application allowlisting** where practical | Tightest on machines with production access |
| **Local admin removed by default**, JIT elevation | The single highest-value endpoint control, and the least popular |
| **Remote wipe** | Departure and loss |
| **USB mass storage disabled** on regulated-access devices | Exfiltration path with no logging |
| **Browser policy** — extension allowlist, sync disabled | A browser extension reads every page including your AWS console |

### Endpoint detection

Named honestly: **EDR is the thinnest area of my direct experience**
(`readiness/00-jd-coverage-matrix.md` rates it a `Gap`).

What I would hold to regardless of vendor:

- **Coverage before features.** An EDR on 70% of the fleet is worth less than a basic agent on 100%. The 30% is where the incident will be.
- **Tuning is the work, not deployment.** Budget ongoing time, not a project end date.
- **Developer machines need a carve-out process, not exemptions.** Compilers and debuggers generate behaviour that looks malicious. Without a documented process, engineers get the agent removed informally and coverage rots.
- **Telemetry to the same place as cloud findings.** An endpoint alert and a GuardDuty finding about the same person, in two consoles, will not be correlated during an incident.
- **Selection follows the estate.** How many machines, what OS mix, what management tooling exists, is there a warehouse/OT estate with different constraints. Arriving with a vendor preference before knowing that would be bluffing.

---

## 3. AI assistant and IDE governance

The newest and least-governed surface. Full policy in
`docs/04-ai-secure-coding-policy.md`; the workstation-side controls:

| Control | Purpose |
|---|---|
| Enterprise agreement with the model provider | Determines training-data use and retention. A consumer tier is a different legal posture. |
| Assistant allowlist | Approved tools only; the sanctioned path must be *easier* than the unsanctioned one or policy loses |
| `.vscode/settings.json` excludes on secret-shaped files | Keeps them out of the index the assistant reads |
| MCP server approval process | An unreviewed MCP server is an unreviewed authorisation boundary |
| Extension allowlist | An extension reads every open file with full user privileges |
| Workspace trust on | Opening an untrusted repo must not execute its tasks |

**The realistic assessment:** developers will paste things into consumer chatbots
regardless of policy. Making the sanctioned route genuinely faster addresses this
better than a prohibition does. Detection (DLP on egress, browser policy) is the
compensating control, not the primary one.

---

## 4. Automation — what to automate, and what not to

| Automate | Why |
|---|---|
| Evidence generation | `make evidence`; a quarterly manual scramble is where compliance programmes die |
| Access reviews | Generate the report; a human still decides |
| Secret rotation | Where the service supports it and rotation does not break a deterministic mask |
| Non-compliant resource **quarantine** | Reversible: isolate a security group, disable a key |
| Dependency update PRs | Raised automatically, merged by a human |
| Detection routing | EventBridge; a finding with no route is a finding nobody sees |

| Do **not** automate | Why |
|---|---|
| Deleting resources on a finding | Destroys evidence mid-incident and, if the detection is wrong, causes the outage |
| Revoking human access on a single signal | One false positive locks someone out at 3am and the automation gets switched off |
| Breach notification | A legal determination, never a trigger |
| Merging security fixes | A malicious dependency arrives as a legitimate-looking bump |

**The rule:** automate the *reversible* and the *repetitive*. Keep a human on
anything that destroys state or has legal consequence.

---

## 5. Honest scope note

Sections 1 and 3 are implemented in this repository — rulesets, CODEOWNERS,
pre-commit, IDE settings, and the OIDC module are real files you can apply.

**Sections 2 and 4 are design, not implementation.** There is no MDM estate here
to configure and no endpoint fleet to protect; presenting a Jamf profile written
against an imaginary fleet as evidence would be exactly the assertion-as-evidence
failure this repository argues against. They are written as what I would do, and
labelled as such.
