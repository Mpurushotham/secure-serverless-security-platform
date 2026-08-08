# Repository rulesets as code

Branch protection expressed as a checked-in artifact rather than a settings page
somebody clicked once.

**Why this matters more than it looks.** Protection configured in the UI has no
history, no review, and no diff. "Who removed the required review, and when?"
is unanswerable. As a ruleset JSON it goes through the same PR process as the
code it protects.

## Two variants, and why

| File | For | Approvals |
|---|---|---|
| `main-branch-protection.json` | A team | 1 required, code-owner review, last-push approval |
| `main-branch-protection-solo.json` | A single maintainer | **0** — see below |

**The team ruleset cannot be applied to a single-maintainer repository.** GitHub
does not permit approving your own pull request, so
`required_approving_review_count: 1` with `bypass_actors: []` is a deadlock: no
merge is ever possible, by anyone, including the owner.

That is a real defect in the first version of this file, caught by trying to
apply it rather than by reading it. It is also the general lesson — a control
that has only been written has not been tested, and "it looks right" is not the
same as "it works here".

The solo variant keeps everything that still functions with one person:
required status checks (the actual quality gate), no force-push, no deletion,
required thread resolution, and **still no bypass actors** — so even the owner
must go through a PR and green CI. What it gives up is peer review, which one
person cannot provide regardless of configuration.

Apply with:

```bash
# Team repository
gh api -X POST /repos/{owner}/{repo}/rulesets \
  --input .github/rulesets/main-branch-protection.json

# Single-maintainer repository
gh api -X POST /repos/{owner}/{repo}/rulesets \
  --input .github/rulesets/main-branch-protection-solo.json
```

Or at organisation level (`/orgs/{org}/rulesets`), which is strictly better —
a repo created tomorrow inherits it rather than needing onboarding.

## The settings that carry the weight

| Rule | Why |
|---|---|
| `bypass_actors: []` | **The most important line in the file.** A protection with admin bypass protects against accident, not against intent — and the accounts most likely to be compromised are the ones with bypass. |
| `require_last_push_approval` | Closes the approve-then-push window: without it an approved PR can be amended after review and merged. |
| `dismiss_stale_reviews_on_push` | An approval applies to the diff that was reviewed, not to the branch name. |
| `required_signatures` | Commit authorship is otherwise a self-asserted string. |
| `strict_required_status_checks_policy` | Requires the branch to be current, so checks pass against the code that will actually be on `main`. |
| `non_fast_forward` | Blocks force-push, which is how history — including evidence of a mistake — gets rewritten. |
| `require_code_owner_review` | Pairs with `CODEOWNERS` so security-relevant paths need a security reviewer specifically. |

## What rulesets do NOT give you

- They do not stop a compromised **GitHub App or PAT** with write access. Audit installed apps separately.
- They do not protect **tags** unless you add a `tag`-target ruleset.
- They do not apply to forks.
- **They must actually be applied.** This repository carried the ruleset JSON for several commits while `GET /rulesets` returned an empty list. A protection design in version control that was never applied protects nothing — check the API, not the file.
- A required status check that never runs blocks nothing — verify the context names match the job names exactly, because a typo silently disables the gate rather than failing loudly.
