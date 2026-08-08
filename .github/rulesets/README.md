# Repository rulesets as code

Branch protection expressed as a checked-in artifact rather than a settings page
somebody clicked once.

**Why this matters more than it looks.** Protection configured in the UI has no
history, no review, and no diff. "Who removed the required review, and when?"
is unanswerable. As a ruleset JSON it goes through the same PR process as the
code it protects.

Apply with:

```bash
gh api -X POST /repos/{owner}/{repo}/rulesets \
  --input .github/rulesets/main-branch-protection.json
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
- A required status check that never runs blocks nothing — verify the context names match the job names exactly, because a typo silently disables the gate rather than failing loudly.
