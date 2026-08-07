# Playbook 01 — Leaked AWS credential

**Default severity: SEV2**, upgraded to SEV1 the moment there is evidence of use against data.

## Trigger

GitHub secret scanning alert · gitleaks in CI · GuardDuty `UnauthorizedAccess:IAMUser/*` · a developer saying "I think I committed something".

That last one deserves the same response as the automated ones. People who self-report get punished by slow, painful responses, and then stop self-reporting.

## The order that matters

Most teams do this in the wrong order and lose the ability to investigate:

1. **Revoke** — before you understand the scope
2. **Then** scope
3. **Then** clean history

Deleting the commit first feels like the fix. It is not: the credential is already scraped — public GitHub is scanned by attackers within seconds — and you have destroyed the evidence of what was exposed and when.

## Step 1 — Revoke (0–10 min)

```bash
# Long-lived access key: deactivate, do not delete. Deletion loses the
# CloudTrail correlation between key ID and activity.
aws iam update-access-key --access-key-id AKIA... --status Inactive

# Role session: attach a token-issue-time deny (see playbook 03, step 2).

# Then rotate whatever the credential protected.
```

**A private key or certificate is compromised the moment it is public.** Deleting the file is not remediation — rotate at the issuer first, then purge history. This applies to anything in a repo, including old ones nobody looks at.

## Step 2 — Scope (10–60 min)

```bash
# What did this credential actually do?
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=AKIA... \
  --start-time "$(date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ)" \
  | jq -r '.Events[] | "\(.EventTime) \(.EventName) \(.Username)"' | sort | uniq -c
```

Questions to answer in writing:

- **When was it exposed** (commit timestamp), and when was it revoked? That interval is your exposure window.
- Any API calls from an IP or region you do not recognise?
- Any `Get*`/`List*` reconnaissance immediately before something else? That pattern — enumerate, then act — is the signature of a human rather than a misconfigured script.
- Did it touch anything holding personal data? If yes, **SEV1 and page the DPO**.

**Absence of evidence is not evidence of absence.** CloudTrail has a delivery delay, and data-plane events (S3 object reads, database queries) are only there if data events were enabled. Say "we saw no use in the control plane" — not "it was not used".

## Step 3 — Clean history

Only now. Use `git filter-repo` (not `filter-branch`), force-push, and tell everyone to re-clone. Forks and existing clones retain the secret regardless — which is why rotation, not deletion, is the actual control.

## Step 4 — After

The interesting question is never "who committed it". It is **why the credential existed at all**. A long-lived AWS access key in 2026 is usually a workload that should be using a role, or a human who should be using SSO. Rotating it and moving on guarantees a repeat.

- [ ] Could this workload use an IAM role instead? (For databases: IAM auth removes the credential entirely — see `modules/aurora-secure`.)
- [ ] Is pre-commit secret scanning on for every repo, not just the active ones?
- [ ] How long was the exposure window, and what would have shortened it?
