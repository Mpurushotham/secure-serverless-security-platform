# Playbook 03 — PII exfiltration via a compromised AI agent

**Default severity: SEV1** until Art. 9 exposure is *excluded*, not until it is confirmed. Starting at SEV2 and upgrading wastes the part of the 72 hours you cannot get back.

---

## What this looks like

Not a break-in. The agent is authenticated, authorised, and doing something it is permitted to do — at a scale or in a pattern that is wrong. Typical triggers:

- **D-001** guardrail refusal burst — the agent is probing the boundary
- **D-003** bulk read volume — many individually compliant queries adding up to an extract
- **D-006** Bedrock guardrail intervention — regulated data reached the model context through a path authorisation did not close
- A developer reporting that an assistant "did something odd" after reading a ticket, a log, or a webpage

That last one is the most common real-world entry point and the easiest to dismiss.

## The mental model

**The agent is not the attacker. The agent is the weapon.** Someone or something placed instructions where the agent would read them — a ticket description, a log line, a webpage, a database row, a code comment. The agent complied because complying with text is its function.

Two consequences that change how you respond:

1. **Do not start by "fixing the agent."** It behaved as designed. Find the injected content, or you will re-enable the agent into the same trap.
2. **Blast radius is bounded by authorisation, and you already know what it is.** You do not need to discover what the agent *could* reach — the controls define it. This is the one advantage you have, and it converts an open-ended investigation into a bounded one.

---

## Step 1 — Declare and page (0–5 min)

Declare SEV1. Name an Incident Commander, Technical Lead, Communications, Scribe.

**Page the DPO now.** Not after the investigation. If Art. 9 data is in scope, the Art. 33 clock is running and the DPO needs the same 72 hours you do.

Open the timeline. Record the trigger and the time you became aware, verbatim. That timestamp will be quoted back to you.

## Step 2 — Contain (5–20 min)

Containment is cheap here because the agent is a service identity, not a person. Nobody is locked out of their job.

```bash
# 1. Stop new sessions: set reserved concurrency to zero. Faster and more
#    reversible than deleting the function, and preserves it for forensics.
aws lambda put-function-concurrency \
  --function-name mcp-agent --reserved-concurrent-executions 0

# 2. Revoke in-flight sessions. IAM role sessions cannot be individually
#    revoked, so attach a deny-all policy with a token-issue-time condition:
#    it invalidates existing sessions while leaving the role intact for
#    investigation. Deleting the role would destroy evidence.
aws iam put-role-policy --role-name <agent-role> \
  --policy-name EMERGENCY-REVOKE-$(date +%s) \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny",
    "Action":"*","Resource":"*","Condition":{"DateLessThan":
    {"aws:TokenIssueTime":"'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'"}}}]}'

# 3. Terminate active database sessions for the agent role.
#    pg_terminate_backend, not just pg_cancel_backend: cancel stops the current
#    query and leaves the connection able to issue another one.
psql -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity
         WHERE usename = 'mcp_readonly';"
```

**Do not** delete the Lambda, the role, or the log groups. Do not rotate the masking salt yet — see Step 5, where the decision depends on what you find.

**If the agent had network egress beyond the MCP server, escalate immediately.** The bounded-blast-radius reasoning below assumes the isolated-subnet design held. Verify it rather than assuming it: VPC flow logs, one query, thirty seconds.

## Step 3 — Scope, from the audit log (20–60 min)

This is where the design pays off. The audit log answers the regulator's question directly.

```bash
# Every tool call in the window, with outcome and row counts.
aws logs filter-log-events \
  --log-group-name /aws/lambda/mcp-agent \
  --start-time $(($(date -d '24 hours ago' +%s) * 1000)) \
  --filter-pattern '{ $.outcome = "allowed" }' \
  | jq -r '.events[].message' | jq -s '
      { calls: length,
        rows: (map(.row_count // 0) | add),
        bytes: (map(.bytes_returned // 0) | add),
        by_tool: (group_by(.tool) | map({(.[0].tool): length}) | add),
        sessions: (map(.session_id) | unique) }'
```

Answer these five, in writing:

| Question | Where it comes from |
|---|---|
| How many rows were returned, in total? | `row_count` sum |
| Which relations? | `tool` + fingerprint correlation |
| Were the rows **masked**? | Which relation — `v_*_masked` or a base table |
| Did any **non-consented** Art. 9 row appear? | RLS makes this answerable: if the query hit `v_prescriptions_masked`, no |
| Did the agent authenticate from an unexpected place? | D-005, VPC flow logs |

### Reaching the Art. 33 determination

**If reads were confined to masked views:** you have a pseudonymisation event, not necessarily a personal-data breach. Recital 26 and Art. 4(5) matter here — pseudonymised data is still personal data, but the exposure is materially different if the re-identification key never left Secrets Manager. **The DPO decides, on the evidence you provide.** Your job is to state plainly whether the salt was reachable, and the answer is in the IAM policy: the agent role has an explicit deny on that secret.

**If any base table was read, or the salt was reachable:** treat as a notifiable personal data breach and proceed on that basis. Do not spend the clock trying to argue otherwise.

## Step 4 — Find the injection (parallel with Step 3)

Do not skip this to get to remediation faster. Without it you will re-enable the agent into the same trap.

Reconstruct what the agent read before it changed behaviour. Working backwards from the first anomalous tool call:

- Ticket or issue text in the session context
- Log lines the agent was asked to analyse
- Web content fetched during the session
- **Database row contents** — the subtle one. A `notes` or `description` field an attacker can write to is an injection channel that reaches the agent through an entirely legitimate read.
- Repository content: comments, READMEs, `.claude/` files, MCP server descriptions

The tell is usually a discontinuity: the agent's tool calls change character mid-session without a corresponding user instruction.

## Step 5 — Eradicate and recover

1. **Remove or neutralise the injected content.** If it came from a user-writable field, that field is now an injection surface for every future agent run — fix the surface, not just the row.
2. **Re-verify the controls actually held.** Run `make evidence` against the affected environment. The privilege proof and bypass report are exactly the artifacts an auditor will ask for, and regenerating them is fast.
3. **Rotate the masking salt only if it was reachable.** This is a real decision, not a reflex: rotation changes every masked value and breaks joins against previously exported analytics. Rotate if the salt was exposed; do not rotate reflexively because it feels thorough. See the suppression register for why automatic rotation is deliberately off.
4. **Restore concurrency** only after the injection source is removed and the control verification passes.
5. **Remove the emergency deny policy.** Left in place, it will cause a confusing outage in three weeks that nobody connects to this incident.

## Step 6 — After

Within five working days:

- **Timeline**, from the scribe's notes.
- **What the controls did.** Be specific: which layer caught what, and which layer would have caught it had the first failed. If a control did *not* fire when it should have, that is the most valuable finding in the review.
- **Detection tuning.** Did D-001/D-003 fire, and how quickly? If the incident was reported by a human before a detection fired, the detection needs work.
- **Was the blast radius what the threat model predicted?** If the agent reached something `docs/01-threat-model.md` says it cannot, the threat model is wrong and takes priority over everything else in this list.

---

## Pre-incident checklist

Verify these are true *now*, not during an incident:

- [ ] The agent's audit log ships somewhere the agent role cannot write to
- [ ] VPC flow logs are on and retained long enough to answer "did it call out?"
- [ ] The emergency revoke command has been run once, in a test environment, by someone who is not you
- [ ] The DPO knows what an "AI agent data access incident" means before you call them at 03:00
- [ ] `make evidence` runs green in an environment that resembles production

The third item is the one most often skipped and most often regretted. A containment command being run for the first time during an incident is how a SEV1 becomes a SEV1 plus an outage.
