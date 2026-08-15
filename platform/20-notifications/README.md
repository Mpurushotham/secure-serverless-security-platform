# `20-notifications` — Slack alerting

One redaction layer, two transports.

```
Alertmanager ─┐
              ├─→ notifier/ (allowlist → scrub → Block Kit) ─→ Slack
SNS → Lambda ─┘
```

## Sending to Slack is publishing

A Slack workspace has different membership, different retention and different
export controls from the AWS account a finding describes. A message posted there
is a copy of that information living somewhere nobody modelled.

So the rule is: **an alert carries a pointer, never a payload.** Finding id,
severity, a console deep link, a runbook path — enough for a responder to go and
look under the access controls that already exist. Not the bucket name, not the
ARN, not the query, never a row.

## Why Alertmanager's own Slack integration is unused

`slack_configs` would post annotation text directly, and an annotation can carry
a bucket name or an ARN. Routing both paths through `notifier/` means one
renderer and one redactor. Two renderers means the second one leaks — it is
always the second one.

## Allowlist, not denylist

`redact.Alert` is a dataclass with named fields. There is no code path that
takes an arbitrary dict and formats it, so a payload carrying extra annotations
cannot smuggle them through. A denylist of patterns to strip fails the first
time somebody adds a field nobody thought to strip, and it fails silently.

The pattern scrubber underneath is belt and braces for anything embedded inline
in a summary.

## Security of the integration itself

Any endpoint Slack calls is a public HTTPS endpoint, and an unverified one will
be found and driven by someone other than Slack.

- **Constant-time signature comparison.** A naive `==` leaks how many leading
  bytes matched, which is enough to forge one a byte at a time.
- **A five-minute replay window.** Without it a valid signature stays valid
  forever, and every interactive action becomes repeatable by whoever captured
  the request.

## What you need to do

1. Create the app from `slack-app/manifest.yml`, replacing both `REPLACE-ME`
   URLs.
2. Install it to your workspace and invite the bot to `#security-alerts` and
   `#security-incidents`.
3. Supply `SLACK_BOT_TOKEN` and `SLACK_SIGNING_SECRET` at run time — via a
   gitignored `.env` locally, or Secrets Manager for the Lambda.

Nothing works until step 3, and nothing here has your credentials.

## Not built

The interactive handler (Acknowledge / Declare SEV / Suppress) and the SNS
Lambda are designed but not implemented. The redaction layer, Block Kit
rendering and signature verification — the parts with security properties worth
testing — are, with 25 tests.
