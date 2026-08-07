# Playbook 02 — GuardDuty crypto-mining on Lambda

**Default severity: SEV2.** Upgrade to SEV1 if the compromised function has access to personal data — which, for anything in the agent path, it does.

## Trigger

GuardDuty `CryptoCurrency:Lambda/BitcoinTool.B!DNS` or the EC2 equivalent, routed by detection **D-007**.

## First: is it real?

Crypto-mining findings have a specific false-positive profile worth knowing before you page anyone. All three of these produce the finding without a compromise:

- A dependency that resolves a domain on a threat-intel list for telemetry
- A security tool doing its own threat-intel lookups
- A developer testing blockchain code in a non-production account

**But do not spend more than ten minutes on this question.** If it is real, every minute is compute spend and lateral movement. Contain first, then determine whether it was real — containment of a Lambda is cheap and reversible.

## Step 1 — Contain (0–15 min)

```bash
# Concurrency to zero: stops execution without destroying the function,
# its configuration, or its logs.
aws lambda put-function-concurrency \
  --function-name <fn> --reserved-concurrent-executions 0

# Then revoke the execution role's sessions (token-issue-time deny,
# as in playbook 03).
```

For this architecture, mining on a Lambda implies **arbitrary code execution in a function that may hold database access**. The mining is the noisy symptom; the access is the incident. Treat the execution role as compromised.

## Step 2 — How did code get in?

Three realistic paths, in rough order of likelihood:

1. **Dependency compromise** — a malicious or typosquatted package. Check the SBOM (`make scan` produces one) and diff dependencies against the last known-good deploy.
2. **Deployment pipeline compromise** — someone pushed a modified artifact. Check CloudTrail for `UpdateFunctionCode` and correlate against your CI's own record. A code update with no matching pipeline run is the finding.
3. **Injection into a function that evaluates input** — rarer in Python Lambdas, but check any `eval`, `exec`, `subprocess`, or deserialisation of untrusted data.

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=UpdateFunctionCode \
  --start-time "$(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)"
```

## Step 3 — Scope the access, not just the mining

The mining is the least interesting thing that happened. What mattered is what the role could reach:

- Did the function have database access? Then follow **playbook 03, step 3** — the audit log answers the same question.
- Were there secrets in environment variables? Rotate all of them, on the assumption they were read.
- Did the function have network egress? Flow logs will show what left.

## Step 4 — Recover

1. Rebuild from a known-good commit, not by patching the running function.
2. Rotate every secret the role could read.
3. Re-deploy through the pipeline so the artifact is attested, rather than uploading by hand.
4. Restore concurrency last.

## Step 5 — After

- [ ] Was the malicious dependency in the SBOM? If yes, why did `pip-audit` not flag it? (Often: no advisory existed yet. That is a real limit of SCA, worth stating rather than treating as a process failure.)
- [ ] Did the function need egress at all? Most do not. The CDK stack in this repo uses isolated subnets with zero NAT for exactly this reason — mining needs to reach a pool, and a function that cannot reach the internet cannot mine.
- [ ] Did reserved concurrency bound the cost? Unbounded concurrency turns a compromise into a bill as well as a breach.
- [ ] Time from GuardDuty finding to containment. If it is measured in hours, the routing is the problem, not the response.
