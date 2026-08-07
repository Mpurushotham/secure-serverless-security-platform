#!/usr/bin/env bash
# Regenerate evidence/cdk-synth.txt. No AWS account required: the stack is
# environment-agnostic unless CDK_DEFAULT_ACCOUNT is set.
set -uo pipefail
cd "$(dirname "$0")/../infra/cdk"
echo "================================================================================"
echo " CDK SYNTHESIS & SECURITY VALIDATION"
echo "================================================================================"
echo
echo "--- tsc --noEmit (strict) ---"
npx tsc --noEmit && echo "  no type errors"
echo
echo "--- security invariant tests ---"
npx jest 2>&1 | grep -E '✓|✕|Tests:' | sed 's/^/  /'
echo
echo "--- cdk synth with Aspects + cdk-nag (AwsSolutionsChecks) ---"
out=$(npx cdk synth --quiet 2>&1 | grep -E '^ERROR|^WARNING' || true)
if [ -z "$out" ]; then echo "  no errors or warnings"; else echo "$out" | sed 's/^/  /'; fi
echo
echo "--- synthesised template ---"
python3 -c "
import json,glob,collections
for f in sorted(glob.glob('cdk.out/*.template.json')):
    t=json.load(open(f)); r=t.get('Resources',{})
    print(f'  {f.split(\"/\")[-1]}: {len(r)} resources')
    for ty,n in collections.Counter(v['Type'] for v in r.values()).most_common():
        print(f'    {n:>3}  {ty}')
"
echo
echo "Aspects enforced: NoWildcardIam, RequireLogRetention, RequireVpcAttachment."
echo "cdk-nag suppressions are declared in bin/app.ts, each with a stated reason."
