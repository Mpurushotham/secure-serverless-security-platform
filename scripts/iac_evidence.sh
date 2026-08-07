#!/usr/bin/env bash
# Regenerate evidence/iac-scan.txt. Static only — no AWS account, no credentials.
set -uo pipefail
cd "$(dirname "$0")/.."
echo "================================================================================"
echo " IaC VALIDATION & POLICY SCAN"
echo "================================================================================"
echo
echo "--- terraform validate ---"
for d in infra/terraform/modules/*/ infra/terraform/detections/; do
  [ -d "$d" ] || continue
  terraform -chdir="$d" init -backend=false -input=false >/dev/null 2>&1
  printf '%-46s ' "$d"; terraform -chdir="$d" validate -no-color 2>&1 | head -1
done
echo
echo "--- terraform fmt -check ---"
terraform fmt -check -recursive infra/ >/dev/null 2>&1 && echo "  all files formatted" || echo "  FORMATTING DRIFT"
echo
echo "--- tflint ---"
command -v tflint >/dev/null && { tflint --recursive --format compact 2>&1 | head -20; echo "  tflint exit=$?"; } || echo "  (not installed)"
echo
echo "--- checkov ---"
if [ -x .venv/bin/checkov ]; then
  .venv/bin/checkov -d infra/ --compact --quiet -o cli 2>&1 | grep -E '^Passed|^Failed|terraform scan'
else
  echo "  (checkov not installed)"
fi
echo
echo "Suppressions are enumerated with justification in evidence/checkov-suppressions.md."
