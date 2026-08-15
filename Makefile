.DEFAULT_GOAL := help
SHELL := /bin/bash

PY        := .venv/bin/python
CHECKOV   := .venv/bin/checkov
PG_NAME   := ssp-pg
PG_PORT   := 55432
PG_IMAGE  := postgres:17-alpine
SQL_DIR   := mcp-servers/rds_readonly_mcp/sql
RO_PASS   ?= harness-only
export MCP_DB_DSN ?= postgresql://mcp_readonly:$(RO_PASS)@127.0.0.1:$(PG_PORT)/pharmadb

DISCOVERY := PYTHONPATH=platform/00-discovery $(PY) -m discovery.run
SNAPSHOTS := platform/00-discovery/snapshots
# Which AWS profile `make assess` points at. Override per run:
#   make assess AWS_PROFILE=some-other-profile
AWS_PROFILE ?= cap-lab

.PHONY: help setup cdk-setup db-up db-down db-reset test mcp-demo evidence scan \
        validate clean all assess assess-offline report vuln-gate posture obs-up obs-down rules-test

help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
	  | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

setup: ## Create the venv and install dependencies
	uv venv --python 3.11 .venv
	uv pip install -e ".[dev,rds,aws]"
	@echo "✔ setup complete — next: make db-up"

db-up: ## Start PostgreSQL and apply schema, roles, and masked views
	@docker rm -f $(PG_NAME) >/dev/null 2>&1 || true
	docker run -d --name $(PG_NAME) \
	  -e POSTGRES_PASSWORD=devonly -e POSTGRES_DB=pharmadb \
	  -p $(PG_PORT):5432 $(PG_IMAGE) >/dev/null
	@echo -n "waiting for postgres"; \
	for i in $$(seq 1 30); do \
	  docker exec $(PG_NAME) pg_isready -U postgres -d pharmadb >/dev/null 2>&1 && break; \
	  echo -n "."; sleep 1; done; echo
	@for f in 00-seed-schema 01-roles 02-masked-views; do \
	  echo "  applying $$f.sql"; \
	  docker exec -i $(PG_NAME) psql -U postgres -d pharmadb -v ON_ERROR_STOP=1 -q < $(SQL_DIR)/$$f.sql; \
	done
	@docker exec -i $(PG_NAME) psql -U postgres -d pharmadb -q \
	  -c "ALTER ROLE mcp_readonly PASSWORD '$(RO_PASS)';"
	@echo "✔ database ready on port $(PG_PORT)"

db-down: ## Stop and remove the database container
	@docker rm -f $(PG_NAME) >/dev/null 2>&1 || true
	@echo "✔ database removed"

db-reset: db-down db-up ## Rebuild the database from scratch

test: ## Run the full test suite (protocol, guardrails, leak assertions)
	$(PY) -m pytest mcp-servers/tests -q

mcp-demo: ## Live stdio MCP session against the database
	$(PY) scripts/mcp_demo.py --json-out evidence/mcp-demo-transcript.jsonl

evidence: ## Regenerate every artifact under evidence/
	@mkdir -p evidence
	$(PY) -m pytest mcp-servers/tests -q > evidence/test-results.txt 2>&1 \
	  || { cat evidence/test-results.txt; exit 1; }
	./scripts/db_privilege_proof.sh $(PG_NAME) > evidence/db-privilege-proof.txt
	$(PY) scripts/bypass_report.py
	$(PY) scripts/mcp_demo.py --json-out evidence/mcp-demo-transcript.jsonl \
	  > evidence/mcp-demo-session.txt
	./scripts/iac_evidence.sh > evidence/iac-scan.txt 2>&1
	-./scripts/cdk_evidence.sh > evidence/cdk-synth.txt 2>&1
	$(PY) scripts/suppression_register.py
	@echo "✔ evidence regenerated"

assess: ## Read-only AWS discovery against a live account (needs credentials)
	@echo "  profile: $(AWS_PROFILE) — read-only Describe/List/Get only"
	$(DISCOVERY) --profile $(AWS_PROFILE) --out $(SNAPSHOTS)
	@echo "✔ assessment complete — platform/00-discovery/report/assessment.md"

assess-offline: ## Re-render the report from the committed snapshot — no AWS, no credentials
	$(DISCOVERY) --from-snapshot $(SNAPSHOTS)/latest.json
	@echo "✔ report regenerated from the committed snapshot"

report: assess-offline ## Alias for assess-offline

posture: ## Posture report + metrics + delta vs the previous snapshot (no AWS)
	PYTHONPATH=platform/18-reporting $(PY) -m reporting
	@echo "✔ platform/18-reporting/posture.md"

vuln-gate: ## Severity budget + remediation SLA against a fresh checkov SARIF
	@mkdir -p /tmp/ssp-sarif
	@cd /tmp/ssp-sarif && $(CURDIR)/$(CHECKOV) -d $(CURDIR)/infra --skip-path cdk.out \
	  -o sarif --output-file-path . >/dev/null 2>&1 || true
	@cd /tmp/ssp-sarif && mv results_sarif.sarif infra.sarif 2>/dev/null || true
	# cdk.out excluded here for the same reason `validate` excludes it: cdk-nag is
	# the authority for the CDK apps and its suppressions carry written reasons,
	# while generated CloudFormation cannot hold a comment — so a finding there
	# could only ever be blanket-skipped. CI never saw this because cdk.out is
	# gitignored; a local run does, and the two gates disagreeing is worse than
	# either answer.
	@cd /tmp/ssp-sarif && $(CURDIR)/$(CHECKOV) -d $(CURDIR)/platform \
	  --skip-path node_modules --skip-path cdk.out \
	  -o sarif --output-file-path . >/dev/null 2>&1 || true
	@cd /tmp/ssp-sarif && mv results_sarif.sarif platform.sarif 2>/dev/null || true
	$(PY) scripts/severity_gate.py /tmp/ssp-sarif/*.sarif
	$(PY) scripts/vuln_sla.py /tmp/ssp-sarif/*.sarif

OBS := platform/19-observability

rules-test: ## promtool: alert rules parse AND fire (a rule that cannot fire is not a control)
	promtool check rules $(OBS)/prometheus/rules/posture.yml
	promtool test rules $(OBS)/prometheus/rules/posture_test.yml

obs-up: ## Prometheus + Alertmanager + Grafana + the posture exporter (no AWS needed)
	@test -f $(OBS)/compose/.env || { \
	  echo "  create $(OBS)/compose/.env from .env.example first —"; \
	  echo "  compose refuses to start rather than defaulting Grafana to admin/admin"; exit 1; }
	docker compose -f $(OBS)/compose/docker-compose.yml up -d --build
	@echo "✔ Grafana http://127.0.0.1:3000 · Prometheus http://127.0.0.1:9090"

obs-down: ## Stop the observability stack
	docker compose -f $(OBS)/compose/docker-compose.yml down
	@echo "✔ stack stopped"

scan: ## SAST, dependency audit, and secret scanning
	-$(PY) -m bandit -q -c pyproject.toml -r mcp-servers -f txt -o evidence/bandit.txt
	-$(PY) -m pip_audit -f json -o evidence/pip-audit.json 2>/dev/null
	-command -v semgrep >/dev/null && semgrep --config auto --sarif -o evidence/semgrep.sarif . || \
	  echo "  (semgrep not installed — skipped)"
	-command -v gitleaks >/dev/null && gitleaks detect --no-git -r evidence/gitleaks.json || \
	  echo "  (gitleaks not installed — skipped)"
	@echo "✔ scans complete (see evidence/)"

TF_DIRS := infra/terraform/modules/*/ infra/terraform/detections/ \
           platform/01-organization/ platform/04-logging/ platform/05-detection/

validate: ## Validate all IaC statically — no AWS account required
	@set -e; for d in $(TF_DIRS); do \
	  [ -d "$$d" ] || continue; echo "  terraform validate $$d"; \
	  terraform -chdir=$$d init -backend=false -input=false >/dev/null; \
	  terraform -chdir=$$d validate; \
	done
	@terraform fmt -check -recursive infra/ platform/ >/dev/null && echo "  fmt: clean" || \
	  { echo "  run 'terraform fmt -recursive infra/ platform/'"; exit 1; }
	-@command -v tflint >/dev/null && tflint --recursive --format compact || \
	  echo "  (tflint not installed — skipped)"
	# cdk.out is EXCLUDED deliberately, not silently. cdk-nag is the authority for the CDK
	# app and its suppressions carry stated reasons; generated CloudFormation cannot hold a
	# comment, so a checkov finding there can never be justified in place. Scanning it would
	# force blanket skips, which is strictly worse. The CDK gate is `cdk synth` + cdk-nag +
	# the invariant tests, all run separately.
	# One checkov invocation PER ROOT, not one with several -d flags.
	#
	# Two reasons, and the second is the important one:
	#   * A parsing error reports "Passed: 0, Failed: 0" and exits clean, so a file
	#     nothing scanned looks exactly like a file with nothing wrong.
	#   * Given multiple -d flags, checkov stops reporting parse errors at all — so the
	#     gate below only works when each root is scanned separately.
	#
	# This is not hypothetical. checkov cannot parse a multi-line parenthesised
	# `a || b` condition, which Terraform accepts; platform/01-organization/checks.tf
	# was silently unscanned until the condition was rewritten with anytrue().
	@test -x $(CHECKOV) || { echo "  (checkov not installed — skipped)"; exit 0; }; \
	  failed=0; \
	  for root in infra platform; do \
	    out=$$($(CHECKOV) -d $$root --skip-path cdk.out --skip-path node_modules \
	      --compact -o cli 2>&1); \
	    echo "$$out" | grep -E '^Passed checks' | head -1 | sed "s|^|  $$root: |"; \
	    if echo "$$out" | grep -q '^Error parsing file'; then \
	      echo "  ✗ checkov could not parse these files — they were NOT scanned:"; \
	      echo "$$out" | grep '^Error parsing file' | sed 's/^/      /'; \
	      failed=1; \
	    fi; \
	    if echo "$$out" | grep -qE '^Failed checks: [1-9]'; then failed=1; fi; \
	  done; \
	  [ $$failed -eq 0 ] && echo "  checkov: no failures, no unparsed files" || exit 1
	@echo "  --- CDK ---"
	@if [ -d node_modules/aws-cdk-lib ]; then \
	  echo "  shared aspects: $$(cd platform/lib/cdk-security && npx tsc --noEmit && npx jest --silent 2>&1 | grep -E '^Tests:' || echo FAILED)"; \
	  (cd infra/cdk && npx tsc --noEmit && npx jest --silent 2>&1 | tail -3 && \
	   npx cdk synth --quiet >/dev/null && echo "  cdk synth: clean (aspects + cdk-nag)"); \
	else echo "  (cdk deps not installed — run 'make cdk-setup')"; fi
	@echo "✔ IaC validation complete"

cdk-setup: ## Install CDK dependencies (npm workspaces — installs from the repo root)
	npm install
	@echo "✔ cdk ready"

all: setup db-up test mcp-demo evidence ## Full pipeline from a clean clone

clean: db-down ## Remove the venv and generated artifacts
	rm -rf .venv .pytest_cache .ruff_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
	@echo "✔ clean"
