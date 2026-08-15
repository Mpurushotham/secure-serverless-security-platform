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

.PHONY: help setup cdk-setup db-up db-down db-reset test mcp-demo evidence scan validate clean all

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

scan: ## SAST, dependency audit, and secret scanning
	-$(PY) -m bandit -q -c pyproject.toml -r mcp-servers -f txt -o evidence/bandit.txt
	-$(PY) -m pip_audit -f json -o evidence/pip-audit.json 2>/dev/null
	-command -v semgrep >/dev/null && semgrep --config auto --sarif -o evidence/semgrep.sarif . || \
	  echo "  (semgrep not installed — skipped)"
	-command -v gitleaks >/dev/null && gitleaks detect --no-git -r evidence/gitleaks.json || \
	  echo "  (gitleaks not installed — skipped)"
	@echo "✔ scans complete (see evidence/)"

validate: ## Validate all IaC statically — no AWS account required
	@set -e; for d in infra/terraform/modules/*/ infra/terraform/detections/; do \
	  [ -d "$$d" ] || continue; echo "  terraform validate $$d"; \
	  terraform -chdir=$$d init -backend=false -input=false >/dev/null; \
	  terraform -chdir=$$d validate; \
	done
	@terraform fmt -check -recursive infra/ >/dev/null && echo "  fmt: clean" || \
	  { echo "  run 'terraform fmt -recursive infra/'"; exit 1; }
	-@command -v tflint >/dev/null && tflint --recursive --format compact || \
	  echo "  (tflint not installed — skipped)"
	# cdk.out is EXCLUDED deliberately, not silently. cdk-nag is the authority for the CDK
	# app and its suppressions carry stated reasons; generated CloudFormation cannot hold a
	# comment, so a checkov finding there can never be justified in place. Scanning it would
	# force blanket skips, which is strictly worse. The CDK gate is `cdk synth` + cdk-nag +
	# the invariant tests, all run separately.
	@test -x $(CHECKOV) && $(CHECKOV) -d infra/ --skip-path cdk.out --compact --quiet -o cli 2>&1 | \
	  grep -E '^Passed|^Failed|terraform scan' || echo "  (checkov not installed — skipped)"
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
