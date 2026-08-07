#!/usr/bin/env bash
# Evidence generator: prove the DATABASE ENGINE — not the application — denies
# writes and raw-PII reads to the agent role.
#
# This is the artifact that makes "read-only" a fact rather than a claim. Every
# refusal below comes from PostgreSQL itself, with the application layer
# entirely out of the picture: we connect as `mcp_readonly` with psql.
#
# Usage: scripts/db_privilege_proof.sh [container] > evidence/db-privilege-proof.txt
set -uo pipefail

CONTAINER="${1:-ssp-pg}"
PGUSER_RO="mcp_readonly"
PGPASS_RO="${MCP_DB_PASSWORD:-harness-only}"

run_as_readonly() {
    docker exec -e PGPASSWORD="$PGPASS_RO" -i "$CONTAINER" \
        psql -U "$PGUSER_RO" -d pharmadb -h 127.0.0.1 -X -A -t -c "$1" 2>&1
}

check() {
    local label="$1" sql="$2" expect="$3"   # expect: ALLOW | DENY
    local out rc
    out="$(run_as_readonly "$sql")"
    rc=$?
    printf '\n### %s\n' "$label"
    printf 'SQL      : %s\n' "$sql"
    printf 'Expect   : %s\n' "$expect"
    if [[ "$expect" == "DENY" ]]; then
        if [[ $rc -ne 0 || "$out" == *"ERROR"* || "$out" == *"denied"* ]]; then
            printf 'Result   : REFUSED BY ENGINE ✔\n'
        else
            printf 'Result   : *** NOT REFUSED — CONTROL FAILURE *** �’\n'
            FAILURES=$((FAILURES + 1))
        fi
    else
        if [[ $rc -eq 0 && "$out" != *"ERROR"* ]]; then
            printf 'Result   : ALLOWED ✔\n'
        else
            printf 'Result   : *** UNEXPECTEDLY REFUSED *** \n'
            FAILURES=$((FAILURES + 1))
        fi
    fi
    printf 'Engine   : %s\n' "$(echo "$out" | head -3 | tr '\n' ' ')"
}

FAILURES=0

cat <<'HEADER'
================================================================================
 DATABASE PRIVILEGE PROOF — role: mcp_readonly
================================================================================
 Every refusal below is issued by PostgreSQL, not by application code. This is
 the defence-in-depth invariant: even with total compromise of the MCP server
 process, the agent identity cannot write, cannot read raw PII, and cannot run
 unbounded queries.
================================================================================
HEADER

printf '\n--- 1. READS THAT SHOULD SUCCEED ------------------------------------\n'
check "Non-sensitive table is readable"      "SELECT count(*) FROM pharmacy.products;"                ALLOW
check "Masked customer view is readable"     "SELECT personnummer_masked, email_masked FROM pharmacy.v_customers_masked ORDER BY id LIMIT 2;" ALLOW

printf '\n--- 2. RAW PII IS ABSENT, NOT MERELY GUARDED ------------------------\n'
check "Base customers table"                 "SELECT personnummer FROM pharmacy.customers LIMIT 1;"   DENY
check "Base prescriptions table (raw)"       "SELECT prescriber_hsa_id FROM pharmacy.prescriptions LIMIT 1;" DENY

printf '\n--- 3. WRITES ARE IMPOSSIBLE ----------------------------------------\n'
check "INSERT"        "INSERT INTO pharmacy.orders (customer_id,status,total_sek) VALUES (1,'x',1);" DENY
check "UPDATE"        "UPDATE pharmacy.orders SET status='hacked';"                                  DENY
check "DELETE"        "DELETE FROM pharmacy.orders;"                                                 DENY
check "TRUNCATE"      "TRUNCATE pharmacy.orders;"                                                    DENY
check "DROP TABLE"    "DROP TABLE pharmacy.orders;"                                                  DENY
check "CREATE TABLE"  "CREATE TABLE pharmacy.evil (id int);"                                         DENY
check "ALTER TABLE"   "ALTER TABLE pharmacy.orders ADD COLUMN evil text;"                            DENY
check "CTE-wrapped write (parser bypass attempt)" \
      "WITH w AS (INSERT INTO pharmacy.orders (customer_id,status,total_sek) VALUES (1,'x',1) RETURNING id) SELECT * FROM w;" DENY

printf '\n--- 4. FILESYSTEM / COMMAND EXECUTION PRIMITIVES --------------------\n'
check "COPY TO PROGRAM"  "COPY (SELECT 1) TO PROGRAM 'id';"                    DENY
check "COPY FROM file"   "COPY pharmacy.orders FROM '/etc/passwd';"            DENY
check "pg_read_file"     "SELECT pg_read_file('/etc/passwd');"                 DENY
check "pg_ls_dir"        "SELECT pg_ls_dir('/');"                              DENY

printf '\n--- 5. PRIVILEGE ESCALATION -----------------------------------------\n'
check "SET ROLE postgres"     "SET ROLE postgres;"                             DENY
check "Create a new role"     "CREATE ROLE eviluser LOGIN;"                     DENY
check "Read password hashes"  "SELECT rolname, rolpassword FROM pg_authid;"     DENY

check "Withheld column: prescriber_hsa_id" "SELECT prescriber_hsa_id FROM pharmacy.prescriptions LIMIT 1;" DENY
# Reading the filter column would turn its absence into an oracle for the
# hidden rows, so it is withheld too.
check "Withheld column: consent_analytics" "SELECT consent_analytics FROM pharmacy.prescriptions LIMIT 1;" DENY

printf '\n--- 6. ROW-LEVEL SECURITY: CONSENT AS AN ENGINE-ENFORCED FILTER -----\n'
printf '\nRegression guard. An earlier revision of this schema had the consent\n'
printf 'policy present in DDL but INERT at runtime: the masked view executed as\n'
printf 'its owner, the owner is a superuser, and superusers bypass RLS. All four\n'
printf 'rows were visible. The fix was security_invoker=true on the view plus\n'
printf 'COLUMN-level grants on the base table. This block pins that fix.\n\n'

TOTAL_ROWS="$(docker exec -i "$CONTAINER" psql -U postgres -d pharmadb -X -A -t \
    -c "SELECT count(*) FROM pharmacy.prescriptions;" 2>&1 | tr -d '[:space:]')"
CONSENTED_ROWS="$(docker exec -i "$CONTAINER" psql -U postgres -d pharmadb -X -A -t \
    -c "SELECT count(*) FROM pharmacy.prescriptions WHERE consent_analytics;" 2>&1 | tr -d '[:space:]')"
VISIBLE_ROWS="$(run_as_readonly "SELECT count(*) FROM pharmacy.v_prescriptions_masked;" | tr -d '[:space:]')"

printf 'Rows in base table            : %s\n' "$TOTAL_ROWS"
printf 'Rows with consent_analytics   : %s\n' "$CONSENTED_ROWS"
printf 'Rows visible to mcp_readonly  : %s\n' "$VISIBLE_ROWS"

if [[ "$VISIBLE_ROWS" == "$CONSENTED_ROWS" && "$VISIBLE_ROWS" != "$TOTAL_ROWS" ]]; then
    printf 'Result   : RLS ENFORCED — non-consented rows unreachable ✔\n'
else
    printf 'Result   : *** RLS BYPASS — agent sees non-consented rows *** \n'
    FAILURES=$((FAILURES + 1))
fi

printf '\nRows the agent can actually see:\n'
run_as_readonly "SELECT id, medication, issued_month FROM pharmacy.v_prescriptions_masked ORDER BY id;"
printf '\nThe agent cannot widen this by omitting a WHERE clause: the filter is\n'
printf 'applied by the engine before the query is evaluated.\n'

printf '\n--- 7. RESOURCE BOUNDS ----------------------------------------------\n'
printf '\nstatement_timeout / read-only defaults pinned to the role:\n'
docker exec -i "$CONTAINER" psql -U postgres -d pharmadb -X -A -t \
    -c "SELECT unnest(rolconfig) FROM pg_roles WHERE rolname='mcp_readonly';" 2>&1

printf '\n================================================================================\n'
if [[ $FAILURES -eq 0 ]]; then
    printf ' RESULT: all controls held. 0 failures.\n'
else
    printf ' RESULT: *** %d CONTROL FAILURE(S) *** \n' "$FAILURES"
fi
printf '================================================================================\n'
exit $FAILURES
