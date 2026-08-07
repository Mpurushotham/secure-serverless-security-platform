"""SQL guardrails — parse, then decide, then execute.

The central claim of this module: **you cannot make SQL safe with a regex.**

Keyword blocklists lose to comment injection (`SEL/**/ECT`), case and unicode
tricks, whitespace, string-literal decoys, and nested constructs. Worse, they
fail *open* — anything the pattern misses is permitted. So every decision here
is made against a parsed abstract syntax tree, where "is this a write?" is a
question about node types rather than about spelling.

This layer is the second of three. It is not the last:

    1. mcp_core       -- protocol shape, tool allowlist
    2. guardrails.py  -- THIS FILE: statement shape, caps, capability checks
    3. mcp_readonly   -- the database role; holds even if 1 and 2 are defeated

Layer 3 exists precisely because this file can have bugs. Anything here that
fails open is caught by grants and RLS that the process cannot alter. That
ordering is deliberate and is what makes the design defensible: the guardrail
is an optimisation for good error messages, not the only thing standing
between an agent and the data.
"""

from __future__ import annotations

from dataclasses import dataclass

import sqlglot
from mcp_core.errors import GuardrailViolation
from sqlglot import exp

DIALECT = "postgres"

# Node types that mutate state or change the security context. Checked by TYPE,
# anywhere in the tree — which is what defeats `WITH w AS (INSERT ...) SELECT`,
# a construct that trivially passes any "must start with SELECT" check.
FORBIDDEN_NODES: tuple[type[exp.Expression], ...] = (
    exp.Insert,
    exp.Update,
    exp.Delete,
    exp.Drop,
    exp.Create,
    exp.Alter,
    exp.TruncateTable,
    exp.Grant,
    exp.Merge,
    exp.Copy,          # COPY ... TO PROGRAM is remote code execution
    exp.Into,          # SELECT ... INTO creates a table
    exp.Set,           # SET ROLE / SET search_path change the security context
    exp.Command,       # sqlglot's catch-all for unparsed statements (CALL, DO, VACUUM)
)

# Functions that reach outside the data. Matched on the bare, lower-cased name
# so schema-qualification (`pg_catalog.pg_read_file`) cannot smuggle one past.
FORBIDDEN_FUNCTIONS: frozenset[str] = frozenset(
    {
        # Filesystem
        "pg_read_file", "pg_read_binary_file", "pg_ls_dir", "pg_stat_file",
        "lo_import", "lo_export",
        # Network / remote
        "dblink", "dblink_exec", "dblink_connect",
        # Denial of service
        "pg_sleep", "pg_sleep_for", "pg_sleep_until",
        # Credential and internal disclosure
        "pg_read_server_files", "current_setting", "set_config",
        # XML/JSON functions that can be coerced into reading arbitrary relations
        "query_to_xml", "database_to_xml", "query_to_xml_and_xmlschema",
        # Privilege inspection used for reconnaissance
        "pg_authid", "pg_shadow",
    }
)

# Relations the agent may read at all. Belt-and-braces with the database
# grants: it produces a clear, fast refusal instead of a bare "permission
# denied", which matters because the model needs a legible reason to adapt.
DEFAULT_ALLOWED_RELATIONS: frozenset[str] = frozenset(
    {
        "products",
        "orders",
        "order_items",
        "v_customers_masked",
        "v_prescriptions_masked",
    }
)


@dataclass(frozen=True)
class GuardrailConfig:
    max_rows: int = 500
    max_bytes: int = 512 * 1024
    allowed_relations: frozenset[str] = DEFAULT_ALLOWED_RELATIONS
    # Off unless explicitly configured. Reading unmasked PII must be a
    # deliberate deployment decision, never a default and never a tool argument
    # the model can set for itself.
    allow_unmask: bool = False


def _refuse(reason: str, control: str, *, detail: str | None = None) -> GuardrailViolation:
    return GuardrailViolation(reason, control=control, internal_detail=detail)


def validate_select(sql: str, config: GuardrailConfig | None = None) -> str:
    """Validate and normalise a read-only statement.

    Returns the rewritten SQL (with an enforced LIMIT) or raises
    GuardrailViolation. Never executes anything.
    """
    config = config or GuardrailConfig()

    if not sql or not sql.strip():
        raise _refuse("empty statement", "sql-parse")

    # 1. PARSE. A statement that will not parse is never executed — "run it and
    #    see" is how you find out what a payload does the expensive way.
    try:
        statements = sqlglot.parse(sql, dialect=DIALECT)
    except Exception as exc:  # sqlglot raises several types
        raise _refuse("statement could not be parsed", "sql-parse", detail=repr(exc)) from exc

    statements = [s for s in statements if s is not None]

    # 2. EXACTLY ONE STATEMENT. Stacked statements are the classic escape:
    #    `SELECT 1; DROP TABLE x` passes any check that only inspects the first.
    if len(statements) == 0:
        raise _refuse("no statement found", "sql-parse")
    if len(statements) > 1:
        raise _refuse(
            f"exactly one statement permitted, found {len(statements)}",
            "single-statement",
        )

    statement = statements[0]

    # 3. ROOT MUST BE A READ. EXPLAIN is allowed but only over a SELECT.
    root = statement
    if isinstance(root, exp.Command) and (root.this or "").upper() == "EXPLAIN":
        raise _refuse(
            "EXPLAIN variant not supported; use explain_query with a plain SELECT",
            "explain-form",
        )

    if not isinstance(root, (exp.Select, exp.Union, exp.Subquery, exp.With)):
        raise _refuse(
            f"only SELECT statements are permitted, got {type(root).__name__.upper()}",
            "read-only",
        )

    # 4. NO MUTATING NODE ANYWHERE IN THE TREE.
    #    Defeats CTE-wrapped writes and writes nested in subqueries.
    for node in root.walk():
        if isinstance(node, FORBIDDEN_NODES):
            raise _refuse(
                f"{type(node).__name__.upper()} is not permitted in any position",
                "read-only",
            )

    # 5. NO LOCKING. `SELECT ... FOR UPDATE` takes row locks — a read that
    #    blocks writers is an availability problem, not a read.
    if list(root.find_all(exp.Lock)):
        raise _refuse("locking clauses (FOR UPDATE/SHARE) are not permitted", "no-locking")

    # 6. FUNCTION DENYLIST, by resolved name.
    for func in root.find_all(exp.Func):
        name = (getattr(func, "sql_name", lambda: "")() or "").lower()
        if not name:
            name = type(func).__name__.lower()
        if name in FORBIDDEN_FUNCTIONS:
            raise _refuse(f"function {name}() is not permitted", "function-denylist")
    # Anonymous functions parse as exp.Anonymous and carry the raw identifier.
    for anon in root.find_all(exp.Anonymous):
        name = str(anon.this or "").lower()
        if name in FORBIDDEN_FUNCTIONS:
            raise _refuse(f"function {name}() is not permitted", "function-denylist")

    # 7. RELATION ALLOWLIST. CTE aliases are not relations; exclude them or
    #    every legitimate `WITH x AS (...)` is refused.
    cte_names = {c.alias_or_name.lower() for c in root.find_all(exp.CTE)}
    for table in root.find_all(exp.Table):
        name = (table.name or "").lower()
        if not name or name in cte_names:
            continue
        if name not in config.allowed_relations:
            raise _refuse(
                f"relation '{name}' is not in the read allowlist",
                "relation-allowlist",
            )

    # 8. ENFORCE A LIMIT. An unbounded SELECT is an exfiltration primitive; the
    #    caller does not get to opt out, and a larger caller-supplied LIMIT is
    #    lowered rather than honoured.
    limited = _apply_limit(root, config.max_rows)

    return limited.sql(dialect=DIALECT)


def _apply_limit(root: exp.Expression, max_rows: int) -> exp.Expression:
    """Force a LIMIT no greater than max_rows onto the outermost query."""
    existing = root.args.get("limit")
    if existing is not None:
        try:
            current = int(existing.expression.this)
        except (AttributeError, TypeError, ValueError):
            # Non-literal LIMIT (expression, parameter). Replace it outright —
            # we cannot reason about what it evaluates to.
            return root.limit(max_rows)
        if current > max_rows:
            return root.limit(max_rows)
        return root
    return root.limit(max_rows)


def enforce_result_caps(
    rows: list[dict], rendered_bytes: int, config: GuardrailConfig | None = None
) -> None:
    """Second-stage cap, applied to actual results.

    The LIMIT bounds row count, not row *size*: 500 rows each holding a 1 MB
    text column is still a bulk transfer. Bounding bytes as well is what makes
    'exfiltration by wide row' uninteresting.
    """
    config = config or GuardrailConfig()
    if len(rows) > config.max_rows:
        raise _refuse(
            f"result exceeded row cap ({len(rows)} > {config.max_rows})", "row-cap"
        )
    if rendered_bytes > config.max_bytes:
        raise _refuse(
            f"result exceeded byte cap ({rendered_bytes} > {config.max_bytes})", "byte-cap"
        )


def require_unmask_capability(config: GuardrailConfig | None = None) -> None:
    """Unmasking is a deployment decision, not a runtime argument."""
    config = config or GuardrailConfig()
    if not config.allow_unmask:
        raise _refuse(
            "unmasked access is disabled for this deployment", "unmask-capability"
        )
