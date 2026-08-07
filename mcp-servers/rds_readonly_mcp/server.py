"""Read-only MCP server for PostgreSQL / Aurora PostgreSQL.

Exposes a deliberately small tool surface. Every tool is a read; every read
passes the guardrail in `guardrails.py`; every connection authenticates as a
database role that cannot write even if both of those fail.

Connection handling worth noting: the DSN is read from the environment, and in
AWS the password component is absent entirely — the role authenticates with
IAM database authentication, so there is no long-lived credential to leak. A
literal DSN in source or in a tool argument would undo the entire design, so
`run_select` takes SQL and nothing else: the model cannot choose what it
connects to.

Run:  MCP_DB_DSN=postgresql://mcp_readonly@host/pharmadb python -m rds_readonly_mcp.server
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any

import psycopg
from psycopg.rows import dict_row

from mcp_core import AuditLog, MCPServer, StdioTransport
from mcp_core.errors import GuardrailViolation

from .guardrails import GuardrailConfig, enforce_result_caps, validate_select
from .masking import classify_columns, summarise

SERVER_NAME = "rds-readonly-mcp"

# Relations the agent may introspect or sample. Kept identical to the guardrail
# allowlist so there is one place to change, not two that can drift apart.
CONFIG = GuardrailConfig(
    allow_unmask=os.environ.get("MCP_ALLOW_UNMASK", "").lower() == "true",
)


def _dsn() -> str:
    dsn = os.environ.get("MCP_DB_DSN")
    if not dsn:
        raise RuntimeError("MCP_DB_DSN is not set")
    return dsn


def _query(sql: str, params: tuple = ()) -> list[dict[str, Any]]:
    """Execute an already-validated statement.

    `autocommit=True` plus a role pinned to read-only transactions means no
    transaction is ever left open by a crashed handler.
    """
    with psycopg.connect(_dsn(), autocommit=True, row_factory=dict_row) as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)  # noqa: S608 — validated by validate_select
            rows = cur.fetchall()
    return rows


def _result(rows: list[dict[str, Any]]) -> dict[str, Any]:
    rendered = json.dumps(rows, default=str)
    enforce_result_caps(rows, len(rendered.encode("utf-8")), CONFIG)
    return {"row_count": len(rows), "rows": rows}


def build_server(audit: AuditLog | None = None) -> MCPServer:
    server = MCPServer(SERVER_NAME, audit=audit)

    @server.tool(
        "list_relations",
        "List the relations this server is permitted to read, with the PII "
        "classification of each column. Start here — it tells you which "
        "columns are masked and why, so you can avoid them by construction.",
        {"type": "object", "properties": {}},
    )
    def _list_relations(_args: dict) -> dict:
        rows = _query(
            """
            SELECT table_name, column_name
            FROM information_schema.columns
            WHERE table_schema = 'pharmacy' AND table_name = ANY(%s)
            ORDER BY table_name, ordinal_position
            """,
            (list(CONFIG.allowed_relations),),
        )
        grouped: dict[str, list[str]] = {}
        for row in rows:
            grouped.setdefault(row["table_name"], []).append(row["column_name"])

        out = []
        for relation, columns in sorted(grouped.items()):
            classifications = classify_columns(columns)
            out.append(
                {
                    "relation": relation,
                    "columns": [
                        {
                            "name": c.column,
                            "sensitivity": c.sensitivity.value,
                            "basis": c.basis,
                        }
                        for c in classifications
                    ],
                    "sensitivity_summary": summarise(classifications),
                }
            )
        return {"allowed_relations": out}

    @server.tool(
        "describe_relation",
        "Describe one relation's columns and types.",
        {
            "type": "object",
            "properties": {"relation": {"type": "string"}},
            "required": ["relation"],
        },
    )
    def _describe(args: dict) -> dict:
        relation = str(args["relation"]).lower()
        if relation not in CONFIG.allowed_relations:
            raise GuardrailViolation(
                f"relation '{relation}' is not in the read allowlist",
                control="relation-allowlist",
            )
        rows = _query(
            """
            SELECT column_name, data_type, is_nullable
            FROM information_schema.columns
            WHERE table_schema = 'pharmacy' AND table_name = %s
            ORDER BY ordinal_position
            """,
            (relation,),
        )
        for row in rows:
            c = classify_columns([row["column_name"]])[0]
            row["sensitivity"] = c.sensitivity.value
            row["basis"] = c.basis
        return _result(rows)

    @server.tool(
        "run_select",
        "Run a read-only SELECT. Refused unless the parsed statement is a "
        "single SELECT over allowlisted relations, with no mutating node "
        "anywhere in the tree. A LIMIT is always enforced.",
        {
            "type": "object",
            "properties": {"sql": {"type": "string", "description": "A single SELECT."}},
            "required": ["sql"],
        },
    )
    def _run_select(args: dict) -> dict:
        safe_sql = validate_select(str(args["sql"]), CONFIG)
        return _result(_query(safe_sql))

    @server.tool(
        "explain_query",
        "Return the query plan for a SELECT without executing it. Uses plain "
        "EXPLAIN — never ANALYZE, which would run the statement.",
        {
            "type": "object",
            "properties": {"sql": {"type": "string"}},
            "required": ["sql"],
        },
    )
    def _explain(args: dict) -> dict:
        safe_sql = validate_select(str(args["sql"]), CONFIG)
        rows = _query(f"EXPLAIN (FORMAT JSON) {safe_sql}")
        return {"plan": rows[0] if rows else None}

    @server.tool(
        "sample_rows",
        "Return a small sample from an allowlisted relation.",
        {
            "type": "object",
            "properties": {
                "relation": {"type": "string"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 100},
            },
            "required": ["relation"],
        },
    )
    def _sample(args: dict) -> dict:
        relation = str(args["relation"]).lower()
        limit = min(int(args.get("limit", 10)), 100)
        # Routed through the same validator rather than string-formatted
        # directly: one code path means one place for the check to live.
        return _result(_query(validate_select(f"SELECT * FROM {relation} LIMIT {limit}", CONFIG)))

    return server


def main() -> None:
    audit_path = os.environ.get("MCP_AUDIT_PATH")
    stream = open(audit_path, "a", encoding="utf-8") if audit_path else sys.stderr  # noqa: SIM115
    server = build_server(audit=AuditLog(stream=stream))
    server.serve(StdioTransport())


if __name__ == "__main__":
    main()
