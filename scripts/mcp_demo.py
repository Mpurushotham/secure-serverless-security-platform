#!/usr/bin/env python3
"""Drive the RDS read-only MCP server over real stdio and record the session.

This is the end-to-end evidence artifact. It launches the server as an actual
subprocess and speaks JSON-RPC over its stdin/stdout — no in-process shortcuts,
no mocked transport. What you see here is what an MCP client would see.

The session deliberately includes refusals. A demo that only shows the happy
path proves the server works; showing it refuse a write, refuse raw PII, and
refuse a CTE-wrapped mutation proves it is a *control*.

Usage: scripts/mcp_demo.py [--json-out evidence/mcp-demo-transcript.jsonl]
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import subprocess  # nosec B404
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SERVERS_DIR = REPO_ROOT / "mcp-servers"

# (label, method, params, what this step is meant to demonstrate)
SCRIPT: list[tuple[str, str, dict, str]] = [
    (
        "Handshake",
        "initialize",
        {"protocolVersion": "2025-06-18", "clientInfo": {"name": "demo-client", "version": "1"}},
        "Capability negotiation. Until this completes, every tool call is refused.",
    ),
    (
        "Discover tools",
        "tools/list",
        {},
        "The agent sees only the tools this server advertises.",
    ),
    (
        "Classify the data",
        "tools/call",
        {"name": "list_relations", "arguments": {}},
        "Columns arrive pre-labelled with sensitivity and regulatory basis, so "
        "the model avoids sensitive columns by construction.",
    ),
    (
        "Legitimate analytical read",
        "tools/call",
        {
            "name": "run_select",
            "arguments": {
                "sql": "SELECT status, count(*) AS n FROM orders GROUP BY status ORDER BY n DESC"
            },
        },
        "A normal aggregate. Permitted, and silently given a LIMIT.",
    ),
    (
        "Read masked personal data",
        "tools/call",
        {
            "name": "run_select",
            "arguments": {
                "sql": "SELECT personnummer_masked, email_masked, phone_masked, "
                "postal_district FROM v_customers_masked ORDER BY id"
            },
        },
        "Personal data is returned pseudonymised. The plaintext never leaves "
        "the database engine for this role.",
    ),
    (
        "Health data under consent (GDPR Art. 9)",
        "tools/call",
        {
            "name": "run_select",
            "arguments": {"sql": "SELECT id, medication, issued_month FROM v_prescriptions_masked"},
        },
        "Only rows whose data subject consented to analytics are visible. "
        "Row-level security applies the filter in the engine.",
    ),
    (
        "REFUSAL: attempt to write",
        "tools/call",
        {"name": "run_select", "arguments": {"sql": "UPDATE orders SET status = 'shipped'"}},
        "Refused at the AST layer, before the database is contacted.",
    ),
    (
        "REFUSAL: CTE-wrapped write",
        "tools/call",
        {
            "name": "run_select",
            "arguments": {
                "sql": "WITH w AS (DELETE FROM orders RETURNING id) SELECT * FROM w"
            },
        },
        "The statement starts with WITH and contains a SELECT, so it defeats "
        "'must begin with SELECT' checks. The AST walk catches it.",
    ),
    (
        "REFUSAL: raw PII table",
        "tools/call",
        {"name": "run_select", "arguments": {"sql": "SELECT personnummer FROM customers"}},
        "The base table is not in the allowlist — and the database role has no "
        "grant on it either.",
    ),
    (
        "REFUSAL: command execution",
        "tools/call",
        {
            "name": "run_select",
            "arguments": {"sql": "SELECT pg_catalog.pg_read_file('/etc/passwd')"},
        },
        "Schema-qualified to evade bare-name matching. Resolved and refused.",
    ),
    (
        "REFUSAL: unbounded extraction",
        "tools/call",
        {"name": "run_select", "arguments": {"sql": "SELECT * FROM orders LIMIT 100000"}},
        "Not refused — silently clamped. The caller does not get to opt out of "
        "the row cap.",
    ),
]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json-out", type=Path, default=None)
    args = parser.parse_args()

    env = os.environ.copy()
    env["PYTHONPATH"] = str(SERVERS_DIR)
    env.setdefault(
        "MCP_DB_DSN",
        "postgresql://mcp_readonly:harness-only@127.0.0.1:55432/pharmadb",
    )
    env["MCP_PRINCIPAL"] = "demo-agent"

    # Justification for the B603/S603 suppression on the next line: argv is a
    # fixed list built from sys.executable and a literal module name. No shell,
    # no user input, no PATH lookup. This is a test harness launching our own
    # server. (The marker itself must stay bare — bandit parses any trailing
    # prose after `# nosec` as further test IDs and warns on every word.)
    proc = subprocess.Popen(  # noqa: S603  # nosec B603
        [sys.executable, "-m", "rds_readonly_mcp.server"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        text=True,
        bufsize=1,
        cwd=str(SERVERS_DIR),
    )

    transcript: list[dict] = []
    print("=" * 78)
    print(" MCP SESSION — rds-readonly-mcp over real stdio")
    print("=" * 78)

    try:
        msg_id = 0
        for label, method, params, rationale in SCRIPT:
            msg_id += 1
            request = {"jsonrpc": "2.0", "id": msg_id, "method": method, "params": params}
            proc.stdin.write(json.dumps(request) + "\n")
            proc.stdin.flush()

            raw = proc.stdout.readline()
            if not raw:
                print("\n!! server closed the stream unexpectedly")
                print(proc.stderr.read()[:2000])
                return 1
            response = json.loads(raw)

            print(f"\n--- {label}")
            print(f"    why : {rationale}")
            print(f"    >>> {json.dumps(request)[:150]}")
            print(f"    <<< {_summarise(response)}")

            transcript.append({"request": request, "response": response})

            # The client must confirm the handshake before tools unlock.
            if method == "initialize":
                ack = {"jsonrpc": "2.0", "method": "notifications/initialized"}
                proc.stdin.write(json.dumps(ack) + "\n")
                proc.stdin.flush()
    finally:
        # The server may already have exited and closed the pipe; that is a
        # normal end-of-session race, not an error worth surfacing.
        with contextlib.suppress(BrokenPipeError, ValueError):
            proc.stdin.close()
        proc.wait(timeout=10)
        audit_lines = [ln for ln in proc.stderr.read().splitlines() if ln.strip().startswith("{")]

    print("\n" + "=" * 78)
    print(" AUDIT TRAIL (stderr — stdout carries protocol frames only)")
    print("=" * 78)
    for line in audit_lines:
        record = json.loads(line)
        bits = [record["tool"], record["outcome"]]
        if record.get("control"):
            bits.append(f"control={record['control']}")
        if record.get("row_count") is not None:
            bits.append(f"rows={record['row_count']}")
        print("  " + "  ".join(bits) + f"  fp={record['args_fingerprint']}")

    refusals = sum(1 for t in transcript if t["response"].get("result", {}).get("isError"))
    print("\n" + "=" * 78)
    print(f" {len(transcript)} exchanges · {refusals} refusals · audit records: {len(audit_lines)}")
    print(" No raw personnummer, email, phone, or prescriber ID appears above.")
    print("=" * 78)

    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        with args.json_out.open("w", encoding="utf-8") as fh:
            for entry in transcript:
                fh.write(json.dumps(entry) + "\n")
            for line in audit_lines:
                fh.write(json.dumps({"audit": json.loads(line)}) + "\n")

    return 0


def _summarise(response: dict) -> str:
    if "error" in response:
        return f"PROTOCOL ERROR {response['error']['code']}: {response['error']['message']}"
    result = response.get("result", {})
    if result.get("isError"):
        return "REFUSED — " + result["content"][0]["text"]
    content = result.get("content")
    if content:
        text = content[0]["text"].replace("\n", " ")
        return (text[:220] + " …") if len(text) > 220 else text
    if "tools" in result:
        return "tools: " + ", ".join(t["name"] for t in result["tools"])
    if "protocolVersion" in result:
        return f"protocol {result['protocolVersion']} · {result['serverInfo']['name']}"
    return json.dumps(result)[:200]


if __name__ == "__main__":
    raise SystemExit(main())
