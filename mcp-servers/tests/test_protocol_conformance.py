"""Protocol conformance for mcp_core.

Protocol bugs are security bugs. A frame the server misparses, a lifecycle step
it honours out of order, or an internal exception it echoes back are all
authorisation or disclosure failures wearing a parsing costume. These tests
exist to make that class of bug loud.
"""

from __future__ import annotations

import io
import json

import pytest

from mcp_core import PROTOCOL_VERSION, AuditLog, GuardrailViolation, MCPServer, StdioTransport
from mcp_core.errors import (
    INTERNAL_ERROR,
    INVALID_PARAMS,
    INVALID_REQUEST,
    METHOD_NOT_FOUND,
    PARSE_ERROR,
    REQUEST_TOO_LARGE,
    SERVER_NOT_INITIALIZED,
)
from mcp_core.transport import MAX_FRAME_BYTES

ECHO_SCHEMA = {
    "type": "object",
    "properties": {"msg": {"type": "string"}},
    "required": ["msg"],
}


def build_server(*, initialized: bool = True) -> MCPServer:
    server = MCPServer("test-server", audit=AuditLog(stream=io.StringIO()))

    @server.tool("echo", "Echo a message back", ECHO_SCHEMA)
    def _echo(args):
        return args["msg"]

    @server.tool("boom", "Always raises", {"type": "object", "properties": {}})
    def _boom(args):
        raise RuntimeError("SECRET-CONNECTION-STRING-postgres://user:pw@host/db")

    @server.tool("refuse", "Always refused by a guardrail", {"type": "object", "properties": {}})
    def _refuse(args):
        raise GuardrailViolation("write statements are not permitted", control="sql-ast")

    if initialized:
        server.handle_frame(frame("initialize", {"protocolVersion": PROTOCOL_VERSION}, mid=1))
        server.handle_frame(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}))
    return server


def frame(method: str, params: dict | None = None, mid: int | str | None = 1) -> str:
    body: dict = {"jsonrpc": "2.0", "method": method}
    if mid is not None:
        body["id"] = mid
    if params is not None:
        body["params"] = params
    return json.dumps(body)


def err_code(raw: str) -> int:
    return json.loads(raw)["error"]["code"]


# --- Frame parsing ---------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("{not json", PARSE_ERROR),
        ("", PARSE_ERROR),
        ('"a bare string"', INVALID_REQUEST),
        ("42", INVALID_REQUEST),
        ("null", INVALID_REQUEST),
        # A JSON-RPC batch is valid JSON-RPC but not valid MCP. Refusing it
        # keeps one frame == one authorisation decision == one audit record.
        ('[{"jsonrpc":"2.0","id":1,"method":"ping"}]', INVALID_REQUEST),
        ('{"id":1,"method":"ping"}', INVALID_REQUEST),  # missing jsonrpc
        ('{"jsonrpc":"1.0","id":1,"method":"ping"}', INVALID_REQUEST),
        ('{"jsonrpc":"2.0","id":1}', INVALID_REQUEST),  # missing method
        ('{"jsonrpc":"2.0","id":1,"method":123}', INVALID_REQUEST),
        ('{"jsonrpc":"2.0","id":1,"method":""}', INVALID_REQUEST),
        ('{"jsonrpc":"2.0","id":{"a":1},"method":"ping"}', INVALID_REQUEST),
        # Positional params are legal JSON-RPC, ambiguous for argument binding.
        ('{"jsonrpc":"2.0","id":1,"method":"ping","params":[1,2]}', INVALID_PARAMS),
        ('{"jsonrpc":"2.0","id":1,"method":"ping","params":"x"}', INVALID_PARAMS),
    ],
)
def test_malformed_frames_are_rejected(raw: str, expected: int) -> None:
    assert err_code(build_server().handle_frame(raw)) == expected


def test_parse_error_still_answers_with_null_id() -> None:
    """The id is unknown before parsing; the spec still requires a response."""
    assert json.loads(build_server().handle_frame("{oops"))["id"] is None


# --- Lifecycle ordering is authorisation -----------------------------------


@pytest.mark.parametrize("method", ["tools/list", "tools/call", "ping"])
def test_calls_before_initialize_are_refused(method: str) -> None:
    server = build_server(initialized=False)
    assert err_code(server.handle_frame(frame(method, {"name": "echo"}))) == SERVER_NOT_INITIALIZED


def test_initialize_advertises_protocol_and_server_info() -> None:
    server = build_server(initialized=False)
    result = json.loads(server.handle_frame(frame("initialize", {"protocolVersion": "1999-01-01"})))[
        "result"
    ]
    assert result["protocolVersion"] == PROTOCOL_VERSION
    assert result["serverInfo"]["name"] == "test-server"
    assert "tools" in result["capabilities"]
    # A client asking for another revision is told, not silently downgraded.
    assert result["_negotiation"]["matched"] is False


def test_unknown_method_and_unknown_tool() -> None:
    server = build_server()
    assert err_code(server.handle_frame(frame("does/not/exist"))) == METHOD_NOT_FOUND
    call = frame("tools/call", {"name": "not_a_tool", "arguments": {}})
    assert err_code(server.handle_frame(call)) == METHOD_NOT_FOUND


# --- Notifications ---------------------------------------------------------


def test_notifications_are_never_answered() -> None:
    server = build_server()
    assert server.handle_frame(json.dumps({"jsonrpc": "2.0", "method": "ping"})) is None
    # Even when the method is bogus — a reply would violate the spec and let a
    # client use notifications as an oracle.
    assert server.handle_frame(json.dumps({"jsonrpc": "2.0", "method": "nope"})) is None


# --- tools/call argument handling ------------------------------------------


@pytest.mark.parametrize(
    "params",
    [
        {},  # no name
        {"name": 123},
        {"name": "echo", "arguments": "not-an-object"},
        {"name": "echo", "arguments": {}},  # missing required 'msg'
    ],
)
def test_bad_tool_call_params(params: dict) -> None:
    assert err_code(build_server().handle_frame(frame("tools/call", params))) == INVALID_PARAMS


def test_successful_call_returns_content_block() -> None:
    raw = build_server().handle_frame(
        frame("tools/call", {"name": "echo", "arguments": {"msg": "hello"}})
    )
    result = json.loads(raw)["result"]
    assert result["isError"] is False
    assert result["content"] == [{"type": "text", "text": "hello"}]


# --- The distinction that matters: tool errors vs protocol errors ----------


def test_guardrail_refusal_is_a_tool_error_not_a_transport_error() -> None:
    """A refusal must be legible to the model, not surface as a broken call.

    If a guardrail refusal came back as a JSON-RPC error the agent would see a
    transport failure and retry blindly. As an isError content block it reads
    "refused because X" and can change approach.
    """
    raw = build_server().handle_frame(frame("tools/call", {"name": "refuse", "arguments": {}}))
    payload = json.loads(raw)
    assert "error" not in payload
    result = payload["result"]
    assert result["isError"] is True
    text = result["content"][0]["text"]
    assert "sql-ast" in text and "not permitted" in text


def test_internal_exception_never_leaks_its_message() -> None:
    """Driver exceptions routinely echo the offending query or DSN."""
    raw = build_server().handle_frame(frame("tools/call", {"name": "boom", "arguments": {}}))
    result = json.loads(raw)["result"]
    assert result["isError"] is True
    assert result["content"][0]["text"] == "Tool execution failed."
    assert "SECRET-CONNECTION-STRING" not in raw
    assert "postgres://" not in raw


def test_unhandled_dispatch_error_is_wrapped(monkeypatch: pytest.MonkeyPatch) -> None:
    server = build_server()
    monkeypatch.setattr(
        server, "_dispatch", lambda _r: (_ for _ in ()).throw(ValueError("leak-me-please"))
    )
    raw = server.handle_frame(frame("ping"))
    assert err_code(raw) == INTERNAL_ERROR
    assert "leak-me-please" not in raw


# --- Registration ----------------------------------------------------------


def test_duplicate_tool_registration_is_rejected() -> None:
    server = MCPServer("dup", audit=AuditLog(stream=io.StringIO()))
    server.tool("t", "d", {"type": "object"})(lambda a: "x")
    with pytest.raises(ValueError, match="duplicate"):
        server.tool("t", "d", {"type": "object"})(lambda a: "y")


# --- Transport -------------------------------------------------------------


def test_transport_refuses_oversized_frame() -> None:
    oversized = "x" * (MAX_FRAME_BYTES + 10)
    transport = StdioTransport(stdin=io.StringIO(oversized + "\n"), stdout=io.StringIO())
    frames = list(transport.read_frames())
    assert len(frames) == 1
    assert not frames[0].ok
    assert frames[0].error.code == REQUEST_TOO_LARGE


def test_oversized_frame_is_survivable_not_fatal() -> None:
    """One bad line must not tear down the session.

    Raising out of the generator would close it permanently — denial of service
    via a single oversized frame. The refusal is carried as data instead, and
    the stream stays aligned so the tail of the huge line is never parsed as a
    fresh request.
    """
    stream = io.StringIO("y" * (MAX_FRAME_BYTES + 10) + "\n" + '{"jsonrpc":"2.0"}' + "\n")
    frames = list(StdioTransport(stdin=stream, stdout=io.StringIO()).read_frames())
    assert len(frames) == 2
    assert frames[0].error.code == REQUEST_TOO_LARGE
    assert frames[1].raw == '{"jsonrpc":"2.0"}'


def test_server_answers_oversized_frame_and_keeps_serving() -> None:
    stdout = io.StringIO()
    server = build_server()
    payload = frame("tools/call", {"name": "echo", "arguments": {"msg": "still-alive"}})
    stream = io.StringIO("z" * (MAX_FRAME_BYTES + 10) + "\n" + payload + "\n")
    server.serve(StdioTransport(stdin=stream, stdout=stdout))

    lines = [json.loads(line) for line in stdout.getvalue().splitlines()]
    assert lines[0]["error"]["code"] == REQUEST_TOO_LARGE
    assert lines[1]["result"]["content"][0]["text"] == "still-alive"


def test_transport_skips_blank_lines() -> None:
    transport = StdioTransport(stdin=io.StringIO('\n\n{"a":1}\n\n'), stdout=io.StringIO())
    assert [f.raw for f in transport.read_frames()] == ['{"a":1}']


# --- Audit -----------------------------------------------------------------


def test_audit_never_writes_to_stdout() -> None:
    """stdout is the transport. One stray write corrupts the protocol stream."""
    stdout = io.StringIO()
    audit_sink = io.StringIO()
    server = MCPServer("audit-test", audit=AuditLog(stream=audit_sink))
    server.tool("echo", "e", ECHO_SCHEMA)(lambda a: a["msg"])
    server.handle_frame(frame("initialize", {"protocolVersion": PROTOCOL_VERSION}))
    server.handle_frame(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}))

    transport = StdioTransport(
        stdin=io.StringIO(frame("tools/call", {"name": "echo", "arguments": {"msg": "hi"}}) + "\n"),
        stdout=stdout,
    )
    server.serve(transport)

    assert audit_sink.getvalue().strip(), "audit record should have been written"
    for line in stdout.getvalue().splitlines():
        json.loads(line)["result"]  # stdout contains protocol frames only


def test_audit_fingerprints_arguments_rather_than_storing_them() -> None:
    """A SQL predicate can itself contain personal data."""
    sink = io.StringIO()
    server = MCPServer("pii", audit=AuditLog(stream=sink))
    server.tool("echo", "e", ECHO_SCHEMA)(lambda a: "ok")
    server.handle_frame(frame("initialize", {"protocolVersion": PROTOCOL_VERSION}))
    server.handle_frame(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}))
    server.handle_frame(
        frame("tools/call", {"name": "echo", "arguments": {"msg": "19850101-1234"}})
    )

    written = sink.getvalue()
    assert "19850101-1234" not in written
    assert json.loads(written.strip())["args_fingerprint"]


def test_audit_records_the_refusing_control() -> None:
    sink = io.StringIO()
    server = MCPServer("refusal", audit=AuditLog(stream=sink))
    server.tool("r", "r", {"type": "object"})(
        lambda a: (_ for _ in ()).throw(GuardrailViolation("nope", control="row-cap"))
    )
    server.handle_frame(frame("initialize", {"protocolVersion": PROTOCOL_VERSION}))
    server.handle_frame(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}))
    server.handle_frame(frame("tools/call", {"name": "r", "arguments": {}}))

    record = json.loads(sink.getvalue().strip())
    assert record["outcome"] == "refused"
    assert record["control"] == "row-cap"
