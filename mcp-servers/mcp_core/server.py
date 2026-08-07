"""MCP server lifecycle and tool dispatch.

Implements the subset of the Model Context Protocol this repo needs:

    initialize                -> capability negotiation, protocol version
    notifications/initialized -> client confirms; server unlocks
    tools/list                -> tool catalogue with JSON Schema
    tools/call                -> invoke one tool

Two distinctions carry the security weight, and both are easy to get wrong:

**Protocol errors vs tool errors.** A malformed frame is a JSON-RPC *error
response*. A guardrail refusal is a successful JSON-RPC response whose result
carries `isError: true`. That is not pedantry — the model only sees content
blocks. If a refusal is returned as a transport error the agent sees a broken
connection and retries blindly; as a tool error it reads "refused because X"
and changes approach. Refusals must be legible to the model.

**Lifecycle ordering is authorisation.** `tools/call` before `initialize` is
refused. Capability negotiation is where a client declares what it supports;
honouring calls before it completes means acting on unnegotiated assumptions.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .audit import AuditLog
from .errors import (
    INTERNAL_ERROR,
    INVALID_PARAMS,
    METHOD_NOT_FOUND,
    SERVER_NOT_INITIALIZED,
    GuardrailViolation,
    ProtocolError,
)
from .jsonrpc import Request, error_response, parse_message, success_response

# The MCP revision this server implements. Advertised during initialize; a
# client asking for a different revision is told what we actually speak rather
# than being silently downgraded.
PROTOCOL_VERSION = "2025-06-18"


@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    input_schema: dict[str, Any]
    handler: Callable[[dict[str, Any]], Any]

    def to_wire(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
        }


class MCPServer:
    def __init__(
        self,
        name: str,
        version: str = "0.1.0",
        *,
        audit: AuditLog | None = None,
    ) -> None:
        self.name = name
        self.version = version
        self._tools: dict[str, Tool] = {}
        self._initialized = False
        self.audit = audit or AuditLog()

    # --- registration ---

    def tool(
        self, name: str, description: str, input_schema: dict[str, Any]
    ) -> Callable[[Callable], Callable]:
        def decorator(fn: Callable[[dict[str, Any]], Any]) -> Callable:
            if name in self._tools:
                raise ValueError(f"duplicate tool registration: {name}")
            self._tools[name] = Tool(name, description, input_schema, fn)
            return fn

        return decorator

    # --- dispatch ---

    def handle_frame(self, raw: str) -> str | None:
        """Parse and dispatch one frame. Returns a frame to send, or None."""
        try:
            request = parse_message(raw)
        except ProtocolError as exc:
            # id is unknown at this point; the spec permits a null id here.
            return error_response(None, exc)

        try:
            result = self._dispatch(request)
        except ProtocolError as exc:
            if request.is_notification:
                return None
            return error_response(request.id, exc)
        except Exception as exc:  # noqa: BLE001 — last-resort boundary
            # Never leak an internal exception string to the client. The detail
            # is preserved for the audit sink only.
            wrapped = ProtocolError(
                INTERNAL_ERROR, "Internal server error", internal_detail=repr(exc)
            )
            if request.is_notification:
                return None
            return error_response(request.id, wrapped)

        if request.is_notification:
            return None
        return success_response(request.id, result)

    def _dispatch(self, request: Request) -> Any:
        method = request.method

        if method == "initialize":
            return self._handle_initialize(request.params)

        if method == "notifications/initialized":
            self._initialized = True
            return None

        # Everything below requires a completed handshake.
        if not self._initialized:
            raise ProtocolError(
                SERVER_NOT_INITIALIZED,
                "Server not initialized; send 'initialize' first",
            )

        if method == "tools/list":
            return {"tools": [t.to_wire() for t in self._tools.values()]}

        if method == "tools/call":
            return self._handle_tools_call(request.params)

        if method == "ping":
            return {}

        raise ProtocolError(METHOD_NOT_FOUND, f"Unknown method: {method}")

    def _handle_initialize(self, params: dict[str, Any]) -> dict[str, Any]:
        requested = params.get("protocolVersion")
        return {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": self.name, "version": self.version},
            # Surfaced so a mismatch is visible to the client rather than
            # silently tolerated.
            "_negotiation": {
                "requested": requested,
                "matched": requested == PROTOCOL_VERSION,
            },
        }

    def _handle_tools_call(self, params: dict[str, Any]) -> dict[str, Any]:
        name = params.get("name")
        if not isinstance(name, str):
            raise ProtocolError(INVALID_PARAMS, "'name' is required and must be a string")

        arguments = params.get("arguments", {})
        if not isinstance(arguments, dict):
            raise ProtocolError(INVALID_PARAMS, "'arguments' must be an object")

        tool = self._tools.get(name)
        if tool is None:
            # Unknown tool is a protocol-level error: the client asked for
            # something outside the advertised catalogue.
            raise ProtocolError(METHOD_NOT_FOUND, f"Unknown tool: {name}")

        self._validate_required(tool, arguments)

        started = time.perf_counter()
        try:
            result = tool.handler(arguments)
        except GuardrailViolation as gv:
            elapsed = (time.perf_counter() - started) * 1000
            self.audit.record(
                tool=name,
                outcome="refused",
                arguments=arguments,
                duration_ms=elapsed,
                control=gv.control,
                reason=gv.reason,
            )
            # Tool error, NOT a transport error — the model must be able to read
            # the refusal and adapt.
            return {
                "content": [{"type": "text", "text": gv.public_message}],
                "isError": True,
            }
        except Exception as exc:  # noqa: BLE001
            elapsed = (time.perf_counter() - started) * 1000
            self.audit.record(
                tool=name,
                outcome="error",
                arguments=arguments,
                duration_ms=elapsed,
                reason=type(exc).__name__,
            )
            # Generic text: a driver exception routinely echoes the offending
            # query, which for a data-access server means echoing the probe.
            return {
                "content": [{"type": "text", "text": "Tool execution failed."}],
                "isError": True,
            }

        elapsed = (time.perf_counter() - started) * 1000
        text, meta = _render(result)
        self.audit.record(
            tool=name,
            outcome="allowed",
            arguments=arguments,
            duration_ms=elapsed,
            row_count=meta.get("row_count"),
            bytes_returned=len(text.encode("utf-8")),
        )
        return {"content": [{"type": "text", "text": text}], "isError": False}

    @staticmethod
    def _validate_required(tool: Tool, arguments: dict[str, Any]) -> None:
        """Minimal schema enforcement: required keys must be present.

        Deliberately shallow. Deep JSON Schema validation would need a
        dependency, and the real authorisation decisions happen in the tool's
        own guardrail layer — not here. This catches shape errors early so the
        guardrail layer can assume its inputs exist.
        """
        required = tool.input_schema.get("required", [])
        missing = [key for key in required if key not in arguments]
        if missing:
            raise ProtocolError(
                INVALID_PARAMS, f"Missing required argument(s): {', '.join(sorted(missing))}"
            )

    # --- run loop ---

    def serve(self, transport) -> None:  # noqa: ANN001 — duck-typed for tests
        """Run until EOF.

        A transport-level refusal (oversized frame) is answered and survived;
        it must not end the session, or one bad line becomes a denial of
        service. See `transport.Frame`.
        """
        for frame in transport.read_frames():
            if not frame.ok:
                transport.write(error_response(None, frame.error))
                continue
            response = self.handle_frame(frame.raw)
            if response is not None:
                transport.write(response)


def _render(result: Any) -> tuple[str, dict[str, Any]]:
    """Turn a handler return value into MCP text content plus metadata."""
    import json

    if isinstance(result, str):
        return result, {}
    if isinstance(result, dict) and "rows" in result:
        rows = result["rows"]
        return json.dumps(result, default=str, indent=2), {"row_count": len(rows)}
    return json.dumps(result, default=str, indent=2), {}
