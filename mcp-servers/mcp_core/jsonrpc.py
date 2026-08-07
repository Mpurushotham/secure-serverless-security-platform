"""JSON-RPC 2.0 message layer, written from scratch.

Scope is deliberately narrow — MCP uses a strict subset of JSON-RPC 2.0:

  * Requests carry an `id` and expect exactly one response.
  * Notifications carry no `id` and MUST NOT be responded to.
  * Batch arrays are NOT part of MCP and are rejected (see `parse_message`).

Rejecting batches is a security decision, not a laziness one: batching lets a
caller amortise a probe across one frame and complicates per-call authorisation
and audit accounting. One frame, one decision, one audit record.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from .errors import INVALID_PARAMS, INVALID_REQUEST, PARSE_ERROR, ProtocolError

JSONRPC_VERSION = "2.0"


@dataclass(frozen=True)
class Request:
    """An inbound call. `id is None` marks a notification (no reply owed)."""

    method: str
    params: dict[str, Any]
    id: str | int | None = None

    @property
    def is_notification(self) -> bool:
        return self.id is None


def parse_message(raw: str) -> Request:
    """Parse one JSON-RPC frame into a Request, or raise ProtocolError."""
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ProtocolError(
            PARSE_ERROR, "Invalid JSON", internal_detail=f"{exc.msg} at pos {exc.pos}"
        ) from exc

    # MCP is single-message; a JSON-RPC batch array is a valid JSON-RPC 2.0
    # construct but not a valid MCP frame. Refuse it explicitly rather than
    # silently processing element zero.
    if isinstance(payload, list):
        raise ProtocolError(INVALID_REQUEST, "Batch requests are not supported")

    if not isinstance(payload, dict):
        raise ProtocolError(INVALID_REQUEST, "Request must be a JSON object")

    if payload.get("jsonrpc") != JSONRPC_VERSION:
        raise ProtocolError(INVALID_REQUEST, "Missing or unsupported 'jsonrpc' version")

    method = payload.get("method")
    if not isinstance(method, str) or not method:
        raise ProtocolError(INVALID_REQUEST, "Missing or invalid 'method'")

    params = payload.get("params", {})
    if params is None:
        params = {}
    if not isinstance(params, dict):
        # MCP always uses by-name params. Positional arrays are legal JSON-RPC
        # but would make argument validation ambiguous — and ambiguity in
        # argument binding is how the wrong value reaches a guardrail check.
        raise ProtocolError(INVALID_PARAMS, "'params' must be an object (by-name only)")

    msg_id = payload.get("id")
    if msg_id is not None and not isinstance(msg_id, (str, int)):
        raise ProtocolError(INVALID_REQUEST, "'id' must be a string or number")

    return Request(method=method, params=params, id=msg_id)


def success_response(msg_id: str | int, result: Any) -> str:
    return json.dumps({"jsonrpc": JSONRPC_VERSION, "id": msg_id, "result": result})


def error_response(msg_id: str | int | None, error: ProtocolError) -> str:
    # A null id is legal when the failure happened before the id could be read
    # (parse errors). The spec requires we still answer.
    return json.dumps({"jsonrpc": JSONRPC_VERSION, "id": msg_id, "error": error.to_wire()})
