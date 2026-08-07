"""JSON-RPC 2.0 and MCP error taxonomy.

Security note: error bodies are a classic leak channel. Every error raised here
carries a `public_message` (safe to return over the wire) and an optional
`internal_detail` (audit log only, never serialised into a response). Server
code must never put a driver exception string straight into a JSON-RPC error —
Postgres error text routinely echoes the offending query, which for a
data-access server means echoing whatever the caller was probing for.
"""

from __future__ import annotations

# --- JSON-RPC 2.0 reserved codes (spec section 5.1) ---
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603

# --- Implementation-defined range (-32000 to -32099) ---
SERVER_NOT_INITIALIZED = -32002
REQUEST_TOO_LARGE = -32003
GUARDRAIL_VIOLATION = -32010
UPSTREAM_UNAVAILABLE = -32011


class ProtocolError(Exception):
    """An error that is safe to serialise into a JSON-RPC error response."""

    def __init__(
        self,
        code: int,
        public_message: str,
        *,
        internal_detail: str | None = None,
        data: dict | None = None,
    ) -> None:
        super().__init__(public_message)
        self.code = code
        self.public_message = public_message
        # Deliberately NOT serialised. Audit sink only.
        self.internal_detail = internal_detail
        self.data = data

    def to_wire(self) -> dict:
        body: dict = {"code": self.code, "message": self.public_message}
        if self.data:
            body["data"] = self.data
        return body


class GuardrailViolation(ProtocolError):
    """A request was refused by a security control, not by a bug.

    Raised on: non-SELECT statements, blocked functions, row/byte cap breaches,
    unmask attempts without the capability. These are expected, logged at WARN,
    and returned to the caller as a tool error rather than a transport error —
    the model needs to see *that* it was refused so it can change approach.
    """

    def __init__(self, reason: str, *, control: str, internal_detail: str | None = None) -> None:
        super().__init__(
            GUARDRAIL_VIOLATION,
            f"Refused by guardrail [{control}]: {reason}",
            internal_detail=internal_detail,
            data={"control": control},
        )
        self.control = control
        self.reason = reason
