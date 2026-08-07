"""mcp_core — a from-scratch Model Context Protocol server implementation.

Zero runtime dependencies, by design. A security repository that argues for
supply-chain discipline should not pull forty transitive packages to parse
JSON; the entire trust surface here is auditable in one sitting.

**Stated plainly:** hand-writing the protocol is a *demonstration* choice. It
proves the wire format and its trust boundaries are understood rather than
assumed. Production systems should use the official MCP SDK, which is
maintained, spec-tracked, and tested far more broadly than this. The repository
makes that trade-off explicit rather than implying the hand-rolled version is
the better engineering choice.
"""

from .audit import AuditLog, AuditRecord
from .errors import GuardrailViolation, ProtocolError
from .jsonrpc import Request, error_response, parse_message, success_response
from .server import PROTOCOL_VERSION, MCPServer, Tool
from .transport import MAX_FRAME_BYTES, StdioTransport

__all__ = [
    "MAX_FRAME_BYTES",
    "PROTOCOL_VERSION",
    "AuditLog",
    "AuditRecord",
    "GuardrailViolation",
    "MCPServer",
    "ProtocolError",
    "Request",
    "StdioTransport",
    "Tool",
    "error_response",
    "parse_message",
    "success_response",
]
