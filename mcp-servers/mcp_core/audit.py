"""Structured audit logging for every tool invocation.

This is the evidence artifact. GDPR Art. 30 requires a record of processing
activities; for an AI agent touching Art. 9 health data, "which agent read
which rows, when, and how many" is exactly that record.

Design rules, learned the hard way:

  * Audit goes to **stderr or a file, never stdout** — stdout is the JSON-RPC
    transport. One stray print corrupts the protocol stream.
  * Arguments are **hashed, not stored**. A SQL predicate can itself contain
    personal data (`WHERE personnummer = '...'`). Logging raw arguments would
    turn the audit log into a second copy of the data we are protecting.
  * The log records the *decision* (allowed / refused / errored) and the
    control that made it, so a reviewer can answer "was this refused, and by
    what?" without re-running anything.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, TextIO


def _hash_args(arguments: dict[str, Any]) -> str:
    """Stable, non-reversible fingerprint of tool arguments.

    sort_keys makes it deterministic so the same call fingerprints identically
    across runs — which is what makes "this agent ran the same query 400 times"
    a detectable pattern.
    """
    canonical = json.dumps(arguments, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


@dataclass
class AuditRecord:
    tool: str
    outcome: str  # "allowed" | "refused" | "error"
    args_fingerprint: str
    duration_ms: float
    principal: str
    session_id: str
    row_count: int | None = None
    bytes_returned: int | None = None
    control: str | None = None  # which guardrail refused, if any
    reason: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> str:
        body = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "tool": self.tool,
            "outcome": self.outcome,
            "args_fingerprint": self.args_fingerprint,
            "duration_ms": round(self.duration_ms, 2),
            "principal": self.principal,
            "session_id": self.session_id,
        }
        for key in ("row_count", "bytes_returned", "control", "reason"):
            value = getattr(self, key)
            if value is not None:
                body[key] = value
        body.update(self.extra)
        return json.dumps(body, separators=(",", ":"))


class AuditLog:
    """Append-only JSONL sink. Never writes to stdout."""

    def __init__(self, stream: TextIO | None = None, *, principal: str | None = None) -> None:
        # Default to stderr precisely because stdout is the transport.
        self._stream = stream or sys.stderr
        self._principal = principal or os.environ.get("MCP_PRINCIPAL", "unknown")
        self._session_id = uuid.uuid4().hex[:12]

    @property
    def session_id(self) -> str:
        return self._session_id

    def record(
        self,
        *,
        tool: str,
        outcome: str,
        arguments: dict[str, Any],
        duration_ms: float,
        **kwargs: Any,
    ) -> AuditRecord:
        rec = AuditRecord(
            tool=tool,
            outcome=outcome,
            args_fingerprint=_hash_args(arguments),
            duration_ms=duration_ms,
            principal=self._principal,
            session_id=self._session_id,
            **kwargs,
        )
        self._stream.write(rec.to_json() + "\n")
        self._stream.flush()
        return rec
