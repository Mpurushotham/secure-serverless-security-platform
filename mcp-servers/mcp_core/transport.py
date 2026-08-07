"""Newline-delimited JSON framing over stdio.

MCP's stdio transport is one JSON object per line. Two security properties are
enforced here rather than upstream, because by the time a frame reaches the
JSON parser it is too late:

  1. **Maximum frame size.** An unbounded read against a hostile or buggy client
     is a memory-exhaustion primitive. We cap the frame and refuse oversized
     input without ever buffering it in full.
  2. **stdout is reserved.** Anything that is not a protocol response goes to
     stderr. `write()` is the only sanctioned path to stdout, which makes "who
     wrote to the transport" a one-line grep during review.

**Why `read_frames()` yields a `Frame` rather than raising:** raising out of a
generator closes it permanently, so a single oversized frame would tear down
the whole session — denial of service via one bad line. A malformed frame must
be *refused and survived*, not fatal. The error is carried as data so the
server can answer it and keep serving. The conformance suite pins this.
"""

from __future__ import annotations

import sys
from collections.abc import Iterator
from dataclasses import dataclass
from typing import TextIO

from .errors import REQUEST_TOO_LARGE, ProtocolError

# 4 MiB. Large enough for any legitimate tool result, small enough that a
# malicious client cannot exhaust memory one frame at a time.
MAX_FRAME_BYTES = 4 * 1024 * 1024


@dataclass(frozen=True)
class Frame:
    """One unit off the wire: either raw text, or a refusal to be answered."""

    raw: str | None = None
    error: ProtocolError | None = None

    @property
    def ok(self) -> bool:
        return self.error is None


class StdioTransport:
    def __init__(self, stdin: TextIO | None = None, stdout: TextIO | None = None) -> None:
        self._stdin = stdin or sys.stdin
        self._stdout = stdout or sys.stdout

    def read_frames(self) -> Iterator[Frame]:
        """Yield frames until EOF. Oversized lines are refused, not fatal."""
        while True:
            chunks: list[str] = []
            size = 0
            oversized = False

            while True:
                ch = self._stdin.read(1)
                if ch == "":  # EOF
                    if chunks and not oversized:
                        line = "".join(chunks).strip()
                        if line:
                            yield Frame(raw=line)
                    return
                if ch == "\n":
                    break
                if oversized:
                    # Already over budget: keep consuming to realign the stream
                    # but stop accumulating. Without this the tail of the
                    # oversized line would be parsed as a fresh request.
                    continue
                size += len(ch.encode("utf-8"))
                if size > MAX_FRAME_BYTES:
                    oversized = True
                    chunks.clear()
                    continue
                chunks.append(ch)

            if oversized:
                yield Frame(
                    error=ProtocolError(
                        REQUEST_TOO_LARGE, f"Frame exceeds {MAX_FRAME_BYTES} bytes"
                    )
                )
                continue

            line = "".join(chunks).strip()
            if line:
                yield Frame(raw=line)

    def write(self, payload: str) -> None:
        """The only sanctioned write to stdout."""
        self._stdout.write(payload + "\n")
        self._stdout.flush()
