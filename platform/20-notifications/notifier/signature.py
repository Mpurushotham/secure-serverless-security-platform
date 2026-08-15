"""Slack request signature verification.

Any endpoint Slack calls is a public HTTPS endpoint, and an unverified one will
be found and driven by someone other than Slack. Two properties matter and both
are easy to get subtly wrong:

**Constant-time comparison.** A naive `==` on the signature leaks how many
leading bytes matched, which is enough to forge one a byte at a time.

**A replay window.** A valid signature stays valid forever without one, so a
captured request can be replayed indefinitely — reopening an incident channel,
re-acknowledging an alert, or whatever the interactive handler does.
"""

from __future__ import annotations

import hashlib
import hmac
import time

MAX_AGE_SECONDS = 60 * 5


class InvalidSignature(Exception):
    """Raised on any verification failure. The caller must not proceed."""


def verify(
    signing_secret: str,
    timestamp: str,
    body: str,
    signature: str,
    now: float | None = None,
) -> None:
    """Raise unless the request genuinely came from Slack, recently."""
    try:
        sent_at = int(timestamp)
    except (TypeError, ValueError) as exc:
        raise InvalidSignature("timestamp is not an integer") from exc

    current = time.time() if now is None else now
    if abs(current - sent_at) > MAX_AGE_SECONDS:
        raise InvalidSignature(
            f"timestamp is {abs(current - sent_at):.0f}s old; replay window is {MAX_AGE_SECONDS}s"
        )

    basestring = f"v0:{timestamp}:{body}"
    expected = (
        "v0="
        + hmac.new(
            signing_secret.encode("utf-8"), basestring.encode("utf-8"), hashlib.sha256
        ).hexdigest()
    )

    if not hmac.compare_digest(expected, signature):
        raise InvalidSignature("signature mismatch")
