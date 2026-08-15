"""The single redaction layer between a finding and anything outbound.

Sending to Slack is publishing. A Slack workspace has different membership,
different retention and different export controls from the AWS account the
finding describes, and a message posted there is a copy of that information
living somewhere nobody modelled.

So the rule this module enforces is: **an alert carries a pointer, never a
payload.** Finding id, severity, a console deep link, a runbook path — enough
for a responder to go and look under the access controls that already exist.
Not the bucket name, not the ARN, not the query, and never a row.

Two design decisions worth defending:

**One layer, two transports.** Alertmanager and the SNS Lambda both call this.
The alternative — Alertmanager's own `slack_configs` for one path and a Lambda
template for the other — means two renderers, and the second one is always the
one that leaks. Alertmanager's native Slack integration is deliberately unused
for exactly that reason.

**Allowlist, not denylist.** ``render`` builds the message from named fields;
there is no code path that takes an arbitrary dict and formats it. A denylist
of patterns to strip fails the first time somebody adds a field nobody thought
to strip, and it fails silently.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any

# Applied to every free-text field that survives the allowlist. Belt and braces:
# the allowlist should already have excluded anything sensitive, and these
# patterns are what catch a summary line that embedded something inline.
_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\b(?:AKIA|ASIA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{12,}\b"), "[aws-key]"),
    (re.compile(r"\barn:aws[\w-]*:[\w-]+:[\w-]*:(\d{12}):"), "[arn]"),
    (re.compile(r"(?<![\w-])\d{12}(?![\w-])"), "[account]"),
    (re.compile(r"\bo-[a-z0-9]{10,32}\b"), "[org]"),
    (re.compile(r"\bou-[a-z0-9]{4,32}-[a-z0-9]{8,32}\b"), "[ou]"),
    (re.compile(r"\b[\w.%+-]+@[\w.-]+\.[A-Za-z]{2,}\b"), "[email]"),
    (re.compile(r"\b(?:vpc|subnet|sg|eni|i|vol|snap|ami)-[0-9a-f]{8,17}\b"), "[resource]"),
    # Swedish personal identity numbers — the Article 9 identifier in this
    # domain. Should never reach a finding; if one does, it stops here.
    (re.compile(r"\b\d{6,8}[-+]?\d{4}\b"), "[personnummer]"),
    (re.compile(r"\beyJ[\w-]+\.[\w-]+\.[\w-]+\b"), "[jwt]"),
)

# Fields allowed out. Anything not named here never reaches a message, whatever
# an alert or a finding happens to contain.
ALLOWED_FIELDS = frozenset(
    {"alertname", "rule_id", "severity", "domain", "summary", "runbook", "status", "service"}
)

MAX_FIELD_LENGTH = 300


class RedactionError(RuntimeError):
    """Raised when a message cannot be rendered safely. Never suppressed."""


def scrub(value: str) -> str:
    """Apply every pattern, then truncate.

    Truncation is after substitution on purpose: cutting first can split an
    identifier so that no pattern matches the halves, and half an account id in
    a public channel is still an account id.
    """
    for pattern, token in _PATTERNS:
        value = pattern.sub(token, value)
    if len(value) > MAX_FIELD_LENGTH:
        value = value[: MAX_FIELD_LENGTH - 1] + "…"
    return value


def fingerprint(value: str, salt: str = "ssp-notify") -> str:
    """Stable pseudonym, so the same resource is recognisable across alerts.

    A responder needs to know that today's alert concerns the same thing as
    yesterday's. They do not need its name to know that.
    """
    return hashlib.sha256(f"{salt}:{value}".encode()).hexdigest()[:8]


@dataclass(frozen=True)
class Alert:
    """The only shape that can become a message."""

    alertname: str
    severity: str
    summary: str
    status: str = "firing"
    rule_id: str | None = None
    domain: str | None = None
    runbook: str | None = None
    service: str | None = None
    console_url: str | None = None


def from_alertmanager(payload: dict[str, Any]) -> list[Alert]:
    """Convert an Alertmanager webhook payload, taking only allowed fields."""
    alerts: list[Alert] = []
    for raw in payload.get("alerts", []):
        labels = raw.get("labels", {}) or {}
        annotations = raw.get("annotations", {}) or {}
        alerts.append(
            Alert(
                alertname=scrub(str(labels.get("alertname", "unknown"))),
                severity=scrub(str(labels.get("severity", "unknown"))),
                summary=scrub(str(annotations.get("summary", ""))),
                status=scrub(str(raw.get("status", "firing"))),
                domain=_optional(labels.get("domain")),
                runbook=_optional(annotations.get("runbook")),
                service=_optional(labels.get("service")),
            )
        )
    return alerts


def from_security_hub(detail: dict[str, Any]) -> Alert:
    """Convert a Security Hub / GuardDuty finding from an SNS envelope.

    The finding's own `Description` is deliberately NOT used: AWS populates it
    with resource names and, for some finding types, request parameters. The
    finding *type* says what happened, and the console link says where to look
    under the access controls that already govern it.
    """
    severity = (detail.get("Severity") or {}).get("Label", "UNKNOWN").lower()
    finding_type = (detail.get("Types") or ["Unknown"])[0]
    region = detail.get("Region", "")
    finding_id = detail.get("Id", "")

    return Alert(
        alertname=scrub(finding_type),
        severity=scrub(severity),
        summary=scrub(str(detail.get("Title", "Security Hub finding"))),
        rule_id=fingerprint(finding_id) if finding_id else None,
        domain="aws",
        console_url=(
            f"https://{region}.console.aws.amazon.com/securityhub/home?region={region}#/findings"
            if region
            else None
        ),
        runbook="docs/05-incident-response/",
    )


def _optional(value: Any) -> str | None:
    return scrub(str(value)) if value else None
