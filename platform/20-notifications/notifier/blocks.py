"""Slack Block Kit rendering.

Every field here has already passed through `redact.Alert`, which is an
allowlist — so this module cannot emit something the redactor never saw. That
ordering is the point: rendering from a dataclass with named fields makes the
unsafe version unavailable rather than discouraged.
"""

from __future__ import annotations

from typing import Any

from .redact import Alert

SEVERITY_EMOJI = {
    "critical": ":red_circle:",
    "high": ":large_orange_circle:",
    "medium": ":large_yellow_circle:",
    "low": ":white_circle:",
}


def render(alert: Alert, repo_url: str | None = None) -> dict[str, Any]:
    """One alert as a Block Kit message."""
    emoji = SEVERITY_EMOJI.get(alert.severity, ":grey_question:")
    resolved = alert.status == "resolved"
    prefix = ":white_check_mark: Resolved — " if resolved else f"{emoji} "

    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"{prefix}{alert.alertname}"[:150]},
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": alert.summary or "_no summary_"},
        },
    ]

    facts = [f"*Severity*\n{alert.severity}"]
    if alert.domain:
        facts.append(f"*Domain*\n{alert.domain}")
    if alert.service:
        facts.append(f"*Service*\n{alert.service}")
    if alert.rule_id:
        facts.append(f"*Reference*\n`{alert.rule_id}`")
    blocks.append({"type": "section", "fields": [{"type": "mrkdwn", "text": f} for f in facts[:4]]})

    # Pointers, not payload. Everything a responder needs to go and look under
    # the access controls that already exist.
    elements: list[dict[str, Any]] = []
    if alert.console_url:
        elements.append(_button("Open in AWS console", alert.console_url, style="primary"))
    if alert.runbook and repo_url:
        elements.append(_button("Runbook", f"{repo_url.rstrip('/')}/blob/main/{alert.runbook}"))
    if elements:
        blocks.append({"type": "actions", "elements": elements})

    blocks.append(
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": (
                        "_Identifiers are redacted. This message is a pointer — open the "
                        "console or the runbook for detail._"
                    ),
                }
            ],
        }
    )

    return {"text": f"{prefix}{alert.alertname}"[:150], "blocks": blocks}


def _button(text: str, url: str, style: str | None = None) -> dict[str, Any]:
    button: dict[str, Any] = {
        "type": "button",
        "text": {"type": "plain_text", "text": text},
        "url": url,
    }
    if style:
        button["style"] = style
    return button
