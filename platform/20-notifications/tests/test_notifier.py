"""Notifier tests: redaction, rendering, and signature verification.

Every identifier below is synthetic. Using a real account or organization id as
a test input would publish exactly what this module exists to remove.

The redaction tests are the load-bearing ones. Sending to Slack is publishing —
a workspace has different membership, retention and export controls from the AWS
account a finding describes. These assert that no identifier survives into a
rendered message, using the same method as the 27 leak assertions over the live
MCP transcript in `mcp-servers/tests/test_no_pii_leakage.py`.
"""

from __future__ import annotations

import json
import re
import time

import pytest
from notifier.blocks import render
from notifier.redact import (
    ALLOWED_FIELDS,
    Alert,
    fingerprint,
    from_alertmanager,
    from_security_hub,
    scrub,
)
from notifier.signature import InvalidSignature, verify

# Every pattern that must never appear in an outbound message.
FORBIDDEN = {
    "account id": re.compile(r"(?<![\w-])\d{12}(?![\w-])"),
    "organization id": re.compile(r"\bo-[a-z0-9]{10,}\b"),
    "ou id": re.compile(r"\bou-[a-z0-9]{4,}-[a-z0-9]{8,}\b"),
    "access key": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{12,}\b"),
    "email": re.compile(r"\b[\w.%+-]+@[\w.-]+\.[A-Za-z]{2,}\b"),
    "resource id": re.compile(r"\b(?:vpc|subnet|sg|eni)-[0-9a-f]{8,}\b"),
    "personnummer": re.compile(r"\b\d{6,8}[-+]?\d{4}\b"),
    "jwt": re.compile(r"\beyJ[\w-]+\.[\w-]+\.[\w-]+\b"),
}


def assert_clean(payload: object, label: str = "") -> None:
    text = json.dumps(payload)
    for name, pattern in FORBIDDEN.items():
        hit = pattern.search(text)
        assert not hit, f"{label} leaked {name}: {hit.group(0)}"


class TestScrub:
    @pytest.mark.parametrize(
        "raw",
        [
            "bucket in account 210987654321 is public",
            "role arn:aws:iam::210987654321:role/admin assumed",
            "organization o-a1b2c3d4e5 has no delegated admin",
            "ou-a1b2-9z8y7x6w contains no accounts",
            "key AKIAIOSFODNN7EXAMPLE found in a commit",
            "contact alice@example.com about this",
            "vpc-0123456789abcdef0 has no flow logs",
            "patient 19850101-1234 record accessed",
            "token eyJhbGciOi.eyJzdWIi.SflKxwRJ presented",
        ],
    )
    def test_identifiers_do_not_survive(self, raw: str) -> None:
        assert_clean(scrub(raw), raw)

    def test_ordinary_text_is_preserved(self) -> None:
        # Over-redaction that mangles the summary makes the alert useless, so
        # the message still has to read as a sentence.
        text = "GuardDuty is not enabled in 4 scanned regions"
        assert scrub(text) == text

    def test_truncation_happens_after_substitution(self) -> None:
        # Cutting first could split an identifier so no pattern matches the
        # halves, and half an account id in a public channel is still one.
        raw = "x" * 290 + " account 210987654321 here"
        assert_clean(scrub(raw), "truncated")

    def test_fingerprints_are_stable_and_distinct(self) -> None:
        assert fingerprint("finding-a") == fingerprint("finding-a")
        assert fingerprint("finding-a") != fingerprint("finding-b")
        assert_clean(fingerprint("arn:aws:iam::210987654321:role/admin"))


class TestAllowlist:
    def test_an_unknown_field_cannot_reach_a_message(self) -> None:
        # The alert dataclass is the allowlist. A payload carrying extra
        # annotations must not smuggle them through.
        payload = {
            "alerts": [
                {
                    "status": "firing",
                    "labels": {"alertname": "Test", "severity": "high"},
                    "annotations": {
                        "summary": "something happened",
                        "bucket": "customer-prescriptions-210987654321",
                        "query": "SELECT * FROM prescriptions",
                    },
                }
            ]
        }
        alerts = from_alertmanager(payload)
        rendered = render(alerts[0])
        text = json.dumps(rendered)
        assert "prescriptions" not in text
        assert "SELECT" not in text
        assert_clean(rendered, "alertmanager")

    def test_allowed_fields_is_a_closed_set(self) -> None:
        assert "bucket" not in ALLOWED_FIELDS
        assert "query" not in ALLOWED_FIELDS
        assert "detail" not in ALLOWED_FIELDS


class TestSecurityHub:
    def test_the_finding_description_is_not_used(self) -> None:
        # AWS populates Description with resource names and, for some finding
        # types, request parameters.
        detail = {
            "Id": "arn:aws:securityhub:eu-north-1:210987654321:finding/abc",
            "Severity": {"Label": "HIGH"},
            "Types": ["Effects/Data Exposure"],
            "Title": "S3 bucket is publicly readable",
            "Description": "Bucket customer-data-210987654321 grants s3:GetObject to *",
            "Region": "eu-north-1",
        }
        alert = from_security_hub(detail)
        rendered = render(alert)
        assert "customer-data" not in json.dumps(rendered)
        assert_clean(rendered, "securityhub")

    def test_it_still_points_somewhere_useful(self) -> None:
        alert = from_security_hub(
            {"Id": "x", "Severity": {"Label": "HIGH"}, "Types": ["T"], "Region": "eu-north-1"}
        )
        assert alert.console_url and "securityhub" in alert.console_url
        assert alert.runbook == "docs/05-incident-response/"


class TestRendering:
    def test_every_severity_renders(self) -> None:
        for severity in ("critical", "high", "medium", "low", "unknown"):
            rendered = render(Alert("Name", severity, "summary"))
            assert rendered["blocks"]
            assert_clean(rendered, severity)

    def test_a_resolved_alert_is_marked_as_such(self) -> None:
        rendered = render(Alert("Name", "high", "summary", status="resolved"))
        assert "Resolved" in rendered["text"]

    def test_the_message_says_it_is_a_pointer(self) -> None:
        rendered = render(Alert("Name", "high", "summary"))
        assert "pointer" in json.dumps(rendered)


class TestSignature:
    SECRET = "test-signing-secret"  # noqa: S105 — a fixture, not a credential

    def _sign(self, body: str, timestamp: str) -> str:
        import hashlib
        import hmac

        return (
            "v0="
            + hmac.new(
                self.SECRET.encode(), f"v0:{timestamp}:{body}".encode(), hashlib.sha256
            ).hexdigest()
        )

    def test_a_valid_recent_request_passes(self) -> None:
        now = time.time()
        ts = str(int(now))
        body = "payload=x"
        verify(self.SECRET, ts, body, self._sign(body, ts), now=now)

    def test_a_tampered_body_is_refused(self) -> None:
        now = time.time()
        ts = str(int(now))
        signature = self._sign("payload=x", ts)
        with pytest.raises(InvalidSignature):
            verify(self.SECRET, ts, "payload=evil", signature, now=now)

    def test_a_replayed_request_is_refused(self) -> None:
        # Without a replay window a captured request stays valid forever, and
        # every interactive action becomes repeatable by whoever captured it.
        old = time.time() - 3600
        ts = str(int(old))
        body = "payload=x"
        with pytest.raises(InvalidSignature, match="replay window"):
            verify(self.SECRET, ts, body, self._sign(body, ts), now=time.time())

    def test_a_wrong_secret_is_refused(self) -> None:
        now = time.time()
        ts = str(int(now))
        body = "payload=x"
        with pytest.raises(InvalidSignature):
            verify("other-secret", ts, body, self._sign(body, ts), now=now)

    def test_a_malformed_timestamp_is_refused(self) -> None:
        with pytest.raises(InvalidSignature):
            verify(self.SECRET, "not-a-number", "b", "v0=x")

    def test_comparison_is_constant_time(self) -> None:
        # A naive == leaks how many leading bytes matched, which is enough to
        # forge a signature one byte at a time.
        import inspect

        from notifier import signature

        assert "compare_digest" in inspect.getsource(signature.verify)
