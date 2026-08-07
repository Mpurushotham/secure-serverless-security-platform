"""Leak assertions over the recorded MCP session.

Two rules this file exists to enforce:

  1. **Claims are asserted, not printed.** The demo script narrates "no raw PII
     appears above". Narration is not a control. These tests fail CI if any
     seeded plaintext value reaches the transcript.

  2. **The verifier must be harder to break than the thing it verifies.** An
     earlier shell version of this check used `grep -c ... || echo 0`, which
     emits "0" twice on a clean scan and made the comparison always report a
     leak. It cried wolf on correct output — the failure mode that gets a
     control switched off. Hence Python, with the seeded values imported from
     one place.

Run `make db-up && make mcp-demo` first to produce the transcript; the tests
skip rather than fail when it is absent, so a fresh clone's `pytest` is green
without Docker.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
TRANSCRIPT = REPO_ROOT / "evidence" / "mcp-demo-transcript.jsonl"

# Values seeded by sql/00-seed-schema.sql. All fabricated; none may ever appear
# in output the agent receives.
SEEDED_PLAINTEXT = [
    "19850101-0000", "19900215-0000", "19771103-0000", "20010730-0000",  # personnummer
    "astrid@example.com", "bjorn@example.com", "cecilia@example.com", "dmitri@example.com",
    "+46700000001", "+46700000002", "+46700000003", "+46700000004",
    "SE2321000016-1001", "SE2321000016-1002", "SE2321000016-1003",       # prescriber HSA-IDs
    "Lindqvist", "Karlsson", "Nyström", "Andersson",                     # family names
    "Sveavägen 1", "Kungsgatan 4", "Storgatan 9", "Drottninggatan 22",   # street addresses
    "11157", "41119", "21142", "11151",                                  # full postal codes
]

# Rows 3 and 4 have consent_analytics = false and must never be visible.
CONSENTED_PRESCRIPTION_IDS = {1, 2}


@pytest.fixture(scope="module")
def transcript_text() -> str:
    if not TRANSCRIPT.exists():
        pytest.skip("no transcript; run `make db-up && make mcp-demo` to generate it")
    return TRANSCRIPT.read_text(encoding="utf-8")


@pytest.mark.parametrize("secret", SEEDED_PLAINTEXT)
def test_seeded_plaintext_never_reaches_the_agent(transcript_text: str, secret: str) -> None:
    assert secret not in transcript_text, (
        f"{secret!r} leaked into the MCP transcript — masking or grants regressed"
    )


def test_transcript_contains_masked_substitutes(transcript_text: str) -> None:
    """Guard against the false pass where the query simply returned nothing."""
    assert "personnummer_masked" in transcript_text
    assert "email_masked" in transcript_text
    assert "+46*******" in transcript_text  # phone mask survived
    assert "XX" in transcript_text  # postal district generalisation survived


def _visible_prescription_ids(text: str) -> set[int]:
    ids: set[int] = set()
    for line in text.splitlines():
        entry = json.loads(line)
        result = entry.get("response", {}).get("result", {})
        for block in result.get("content", []):
            body = block.get("text", "")
            if "medication" not in body:
                continue
            try:
                parsed = json.loads(body)
            except json.JSONDecodeError:
                continue
            for row in parsed.get("rows", []):
                if "medication" in row and "id" in row:
                    ids.add(int(row["id"]))
    return ids


def test_row_level_security_hid_non_consented_rows(transcript_text: str) -> None:
    visible = _visible_prescription_ids(transcript_text)
    assert visible, "no prescription rows found — the transcript may be stale"
    assert visible == CONSENTED_PRESCRIPTION_IDS, (
        f"agent saw prescription ids {sorted(visible)}; only "
        f"{sorted(CONSENTED_PRESCRIPTION_IDS)} consented to analytics processing"
    )


def test_every_refusal_names_its_control(transcript_text: str) -> None:
    refusals = 0
    for line in transcript_text.splitlines():
        entry = json.loads(line)
        result = entry.get("response", {}).get("result", {})
        if result.get("isError"):
            refusals += 1
            text = result["content"][0]["text"]
            assert "Refused by guardrail [" in text, f"refusal without a named control: {text}"
    assert refusals >= 4, f"expected the demo to exercise refusals, found {refusals}"


def test_audit_records_do_not_contain_plaintext_arguments(transcript_text: str) -> None:
    """Arguments are fingerprinted; a SQL predicate can itself carry PII."""
    for line in transcript_text.splitlines():
        entry = json.loads(line)
        if "audit" not in entry:
            continue
        record = entry["audit"]
        assert "args_fingerprint" in record
        assert "arguments" not in record
        assert "sql" not in record
