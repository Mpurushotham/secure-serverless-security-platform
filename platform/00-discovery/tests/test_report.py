"""The report's contract with its reader.

Two promises, both testable: every checklist item appears with a status, and
nothing that could not be assessed is presented as if it had been.
"""

from __future__ import annotations

import json
from pathlib import Path

from discovery.checklist import CHECKLIST
from discovery.report import render
from discovery.rules import evaluate

FIXTURE = Path(__file__).parent / "fixtures" / "snapshot.json"


def load() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


class TestChecklistCoverage:
    def test_the_checklist_has_all_twenty_five_items(self) -> None:
        assert sorted(CHECKLIST) == list(range(1, 26))

    def test_every_item_appears_in_the_report(self) -> None:
        body = render(load(), evaluate(load()))
        for number, item in CHECKLIST.items():
            assert item.title in body, f"checklist item {number} missing from the report"

    def test_every_item_carries_a_status(self) -> None:
        body = render(load(), evaluate(load()))
        table = [
            line for line in body.splitlines()
            if line.startswith("| ") and "`" in line and "|" in line
        ]
        statuses = {"observed", "judgement", "not-permitted", "error"}
        rows = [
            line for line in table
            if any(item.title in line for item in CHECKLIST.values())
        ]
        assert len(rows) == 25, f"expected 25 checklist rows, found {len(rows)}"
        for row in rows:
            assert any(f"`{s}`" in row for s in statuses), f"row has no status: {row}"


class TestHonesty:
    def test_denied_calls_are_surfaced_in_the_caveats(self) -> None:
        s = load()
        s["api_calls"]["denied"] = ["macie2:GetMacieSession"]
        body = render(s, evaluate(s))
        assert "were denied" in body
        assert "macie2:GetMacieSession" in body

    def test_failed_collectors_are_named(self) -> None:
        s = load()
        s["collectors"]["kms"]["status"] = "error"
        body = render(s, evaluate(s))
        assert "did not complete" in body
        assert "kms" in body

    def test_an_over_privileged_assessor_is_declared(self) -> None:
        s = load()
        s["assessed_principal"] = "arn:aws:sts::acct_x:assumed-role/cap-platform-admin/x"
        body = render(s, evaluate(s))
        assert "over-privileged" in body

    def test_region_scope_is_stated(self) -> None:
        body = render(load(), evaluate(load()))
        assert "Findings say nothing about regions outside that set" in body

    def test_the_read_only_claim_is_made_explicitly(self) -> None:
        body = render(load(), evaluate(load()))
        assert "No object, secret value, parameter value or table row was read" in body


class TestStructure:
    def test_findings_have_remediation(self) -> None:
        s = load()
        findings = evaluate(s)
        body = render(s, findings)
        assert body.count("**Remediation.**") == len(findings)

    def test_the_organization_diagram_is_valid_mermaid(self) -> None:
        body = render(load(), evaluate(load()))
        assert "```mermaid" in body
        block = body.split("```mermaid", 1)[1].split("```", 1)[0]
        assert "flowchart TD" in block
        # Mermaid node ids cannot contain hyphens; the renderer substitutes them.
        for line in block.splitlines():
            identifier = line.strip().split("[")[0].split("(")[0].split("-->")[0].strip()
            assert "-" not in identifier, f"hyphen in mermaid node id: {line}"

    def test_no_real_account_id_survives_into_the_report(self) -> None:
        # The report renders from the redacted snapshot. If that ever regresses,
        # this is the test that catches it before the file is committed.
        import re

        body = render(load(), evaluate(load()))
        bare_twelve_digits = re.findall(r"(?<![\w-])\d{12}(?![\w-])", body)
        assert not bare_twelve_digits, (
            f"the report contains what look like raw account IDs: {bare_twelve_digits}"
        )
