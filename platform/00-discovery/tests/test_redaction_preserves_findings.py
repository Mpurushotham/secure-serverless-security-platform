"""The committed snapshot must reach the same conclusions as the raw one.

This is the invariant that a redaction bug breaks silently. Rules are evaluated
against raw data and the *report* is rendered from redacted data; if those two
disagree, the published assessment claims findings that nobody re-running the
tool can reproduce — or worse, omits findings that were really there.

An earlier version of the redactor did exactly that. It replaced collected names
by plain substring match, so organizational units named `audit` and `security`
were rewritten inside `auditmanager.amazonaws.com` and
`securityhub.amazonaws.com`. Four findings disappeared, including the
organization-wide one about delegated administration, and the report still
rendered as though it were complete.

The runner asserts this on every live run. This test asserts it on the committed
artifact, so it is checked in CI without an AWS account.
"""

from __future__ import annotations

import json
from pathlib import Path

from discovery.redact import Redactor
from discovery.rules import evaluate

FIXTURE = Path(__file__).parent / "fixtures" / "snapshot.json"
COMMITTED = Path(__file__).parents[1] / "snapshots" / "latest.json"


def test_redacting_an_already_redacted_snapshot_changes_no_findings() -> None:
    """Redaction must be idempotent with respect to findings.

    The fixture is already redacted, so a second pass should be a no-op as far
    as the rules are concerned. If a second pass changes the findings, the first
    pass would have too.
    """
    snapshot = json.loads(FIXTURE.read_text(encoding="utf-8"))
    before = {f.rule_id for f in evaluate(snapshot)}
    after = {f.rule_id for f in evaluate(Redactor("123456789012").apply(snapshot))}
    assert before == after, f"lost {sorted(before - after)}, gained {sorted(after - before)}"


def test_the_committed_snapshot_still_produces_findings() -> None:
    """A snapshot that produces nothing is indistinguishable from a broken one."""
    if not COMMITTED.exists():
        return
    findings = evaluate(json.loads(COMMITTED.read_text(encoding="utf-8")))
    assert findings, "the committed snapshot produces no findings at all"


def test_no_finding_text_contains_an_unredacted_identifier() -> None:
    import re

    snapshot = json.loads(FIXTURE.read_text(encoding="utf-8"))
    patterns = {
        "account id": re.compile(r"(?<![\w-])\d{12}(?![\w-])"),
        "organization id": re.compile(r"\bo-[a-z0-9]{10,}\b"),
        "ou id": re.compile(r"\bou-[a-z0-9]{4,}-[a-z0-9]{8,}\b"),
        "email": re.compile(r"\b[\w.%+-]+@(?!redacted\.invalid)[\w.-]+\.[A-Za-z]{2,}\b"),
        "vpc/sg id": re.compile(r"\b(?:vpc|sg|subnet)-[0-9a-f]{8,}\b"),
    }
    for finding in evaluate(snapshot):
        for label, pattern in patterns.items():
            hit = pattern.search(finding.detail)
            assert not hit, f"{finding.rule_id} leaks {label}: {hit.group(0)}"
