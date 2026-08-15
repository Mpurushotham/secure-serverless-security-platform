"""Posture reporting: metrics, delta, and the honesty constraints.

The constraints come from ``readiness/02-security-metrics.md`` and are testable,
so they are tested rather than left as intentions: every metric carries a gaming
mode, unmeasurable metrics carry a reason, and no overall score is produced.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from reporting.delta import compare
from reporting.metrics import UNMEASURABLE, compute
from reporting.render import render

FIXTURE = Path(__file__).parents[2] / "00-discovery" / "tests" / "fixtures" / "snapshot.json"


def snapshot() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


@dataclass(frozen=True)
class FakeFinding:
    rule_id: str
    severity: str = "high"
    title: str = "example"


class TestHonestyConstraints:
    def test_every_metric_states_how_it_gets_gamed(self) -> None:
        # readiness/02-security-metrics.md: "a metric without one gets gamed".
        for metric in compute(snapshot()).metrics:
            assert metric.gaming.strip(), f"{metric.key} has no stated gaming mode"

    def test_every_unmeasurable_metric_states_why(self) -> None:
        for metric in compute(snapshot()).unmeasured:
            assert metric.unmeasurable_because, f"{metric.key} is unmeasured with no reason"

    def test_unmeasurable_metrics_are_present_not_omitted(self) -> None:
        keys = {m.key for m in compute(snapshot()).metrics}
        for key, *_ in UNMEASURABLE:
            assert key in keys, f"{key} was dropped instead of being reported as unmeasurable"

    def test_the_report_produces_no_overall_score(self) -> None:
        body = render(compute(snapshot()), [], None)
        lowered = body.lower()
        assert "overall score" not in lowered.replace("no overall score", "")
        assert "security score:" not in lowered
        assert "There is no overall score" in body

    def test_the_report_names_the_unmeasured_section(self) -> None:
        assert "## Not measured, and why" in render(compute(snapshot()), [], None)


class TestMetrics:
    def test_detection_coverage_is_a_fraction_not_a_boolean(self) -> None:
        metric = next(m for m in compute(snapshot()).metrics if m.key == "detection_coverage")
        # The detail must show per-service counts: "GuardDuty is enabled" is true
        # and useless if it means one region out of seventeen.
        assert "/" in metric.detail
        assert isinstance(metric.value, float)

    def test_a_failed_collector_makes_its_metric_unmeasurable_not_zero(self) -> None:
        s = snapshot()
        s["collectors"]["iam"]["status"] = "error"
        metrics = {m.key: m for m in compute(s).metrics}
        # Zero admin identities would be a great result and a total fabrication.
        assert metrics["privileged_identities"].value is None
        assert metrics["privileged_identities"].unmeasurable_because


class TestDelta:
    def test_new_and_resolved_are_detected(self) -> None:
        s = snapshot()
        d = compare(
            s, s,
            [FakeFinding("A"), FakeFinding("B")],
            [FakeFinding("B"), FakeFinding("C")],
        )
        assert [f.rule_id for f in d.new_findings] == ["C"]
        assert [f.rule_id for f in d.resolved_findings] == ["A"]
        assert [f.rule_id for f in d.unchanged_findings] == ["B"]

    def test_a_degraded_collector_makes_resolutions_untrustworthy(self) -> None:
        before, after = snapshot(), snapshot()
        after["collectors"]["s3"]["status"] = "error"
        d = compare(before, after, [FakeFinding("DAT-002")], [])
        assert d.collectors_degraded == ["s3"]
        assert not d.resolutions_are_trustworthy

    def test_a_removed_region_makes_resolutions_untrustworthy(self) -> None:
        before, after = snapshot(), snapshot()
        after["regions_scanned"] = before["regions_scanned"][:1]
        d = compare(before, after, [FakeFinding("DET-001")], [])
        assert d.regions_removed
        assert not d.resolutions_are_trustworthy

    def test_a_widened_scope_keeps_resolutions_trustworthy(self) -> None:
        # Adding regions cannot cause a finding to disappear, so resolutions
        # still stand — but new findings may be pre-existing rather than
        # regressions, which the report says separately.
        before, after = snapshot(), snapshot()
        before["regions_scanned"] = after["regions_scanned"][:1]
        d = compare(before, after, [], [FakeFinding("NET-001")])
        assert d.regions_added
        assert d.resolutions_are_trustworthy
        assert d.scope_changed

    def test_the_untrustworthy_warning_reaches_the_report(self) -> None:
        before, after = snapshot(), snapshot()
        after["collectors"]["s3"]["status"] = "error"
        d = compare(before, after, [FakeFinding("DAT-002")], [])
        body = render(compute(after), [], d)
        assert "unconfirmed" in body
        assert "nobody looked" in body


class TestPreviousSnapshotSelection:
    def test_a_run_is_never_compared_against_itself(self) -> None:
        """Regression test.

        `latest.json` is a copy of the newest timestamped snapshot. Excluding
        only the current *path* left its own twin as the "previous" snapshot, so
        the report compared a run against itself and reported zero change — a
        clean bill of health produced by comparing a thing to itself.
        """
        import tempfile

        from reporting.__main__ import _previous_snapshot

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            same_run = {"generated_at": "2026-01-01T00:00:00Z", "collectors": {}}
            older = {"generated_at": "2025-12-01T00:00:00Z", "collectors": {}}
            (root / "latest.json").write_text(json.dumps(same_run))
            (root / "20260101T000000Z.json").write_text(json.dumps(same_run))
            (root / "20251201T000000Z.json").write_text(json.dumps(older))

            chosen = _previous_snapshot(root / "latest.json", same_run)
            assert chosen is not None
            assert chosen.name == "20251201T000000Z.json"
