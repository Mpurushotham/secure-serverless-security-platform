"""What changed between two snapshots.

The reason this module exists: a point-in-time posture report tells you where
you are, and everybody already knows roughly where they are. What nobody knows
is the direction — whether last month's remediation held, or whether something
regressed quietly while attention was elsewhere.

Two properties make the comparison trustworthy:

**Pseudonyms are stable across runs.** The redactor salts from the account ID
rather than randomly, so `role_8cb8f5` is the same role in every snapshot. Two
snapshots therefore diff on real change instead of on noise, which is the
property that makes a diff worth reading at all.

**A finding that disappears is not automatically fixed.** It may have been
suppressed, the collector may have failed, or the region may have dropped out of
scope. Resolved findings are reported alongside the collector and scope changes
that could explain them, because "the finding went away" and "we stopped
looking" are indistinguishable from the finding list alone — and only one of
them is good news.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

Snapshot = dict[str, Any]


@dataclass
class Delta:
    previous_at: str
    current_at: str

    new_findings: list[Any] = field(default_factory=list)
    resolved_findings: list[Any] = field(default_factory=list)
    unchanged_findings: list[Any] = field(default_factory=list)

    #: Collectors that reported before and not now, or vice versa.
    collectors_degraded: list[str] = field(default_factory=list)
    collectors_recovered: list[str] = field(default_factory=list)

    regions_added: list[str] = field(default_factory=list)
    regions_removed: list[str] = field(default_factory=list)

    @property
    def scope_changed(self) -> bool:
        return bool(
            self.collectors_degraded
            or self.collectors_recovered
            or self.regions_added
            or self.regions_removed
        )

    @property
    def resolutions_are_trustworthy(self) -> bool:
        """False when scope moved, because then a resolution may be an absence.

        Deliberately conservative: any scope movement at all taints every
        resolution in the run, not just the ones plausibly connected to it.
        Attributing which resolution the scope change explains would be a guess,
        and a confident guess is worse here than an honest caveat.
        """
        return not (self.collectors_degraded or self.regions_removed)


def compare(
    previous: Snapshot,
    current: Snapshot,
    previous_findings: list[Any],
    current_findings: list[Any],
) -> Delta:
    before = {f.rule_id: f for f in previous_findings}
    after = {f.rule_id: f for f in current_findings}

    prev_ok = {
        name
        for name, entry in previous.get("collectors", {}).items()
        if entry.get("status") == "observed"
    }
    curr_ok = {
        name
        for name, entry in current.get("collectors", {}).items()
        if entry.get("status") == "observed"
    }

    prev_regions = set(previous.get("regions_scanned", []))
    curr_regions = set(current.get("regions_scanned", []))

    return Delta(
        previous_at=previous.get("generated_at", "unknown"),
        current_at=current.get("generated_at", "unknown"),
        new_findings=[after[k] for k in sorted(set(after) - set(before))],
        resolved_findings=[before[k] for k in sorted(set(before) - set(after))],
        unchanged_findings=[after[k] for k in sorted(set(after) & set(before))],
        collectors_degraded=sorted(prev_ok - curr_ok),
        collectors_recovered=sorted(curr_ok - prev_ok),
        regions_added=sorted(curr_regions - prev_regions),
        regions_removed=sorted(prev_regions - curr_regions),
    )
