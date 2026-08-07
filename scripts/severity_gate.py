#!/usr/bin/env python3
"""Fail the build when scanner findings exceed the configured severity budget.

Separate from vuln_sla.py on purpose. The SLA script asks "has this been open
too long?"; this one asks "is this bad enough to block the merge right now?".
Conflating them produces a gate that either blocks on everything or ages
everything, and teams end up disabling whichever it is.

The budget is a count per severity, not a boolean. Zero criticals is a
reasonable bar; zero mediums is not, and a gate set to an unreachable bar gets
switched off within a month — which is strictly worse than a bar that holds.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vuln_sla import finding_id, normalise_severity  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent

DEFAULT_BUDGET = {"critical": 0, "high": 0, "medium": 10, "low": 50}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("sarif", nargs="+", type=Path)
    parser.add_argument("--max-critical", type=int, default=DEFAULT_BUDGET["critical"])
    parser.add_argument("--max-high", type=int, default=DEFAULT_BUDGET["high"])
    parser.add_argument("--max-medium", type=int, default=DEFAULT_BUDGET["medium"])
    parser.add_argument("--max-low", type=int, default=DEFAULT_BUDGET["low"])
    args = parser.parse_args()

    budget = {
        "critical": args.max_critical, "high": args.max_high,
        "medium": args.max_medium, "low": args.max_low,
    }

    counts: Counter[str] = Counter()
    worst: dict[str, list[str]] = {k: [] for k in budget}

    for path in args.sarif:
        if not path.exists():
            print(f"warning: {path} not found, skipping", file=sys.stderr)
            continue
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            print(f"::error::{path} is not valid SARIF", file=sys.stderr)
            return 1
        for run in doc.get("runs", []):
            tool = run.get("tool", {}).get("driver", {}).get("name", "unknown")
            for result in run.get("results", []):
                severity = normalise_severity(result)
                counts[severity] += 1
                if len(worst[severity]) < 10:
                    worst[severity].append(f"[{tool}] {finding_id(result)}")

    print(f"{'severity':<10} {'found':>6} {'budget':>7}  status")
    print("-" * 42)
    failed = False
    for severity in ("critical", "high", "medium", "low"):
        found, allowed = counts[severity], budget[severity]
        over = found > allowed
        failed = failed or over
        print(f"{severity:<10} {found:>6} {allowed:>7}  {'OVER BUDGET' if over else 'ok'}")

    if failed:
        print("\nFindings pushing the build over budget:", file=sys.stderr)
        for severity in ("critical", "high", "medium", "low"):
            if counts[severity] > budget[severity]:
                for item in worst[severity]:
                    print(f"::error::{severity}: {item}", file=sys.stderr)
        return 1

    print("\nWithin severity budget.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
