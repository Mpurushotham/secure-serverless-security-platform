"""Posture report CLI.

    python -m reporting --snapshot <current.json> [--previous <older.json>]

Reads committed snapshots only. Makes no AWS calls — the report is a view over
what discovery already recorded, so it regenerates on a fork with no account.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# parents[2] is platform/; the discovery package lives under a numbered
# directory that is not a legal Python identifier, hence the path insert
# rather than an import.
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "00-discovery"))
from discovery.rules import evaluate  # noqa: E402

from .delta import compare  # noqa: E402
from .metrics import compute  # noqa: E402
from .render import render  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[3]


def _sla_state() -> tuple[int | None, int | None]:
    """Breaches and expired exceptions, from the artifacts vuln_sla.py writes."""
    report = REPO_ROOT / "evidence" / "vuln-sla-report.md"
    if not report.exists():
        return None, None
    text = report.read_text(encoding="utf-8")
    breaches = expired = 0
    for line in text.splitlines():
        if "breach" in line.lower() and line.strip().startswith(("0", "1", "2", "3", "4",
                                                                 "5", "6", "7", "8", "9")):
            parts = line.split("·")
            for part in parts:
                if "breach" in part:
                    breaches = int(part.strip().split()[0])
                if "expired" in part:
                    expired = int(part.strip().split()[0])
    return breaches, expired


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Render the security posture report")
    parser.add_argument(
        "--snapshot",
        type=Path,
        default=REPO_ROOT / "platform" / "00-discovery" / "snapshots" / "latest.json",
    )
    parser.add_argument("--previous", type=Path, default=None)
    parser.add_argument(
        "--out", type=Path, default=REPO_ROOT / "platform" / "18-reporting" / "posture.md"
    )
    args = parser.parse_args(argv)

    current = json.loads(args.snapshot.read_text(encoding="utf-8"))
    findings = evaluate(current)

    previous_path = args.previous or _previous_snapshot(args.snapshot, current)
    delta = None
    if previous_path is not None and previous_path.exists():
        previous = json.loads(previous_path.read_text(encoding="utf-8"))
        delta = compare(previous, current, evaluate(previous), findings)
        print(f"  comparing against {previous_path.name}", file=sys.stderr)
    else:
        print("  no earlier snapshot — no delta section", file=sys.stderr)

    breaches, expired = _sla_state()
    metrics = compute(current, sla_breaches=breaches, expired_exceptions=expired)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(render(metrics, findings, delta), encoding="utf-8")

    print(
        f"  {len(metrics.measured)} measured · {len(metrics.unmeasured)} not measurable "
        f"here · {len(findings)} findings",
        file=sys.stderr,
    )
    print(f"  report   : {args.out}", file=sys.stderr)
    return 0


def _previous_snapshot(current: Path, current_doc: dict) -> Path | None:
    """The most recent snapshot from a DIFFERENT run.

    Matching on filename is not enough: `latest.json` is a copy of the newest
    timestamped snapshot, so excluding only the current path leaves its own twin
    as the "previous" one — and the report then compares a run against itself
    and cheerfully declares zero change. Compare `generated_at` instead, which
    identifies the run rather than the file.
    """
    stamp = current_doc.get("generated_at")
    candidates = []
    for path in sorted(current.parent.glob("*.json")):
        if path.resolve() == current.resolve():
            continue
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        if doc.get("generated_at") != stamp:
            candidates.append(path)
    return candidates[-1] if candidates else None


if __name__ == "__main__":
    raise SystemExit(main())
