#!/usr/bin/env python3
"""Enforce vulnerability remediation SLAs against SARIF output.

Closes the JD's "oversee vulnerability management ... and patching" with
something executable rather than a policy document. Reads the SARIF the pipeline
already produces, applies a severity-to-SLA matrix, and exits non-zero when a
finding is older than its allowance.

Two design decisions worth defending:

**Exceptions expire.** An exception register without expiry dates becomes a
permanent allowlist within a year — every risk acceptance made under deadline
pressure quietly becomes policy. An expired exception here fails the build, so
the conversation happens again on a schedule.

**First-seen dates come from a checked-in ledger, not the scan.** SARIF has no
notion of when a finding first appeared. Without a ledger, "age" resets on every
run and no SLA can ever be breached — the check would pass forever while
measuring nothing.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date, datetime, timedelta
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Days to remediate, by severity. Deliberately tighter than many published
# baselines for the two top bands: this system handles Art. 9 health data, and
# a 90-day critical SLA is indistinguishable from having none.
SLA_DAYS = {"critical": 7, "high": 30, "medium": 90, "low": 180}

LEDGER = REPO_ROOT / "evidence" / "vuln-ledger.json"
EXCEPTIONS = REPO_ROOT / "evidence" / "vuln-exceptions.json"


def normalise_severity(result: dict) -> str:
    props = result.get("properties", {})
    for key in ("security-severity", "problem.severity", "severity"):
        raw = str(props.get(key, "")).lower()
        if raw:
            try:  # SARIF security-severity is a 0-10 numeric string
                score = float(raw)
                if score >= 9.0:
                    return "critical"
                if score >= 7.0:
                    return "high"
                if score >= 4.0:
                    return "medium"
                return "low"
            except ValueError:
                if raw in SLA_DAYS:
                    return raw
                if raw == "error":
                    return "high"
                if raw == "warning":
                    return "medium"
    level = result.get("level", "warning")
    return {"error": "high", "warning": "medium", "note": "low"}.get(level, "medium")


def finding_id(result: dict) -> str:
    rule = result.get("ruleId", "unknown")
    locations = result.get("locations", [])
    where = "unknown"
    if locations:
        phys = locations[0].get("physicalLocation", {})
        where = phys.get("artifactLocation", {}).get("uri", "unknown")
    return f"{rule}::{where}"


def load(path: Path, default):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return default


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("sarif", nargs="*", type=Path, help="SARIF files to evaluate")
    parser.add_argument("--update-ledger", action="store_true",
                        help="Record newly seen findings (run on main, not on PRs)")
    parser.add_argument("--report", type=Path, default=REPO_ROOT / "evidence" / "vuln-sla-report.md")
    args = parser.parse_args()

    ledger: dict[str, str] = load(LEDGER, {})
    exceptions: dict[str, dict] = load(EXCEPTIONS, {})
    today = date.today()

    findings: dict[str, str] = {}
    for path in args.sarif:
        if not path.exists():
            print(f"warning: {path} not found, skipping", file=sys.stderr)
            continue
        doc = load(path, {})
        for run in doc.get("runs", []):
            for result in run.get("results", []):
                findings[finding_id(result)] = normalise_severity(result)

    breaches, expired, active = [], [], []
    for fid, severity in sorted(findings.items()):
        first_seen_str = ledger.get(fid)
        if first_seen_str is None:
            if args.update_ledger:
                ledger[fid] = today.isoformat()
            first_seen = today
        else:
            first_seen = datetime.fromisoformat(first_seen_str).date()

        age = (today - first_seen).days
        allowed = SLA_DAYS.get(severity, 90)
        due = first_seen + timedelta(days=allowed)

        exception = exceptions.get(fid)
        if exception:
            expiry = datetime.fromisoformat(exception["expires"]).date()
            if expiry < today:
                expired.append((fid, severity, exception, expiry))
            else:
                active.append((fid, severity, exception, expiry))
            continue

        if age > allowed:
            breaches.append((fid, severity, age, allowed, due))

    lines = [
        "# Vulnerability SLA report", "",
        f"Generated {today.isoformat()} by `scripts/vuln_sla.py`.", "",
        "| Severity | Remediate within |", "|---|---|",
    ]
    lines += [f"| {s} | {d} days |" for s, d in SLA_DAYS.items()]
    lines += ["", f"**{len(findings)} findings tracked · {len(breaches)} SLA breaches · "
                  f"{len(active)} active exceptions · {len(expired)} expired exceptions**", ""]

    if breaches:
        lines += ["## SLA breaches", "",
                  "| Finding | Severity | Age (days) | Allowed | Due |", "|---|---|--:|--:|---|"]
        lines += [f"| `{f}` | {s} | {a} | {al} | {d} |" for f, s, a, al, d in breaches]
        lines.append("")
    if expired:
        lines += ["## Expired exceptions", "",
                  "An expired exception fails the build by design: a risk acceptance that "
                  "renews itself silently is not an acceptance, it is an allowlist.", "",
                  "| Finding | Severity | Expired | Reason |", "|---|---|---|---|"]
        lines += [f"| `{f}` | {s} | {e} | {x.get('reason','—')} |" for f, s, x, e in expired]
        lines.append("")
    if active:
        lines += ["## Active exceptions", "",
                  "| Finding | Severity | Expires | Reason | Approved by |", "|---|---|---|---|---|"]
        lines += [f"| `{f}` | {s} | {e} | {x.get('reason','—')} | {x.get('approved_by','—')} |"
                  for f, s, x, e in active]
        lines.append("")
    if not breaches and not expired:
        lines += ["## Result", "", "All findings are within their remediation SLA.", ""]

    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text("\n".join(lines), encoding="utf-8")

    if args.update_ledger:
        LEDGER.parent.mkdir(parents=True, exist_ok=True)
        LEDGER.write_text(json.dumps(ledger, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(f"{len(findings)} findings · {len(breaches)} breaches · {len(expired)} expired exceptions")
    try:
        shown = args.report.relative_to(REPO_ROOT)
    except ValueError:
        shown = args.report  # report written outside the repo (e.g. a temp dir)
    print(f"report: {shown}")

    if breaches or expired:
        for fid, severity, age, allowed, _ in breaches:
            print(f"::error::SLA breach {fid} ({severity}) open {age}d, allowed {allowed}d",
                  file=sys.stderr)
        for fid, _, _, expiry in expired:
            print(f"::error::exception for {fid} expired {expiry}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
