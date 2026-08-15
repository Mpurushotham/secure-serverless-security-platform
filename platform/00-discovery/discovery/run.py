"""Discovery runner.

    python -m discovery.run --profile cap-lab --out platform/00-discovery/snapshots

Produces two artifacts:

* ``snapshots/raw/<account>-<timestamp>.json`` — everything observed, with real
  account IDs, ARNs and email addresses. **Gitignored.**
* ``snapshots/<timestamp>.json`` — the same content with identifiers redacted.
  This is the one that gets committed and that the report renders from.

Collectors run concurrently because a seventeen-region sweep is almost entirely
latency. They are independent by construction: each builds its own clients and
writes only its own result, so the only shared state is the session's call log,
which is appended under the GIL.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import replace
from pathlib import Path
from typing import Any

from . import collectors as collector_pkg
from .redact import Redactor
from .report import render
from .rules import evaluate
from .session import DiscoverySession


def run(
    profile: str | None,
    region: str,
    out_dir: Path,
    only: list[str] | None = None,
    regions_override: list[str] | None = None,
    max_workers: int = 8,
) -> tuple[dict[str, Any], dict[str, Any], Redactor]:
    session = DiscoverySession(profile=profile, default_region=region)

    identity = session.caller_identity()
    account_id = identity.get("Account", "unknown")
    started = time.time()

    regions = regions_override or session.enabled_regions()
    print(f"  identity : {identity.get('Arn', 'unknown')}", file=sys.stderr)
    print(f"  regions  : {len(regions)} ({', '.join(regions[:6])}…)", file=sys.stderr)

    instances = [
        c for c in collector_pkg.build_all() if not only or c.name in only
    ]
    print(f"  collectors: {len(instances)}", file=sys.stderr)

    results: dict[str, Any] = {}
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(_safe_collect, c, session, regions): c for c in instances
        }
        for future in as_completed(futures):
            collector = futures[future]
            result = future.result()
            results[collector.name] = result.to_dict()
            status = result.status
            marker = "ok" if status == "observed" else status
            print(f"    {collector.name:22s} {marker}", file=sys.stderr)

    snapshot = {
        "schema_version": 1,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(started)),
        "duration_seconds": round(time.time() - started, 1),
        "assessed_account": account_id,
        "assessed_principal": identity.get("Arn"),
        # Derived from the RAW ARN and stored as a boolean, because redaction
        # rewrites the ARN and a report that re-derives this from the redacted
        # string silently loses the caveat. Conclusions are drawn before
        # redaction; redaction only changes how they are presented.
        "assessor_is_privileged": _looks_privileged(identity.get("Arn") or ""),
        "regions_scanned": regions,
        "collectors": results,
        "api_calls": {
            "total": len(session.calls),
            "by_outcome": _count_by(session.calls, lambda c: c.outcome),
            "denied": [
                f"{c.service}:{c.operation}"
                for c in session.calls
                if c.outcome == "denied"
            ],
            "errors": [
                f"{c.service}:{c.operation} ({c.error_code})"
                for c in session.calls
                if c.outcome == "error"
            ],
        },
    }

    return _write(snapshot, out_dir, account_id)


def _looks_privileged(arn: str) -> bool:
    """Whether the assessing identity looks like an administrator.

    A heuristic on the principal name, and deliberately a loud one: the cost of
    a false positive is one extra paragraph of caveat, and the cost of a false
    negative is an assessment that quietly implies it ran under least privilege.
    """
    lowered = arn.lower()
    return any(
        marker in lowered
        for marker in ("admin", "poweruser", "root", "fullaccess", "superuser")
    )


def _safe_collect(collector: Any, session: DiscoverySession, regions: list[str]) -> Any:
    """Run one collector, converting an unexpected crash into a recorded status.

    A defect in one collector must not lose the other twenty results. The
    exception is ReadOnlyViolation, which is re-raised: a collector reaching for
    customer data is a defect in this tool, and continuing past it would be
    exactly the wrong instinct.
    """
    from .collectors.base import CollectorResult
    from .readonly_guard import ReadOnlyViolation

    try:
        return collector.collect(session, regions)
    except ReadOnlyViolation:
        raise
    except Exception as exc:  # noqa: BLE001 — deliberate boundary
        return CollectorResult(
            name=collector.name,
            domain=collector.domain,
            checklist=collector.checklist,
            status="error",
            note=f"{type(exc).__name__}: {exc}"[:300],
        )


def _count_by(items: list[Any], key: Any) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        counts[key(item)] = counts.get(key(item), 0) + 1
    return dict(sorted(counts.items()))


def _assert_redaction_preserves_findings(
    findings: list[Any], redacted: dict[str, Any]
) -> None:
    """Fail loudly if the redacted snapshot would produce different findings.

    The committed snapshot is what anyone else re-runs the rules against, via
    `make assess-offline` and in CI. If redaction changes what those rules
    conclude, the published assessment and the reproducible one disagree — and
    the published one is the one people read.

    This is a hard failure rather than a warning because the symptom is
    invisible: the report still renders, still looks complete, and is simply
    missing findings.
    """
    expected = {f.rule_id for f in findings}
    actual = {f.rule_id for f in evaluate(redacted)}
    if expected != actual:
        lost = sorted(expected - actual)
        gained = sorted(actual - expected)
        raise RuntimeError(
            "redaction changed the findings, which means the committed snapshot "
            "does not reproduce the published assessment.\n"
            f"  lost:   {lost}\n"
            f"  gained: {gained}\n"
            "Check discovery/redact.py — most likely a collected name is being "
            "matched inside an unrelated identifier."
        )


def _write(
    snapshot: dict[str, Any], out_dir: Path, account_id: str
) -> tuple[dict[str, Any], dict[str, Any], Redactor]:
    """Persist both snapshots and return the redacted one.

    Returns ``(raw, redacted)``. The redacted one is what the report renders
    from — the report is a committed file, so the safe artifact has to be the
    default path. The first version returned only the raw snapshot and the
    account ID went straight into `assessment.md`.
    """
    stamp = snapshot["generated_at"].replace(":", "").replace("-", "")

    raw_dir = out_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    raw_path = raw_dir / f"{account_id}-{stamp}.json"
    raw_path.write_text(json.dumps(snapshot, indent=2, default=str), encoding="utf-8")

    redactor = Redactor(account_id)
    redacted = redactor.apply(snapshot)
    out_dir.mkdir(parents=True, exist_ok=True)
    redacted_path = out_dir / f"{stamp}.json"
    body = json.dumps(redacted, indent=2, default=str)
    redacted_path.write_text(body, encoding="utf-8")
    (out_dir / "latest.json").write_text(body, encoding="utf-8")

    print(f"  raw      : {raw_path}  (gitignored)", file=sys.stderr)
    print(f"  redacted : {redacted_path}", file=sys.stderr)
    return snapshot, redacted, redactor


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="AWS read-only security discovery")
    parser.add_argument("--profile", default=None, help="AWS profile to assess")
    parser.add_argument("--region", default="us-east-1", help="Region for global services")
    parser.add_argument(
        "--regions",
        default=None,
        help="Comma-separated region list; default is every enabled region",
    )
    parser.add_argument(
        "--only", default=None, help="Comma-separated collector names to run"
    )
    parser.add_argument(
        "--out",
        default="platform/00-discovery/snapshots",
        type=Path,
        help="Snapshot output directory",
    )
    parser.add_argument(
        "--report",
        default="platform/00-discovery/report/assessment.md",
        type=Path,
        help="Where to write the rendered assessment",
    )
    parser.add_argument(
        "--from-snapshot",
        default=None,
        type=Path,
        help="Render from an existing snapshot instead of calling AWS",
    )
    args = parser.parse_args(argv)

    if args.from_snapshot:
        snapshot = json.loads(args.from_snapshot.read_text(encoding="utf-8"))
        print(f"  rendering from {args.from_snapshot} (no AWS calls)", file=sys.stderr)
        findings = evaluate(snapshot)
    else:
        raw, snapshot, redactor = run(
            profile=args.profile,
            region=args.region,
            out_dir=args.out,
            only=args.only.split(",") if args.only else None,
            regions_override=args.regions.split(",") if args.regions else None,
        )
        # Rules are evaluated against the RAW snapshot, then their text is
        # redacted — not the other way round.
        #
        # Evaluating redacted data was the original design and it was wrong: a
        # redaction bug silently dropped four findings, and the report still
        # looked complete. Redaction is a presentation concern and must not be
        # able to reach the conclusions. `_assert_redaction_preserves_findings`
        # then checks the committed artifact would reach the same ones.
        findings = evaluate(raw)
        _assert_redaction_preserves_findings(findings, snapshot)
        # Findings were computed from raw data, so their detail text still names
        # real users, roles and buckets. Same redactor instance, so a role named
        # in a finding gets the same pseudonym it has in the snapshot and the
        # reader can follow one to the other.
        findings = [
            replace(f, detail=redactor.text(f.detail)) for f in findings
        ]
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(render(snapshot, findings), encoding="utf-8")

    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1

    calls = snapshot["api_calls"]
    print(f"\n  {calls['total']} API calls: {calls['by_outcome']}", file=sys.stderr)
    print(f"  {len(findings)} findings: {counts}", file=sys.stderr)
    print(f"  report   : {args.report}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
