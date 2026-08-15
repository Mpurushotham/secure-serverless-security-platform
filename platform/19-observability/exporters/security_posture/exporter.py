"""Prometheus exporter for AWS security posture and DevSecOps health.

Serves the metrics `platform/18-reporting` already computes, plus the ones that
only make sense as a time series. The design decisions worth reading:

**Scrapes are served from a cached snapshot, never computed inline.** A
discovery sweep takes ~30 seconds across 17 regions; Prometheus times a scrape
out in 10. Refreshing in a background thread and serving the last good result
means a slow AWS API degrades the *freshness* of the data rather than the
availability of the endpoint.

**Staleness is itself a metric.** `aws_discovery_last_success_timestamp_seconds`
is the most important series here. A dashboard showing "0 public buckets"
because the exporter died three days ago is worse than a dashboard showing
nothing — it is confidently wrong, and nobody investigates a green panel. Every
alert rule that reads posture data is paired with one that reads this.

**No overall score.** Same constraint as the report: `readiness/02-security-
metrics.md` rejects one, and a gauge called `aws_security_score` would be the
first thing anyone put on a wall.

Runs offline. With `--snapshot` it serves a committed snapshot and makes no AWS
calls at all, which is how the compose stack comes up on a laptop with no
credentials.
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(REPO_ROOT / "platform" / "00-discovery"))
sys.path.insert(0, str(REPO_ROOT / "platform" / "18-reporting"))

from discovery.rules import evaluate  # noqa: E402
from reporting.metrics import compute  # noqa: E402


class Registry:
    """A tiny text-format registry.

    Deliberately not `prometheus_client`. This exporter has to run in a
    distroless container and be auditable in one sitting — the same argument
    `mcp_core` makes for hand-writing JSON-RPC. The exposition format is six
    lines of specification and the dependency is not worth its supply chain.
    """

    def __init__(self) -> None:
        self._lines: list[str] = []
        self._seen: set[str] = set()

    def gauge(
        self,
        name: str,
        value: float | int | bool,
        help_text: str,
        labels: dict[str, str] | None = None,
    ) -> None:
        if name not in self._seen:
            self._lines.append(f"# HELP {name} {help_text}")
            self._lines.append(f"# TYPE {name} gauge")
            self._seen.add(name)
        rendered = ""
        if labels:
            pairs = ",".join(f'{k}="{_escape(v)}"' for k, v in sorted(labels.items()))
            rendered = "{" + pairs + "}"
        self._lines.append(f"{name}{rendered} {int(value) if isinstance(value, bool) else value}")

    def render(self) -> str:
        return "\n".join(self._lines) + "\n"


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


def _collector(snapshot: dict[str, Any], name: str) -> dict[str, Any]:
    entry = snapshot.get("collectors", {}).get(name, {})
    if entry.get("status") != "observed":
        return {}
    return entry.get("data", {}) or {}


def build(snapshot: dict[str, Any], collected_at: float) -> str:
    registry = Registry()
    findings = evaluate(snapshot)

    # -- freshness. Read this before trusting anything below it. ------------
    registry.gauge(
        "aws_discovery_last_success_timestamp_seconds",
        collected_at,
        "Unix time of the last successful discovery refresh. A posture panel is "
        "only as true as this is recent.",
    )
    registry.gauge(
        "aws_discovery_regions_scanned",
        len(snapshot.get("regions_scanned", [])),
        "Regions covered by the last sweep. Findings say nothing about the rest.",
    )
    calls = snapshot.get("api_calls", {})
    for outcome, count in (calls.get("by_outcome") or {}).items():
        registry.gauge(
            "aws_discovery_api_calls",
            count,
            "AWS API calls by outcome. A rise in denied means the assessing role lost access.",
            {"outcome": outcome},
        )

    collectors = snapshot.get("collectors", {})
    registry.gauge(
        "aws_discovery_collectors_failed",
        sum(1 for c in collectors.values() if c.get("status") != "observed"),
        "Collectors that did not complete. Their metrics are absent, not zero.",
    )

    # -- findings -----------------------------------------------------------
    by_severity: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    by_domain: dict[str, int] = {}
    for finding in findings:
        by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
        by_domain[finding.domain] = by_domain.get(finding.domain, 0) + 1

    for severity, count in by_severity.items():
        registry.gauge(
            "aws_security_findings",
            count,
            "Open findings by severity, from the committed rule set.",
            {"severity": severity},
        )
    for domain, count in by_domain.items():
        registry.gauge(
            "aws_security_findings_by_domain", count, "Open findings by domain.", {"domain": domain}
        )

    # -- coverage, always as a fraction ------------------------------------
    for collector, key in (
        ("guardduty", "regions_enabled"),
        ("securityhub", "regions_enabled"),
        ("config", "regions_recording"),
        ("access_analyzer", "regions_enabled"),
    ):
        data = _collector(snapshot, collector)
        by_region = data.get("by_region") or {}
        if not by_region:
            continue
        registry.gauge(
            "aws_detection_regions_enabled",
            len(data.get(key) or []),
            "Regions where the service is enabled. Compare against _total: an "
            "attacker operates in the region without a detector.",
            {"service": collector},
        )
        registry.gauge(
            "aws_detection_regions_total",
            len(by_region),
            "Regions scanned for this service.",
            {"service": collector},
        )

    # -- identity -----------------------------------------------------------
    iam = _collector(snapshot, "iam")
    totals = iam.get("totals") or {}
    for label, key in (
        ("users", "users"),
        ("roles", "roles"),
        ("users_with_admin", "users_with_admin"),
        ("roles_with_admin", "roles_with_admin"),
        ("roles_without_boundary", "roles_without_permission_boundary"),
    ):
        if key in totals:
            registry.gauge(
                "aws_iam_principals", totals[key], "IAM principal counts.", {"kind": label}
            )

    for user in iam.get("users", []):
        for access_key in user.get("access_keys", []):
            if access_key.get("status") == "Active" and access_key.get("age_days") is not None:
                registry.gauge(
                    "aws_iam_access_key_age_days",
                    access_key["age_days"],
                    "Age of an active access key. A static credential cannot expire.",
                    {"user": user["name"]},
                )

    root = _collector(snapshot, "root_controls")
    if root:
        registry.gauge(
            "aws_root_mfa_enabled", bool(root.get("root_mfa_enabled")), "Root has an MFA device."
        )
        registry.gauge(
            "aws_root_mfa_is_hardware",
            bool(root.get("root_mfa_is_hardware")),
            "Root MFA is a hardware key rather than a phone app.",
        )
        registry.gauge(
            "aws_root_access_keys",
            root.get("root_access_keys", 0),
            "Root access keys. There is no supported reason for this to be non-zero.",
        )

    # -- exposure and data --------------------------------------------------
    exposure = _collector(snapshot, "exposure")
    if exposure:
        registry.gauge(
            "aws_internet_facing_resources",
            exposure.get("total_internet_facing", 0),
            "Resources reachable from the internet.",
        )
        registry.gauge(
            "aws_unauthenticated_function_urls",
            len(exposure.get("unauthenticated_function_urls") or []),
            "Lambda function URLs with AuthType NONE — public endpoints bypassing API Gateway.",
        )

    sg = _collector(snapshot, "security_groups")
    if sg:
        registry.gauge(
            "aws_security_groups_open_to_internet",
            len(sg.get("groups_open_to_internet") or []),
            "Security groups allowing ingress from 0.0.0.0/0.",
        )

    s3 = _collector(snapshot, "s3")
    if s3:
        registry.gauge(
            "aws_s3_account_public_access_blocked",
            bool(s3.get("account_fully_blocked")),
            "Account-level S3 public access block, which covers buckets not yet created.",
        )
        registry.gauge(
            "aws_s3_buckets_unencrypted",
            len(s3.get("buckets_unencrypted") or []),
            "Buckets with no default encryption.",
        )

    kms = _collector(snapshot, "kms")
    if kms:
        registry.gauge(
            "aws_kms_customer_keys",
            kms.get("total", 0),
            "Customer-managed keys. Zero means encryption cannot act as an access boundary.",
        )
        registry.gauge(
            "aws_kms_keys_without_rotation",
            len(kms.get("without_rotation") or []),
            "CMKs without rotation.",
        )

    # -- pipeline health ----------------------------------------------------
    cicd = _collector(snapshot, "cicd")
    if cicd:
        registry.gauge(
            "devsecops_workflows_use_oidc",
            bool(cicd.get("any_uses_aws_oidc")),
            "CI authenticates to AWS via OIDC rather than a stored credential.",
        )
        registry.gauge(
            "devsecops_actions_not_sha_pinned",
            len(cicd.get("total_actions_not_sha_pinned") or []),
            "Actions pinned to a movable tag rather than a commit SHA.",
        )

    # -- the metric set from 18-reporting, for anything not covered above ---
    metric_set = compute(snapshot)
    registry.gauge(
        "security_metrics_measurable",
        len(metric_set.measured),
        "Metrics computable from a snapshot.",
    )
    registry.gauge(
        "security_metrics_unmeasurable",
        len(metric_set.unmeasured),
        "Metrics defined but not derivable here. Non-zero by design — see the posture report.",
    )

    return registry.render()


class Exporter:
    def __init__(self, snapshot_path: Path, interval: int) -> None:
        self._path = snapshot_path
        self._interval = interval
        self._lock = threading.Lock()
        self._payload = "# no data yet\n"
        self._collected_at = 0.0
        self._refresh()

    def _refresh(self) -> None:
        try:
            snapshot = json.loads(self._path.read_text(encoding="utf-8"))
            payload = build(snapshot, time.time())
            with self._lock:
                self._payload = payload
                self._collected_at = time.time()
        except Exception as exc:  # noqa: BLE001 — a refresh failure must not kill the loop
            print(f"refresh failed: {type(exc).__name__}: {exc}", file=sys.stderr)

    def run_forever(self) -> None:
        while True:
            time.sleep(self._interval)
            self._refresh()

    @property
    def payload(self) -> str:
        with self._lock:
            return self._payload


def serve(exporter: Exporter, port: int) -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 — BaseHTTPRequestHandler's contract
            if self.path == "/healthz":
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok\n")
                return
            if self.path != "/metrics":
                self.send_response(404)
                self.end_headers()
                return
            body = exporter.payload.encode("utf-8")
            self.send_response(200)
            self.send_header("content-type", "text/plain; version=0.0.4")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args: Any) -> None:
            """Silence per-request logging — Prometheus scrapes every 15s."""

    HTTPServer(("", port), Handler).serve_forever()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="AWS security posture exporter")
    parser.add_argument(
        "--snapshot",
        type=Path,
        default=REPO_ROOT / "platform" / "00-discovery" / "snapshots" / "latest.json",
    )
    parser.add_argument("--port", type=int, default=9877)
    parser.add_argument("--interval", type=int, default=300)
    parser.add_argument("--once", action="store_true", help="Print metrics and exit")
    args = parser.parse_args(argv)

    exporter = Exporter(args.snapshot, args.interval)
    if args.once:
        print(exporter.payload)
        return 0

    threading.Thread(target=exporter.run_forever, daemon=True).start()
    print(f"serving :{args.port}/metrics from {args.snapshot}", file=sys.stderr)
    serve(exporter, args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
