"""Checklist 8–11, 20 — audit, threat detection, posture and configuration coverage.

These collectors answer one question each: *is this control on, everywhere it
should be?* The interesting part is almost never the region where it is enabled;
it is the region where nobody looked. An attacker choosing where to operate
picks the region with no detector, and "GuardDuty is enabled" is true and
useless if it means one region out of seventeen.

So each collector reports per-region state and the report computes coverage as
a fraction, never as a boolean.
"""

from __future__ import annotations

from typing import Any

from ..session import DiscoverySession
from .base import CollectorResult, register


@register
class CloudTrailCollector:
    name = "cloudtrail"
    domain = "logging"
    checklist = (8,)

    def collect(self, session: DiscoverySession, regions: list[str]) -> CollectorResult:
        trails: dict[str, dict[str, Any]] = {}

        for region in regions:
            client = session.client("cloudtrail", region)
            described = session.call(client, "describe_trails", includeShadowTrails=False)
            if described is None:
                continue

            for trail in described.get("trailList", []):
                arn = trail["TrailARN"]
                if arn in trails:
                    continue

                status = session.call(client, "get_trail_status", Name=arn) or {}
                selectors = session.call(client, "get_event_selectors", TrailName=arn) or {}

                trails[arn] = {
                    "name": trail.get("Name"),
                    "home_region": trail.get("HomeRegion"),
                    "is_organization_trail": trail.get("IsOrganizationTrail", False),
                    "is_multi_region": trail.get("IsMultiRegionTrail", False),
                    # Without this, log files can be altered after the fact and
                    # the trail stops being evidence.
                    "log_file_validation": trail.get("LogFileValidationEnabled", False),
                    "kms_key_id": trail.get("KmsKeyId"),
                    "s3_bucket": trail.get("S3BucketName"),
                    "cloudwatch_logs_arn": trail.get("CloudWatchLogsLogGroupArn"),
                    "is_logging": status.get("IsLogging", False),
                    "latest_delivery_error": status.get("LatestDeliveryError"),
                    "data_events_configured": bool(
                        selectors.get("AdvancedEventSelectors")
                        or any(
                            s.get("DataResources")
                            for s in selectors.get("EventSelectors", [])
                        )
                    ),
                }

        return CollectorResult(
            name=self.name,
            domain=self.domain,
            checklist=self.checklist,
            data={
                "trails": list(trails.values()),
                "has_organization_trail": any(
                    t["is_organization_trail"] and t["is_logging"] for t in trails.values()
                ),
                "has_multi_region_trail": any(
                    t["is_multi_region"] and t["is_logging"] for t in trails.values()
                ),
            },
        )


@register
class GuardDutyCollector:
    name = "guardduty"
    domain = "logging"
    checklist = (9,)

    def collect(self, session: DiscoverySession, regions: list[str]) -> CollectorResult:
        by_region: dict[str, Any] = {}

        for region in regions:
            client = session.client("guardduty", region)
            detectors = session.paginate(client, "list_detectors", "DetectorIds")
            if not detectors:
                by_region[region] = {"enabled": False}
                continue

            detector = session.call(client, "get_detector", DetectorId=detectors[0]) or {}
            features = {
                f["Name"]: f.get("Status")
                for f in detector.get("Features", [])
            }
            by_region[region] = {
                "enabled": detector.get("Status") == "ENABLED",
                "finding_publishing_frequency": detector.get("FindingPublishingFrequency"),
                "features": features,
                "features_disabled": sorted(
                    name for name, status in features.items() if status != "ENABLED"
                ),
            }

        enabled = [r for r, v in by_region.items() if v.get("enabled")]
        return CollectorResult(
            name=self.name,
            domain=self.domain,
            checklist=self.checklist,
            data={
                "by_region": by_region,
                "regions_enabled": sorted(enabled),
                "regions_not_enabled": sorted(set(by_region) - set(enabled)),
                "coverage": f"{len(enabled)}/{len(by_region)}",
            },
        )


@register
class SecurityHubCollector:
    name = "securityhub"
    domain = "logging"
    checklist = (10,)

    def collect(self, session: DiscoverySession, regions: list[str]) -> CollectorResult:
        by_region: dict[str, Any] = {}

        for region in regions:
            client = session.client("securityhub", region)
            hub = session.call(client, "describe_hub")
            if hub is None:
                by_region[region] = {"enabled": False}
                continue

            standards = session.paginate(
                client, "get_enabled_standards", "StandardsSubscriptions"
            )
            by_region[region] = {
                "enabled": True,
                "auto_enable_controls": hub.get("AutoEnableControls"),
                "standards": [
                    {
                        "arn": s.get("StandardsArn"),
                        "status": s.get("StandardsStatus"),
                    }
                    for s in standards
                ],
            }

        enabled = [r for r, v in by_region.items() if v.get("enabled")]
        return CollectorResult(
            name=self.name,
            domain=self.domain,
            checklist=self.checklist,
            data={
                "by_region": by_region,
                "regions_enabled": sorted(enabled),
                "regions_not_enabled": sorted(set(by_region) - set(enabled)),
                "coverage": f"{len(enabled)}/{len(by_region)}",
            },
        )


@register
class ConfigCollector:
    name = "config"
    domain = "logging"
    checklist = (11,)

    def collect(self, session: DiscoverySession, regions: list[str]) -> CollectorResult:
        by_region: dict[str, Any] = {}

        for region in regions:
            client = session.client("config", region)
            recorders = session.call(client, "describe_configuration_recorders") or {}
            recorder_list = recorders.get("ConfigurationRecorders", [])
            channels = session.call(client, "describe_delivery_channels") or {}
            rules = session.paginate(client, "describe_config_rules", "ConfigRules")

            status = session.call(client, "describe_configuration_recorder_status") or {}
            recording = any(
                s.get("recording") for s in status.get("ConfigurationRecordersStatus", [])
            )

            by_region[region] = {
                "enabled": bool(recorder_list),
                "recording": recording,
                "records_all_resources": any(
                    (r.get("recordingGroup") or {}).get("allSupported")
                    for r in recorder_list
                ),
                "includes_global_resources": any(
                    (r.get("recordingGroup") or {}).get("includeGlobalResourceTypes")
                    for r in recorder_list
                ),
                "delivery_channels": len(channels.get("DeliveryChannels", [])),
                "rule_count": len(rules),
            }

        enabled = [r for r, v in by_region.items() if v.get("recording")]
        return CollectorResult(
            name=self.name,
            domain=self.domain,
            checklist=self.checklist,
            data={
                "by_region": by_region,
                "regions_recording": sorted(enabled),
                "regions_not_recording": sorted(set(by_region) - set(enabled)),
                "coverage": f"{len(enabled)}/{len(by_region)}",
            },
        )


@register
class AccessAnalyzerCollector:
    name = "access_analyzer"
    domain = "identity"
    checklist = (4, 22)

    def collect(self, session: DiscoverySession, regions: list[str]) -> CollectorResult:
        by_region: dict[str, Any] = {}

        for region in regions:
            client = session.client("accessanalyzer", region)
            analyzers = session.paginate(client, "list_analyzers", "analyzers")
            if not analyzers:
                by_region[region] = {"enabled": False}
                continue

            entries = []
            for analyzer in analyzers:
                findings = session.paginate(
                    client,
                    "list_findings_v2",
                    "findings",
                    analyzerArn=analyzer["arn"],
                    filter={"status": {"eq": ["ACTIVE"]}},
                )
                entries.append(
                    {
                        "name": analyzer.get("name"),
                        # EXTERNAL_ACCESS finds resources reachable from outside;
                        # UNUSED_ACCESS finds privilege nobody exercises. They are
                        # different analyzers and most estates only run the first.
                        "type": analyzer.get("type"),
                        "status": analyzer.get("status"),
                        "active_findings": len(findings),
                    }
                )
            by_region[region] = {"enabled": True, "analyzers": entries}

        types_present = {
            a["type"]
            for v in by_region.values()
            for a in v.get("analyzers", [])
        }
        enabled = [r for r, v in by_region.items() if v.get("enabled")]
        return CollectorResult(
            name=self.name,
            domain=self.domain,
            checklist=self.checklist,
            data={
                "by_region": by_region,
                "regions_enabled": sorted(enabled),
                "coverage": f"{len(enabled)}/{len(by_region)}",
                "analyzer_types_present": sorted(types_present),
                "has_unused_access_analyzer": any(
                    "UNUSED_ACCESS" in t for t in types_present
                ),
            },
        )


@register
class VulnerabilityServicesCollector:
    """Inspector and Macie — enablement state only, no findings pulled."""

    name = "vulnerability_services"
    domain = "code"
    checklist = (20,)

    def collect(self, session: DiscoverySession, regions: list[str]) -> CollectorResult:
        inspector: dict[str, Any] = {}
        macie: dict[str, Any] = {}
        account_id = session.caller_identity().get("Account")

        for region in regions:
            client = session.client("inspector2", region)
            status = session.call(
                client, "batch_get_account_status", accountIds=[account_id]
            )
            if status and status.get("accounts"):
                state = status["accounts"][0]
                inspector[region] = {
                    "status": (state.get("state") or {}).get("status"),
                    "resources": {
                        k: (v or {}).get("status")
                        for k, v in (state.get("resourceState") or {}).items()
                    },
                }
            else:
                inspector[region] = {"status": "DISABLED"}

            macie_client = session.client("macie2", region)
            macie_session = session.call(macie_client, "get_macie_session")
            macie[region] = {
                "status": (macie_session or {}).get("status", "DISABLED"),
            }

        return CollectorResult(
            name=self.name,
            domain=self.domain,
            checklist=self.checklist,
            data={
                "inspector": inspector,
                "macie": macie,
                "inspector_regions_enabled": sorted(
                    r for r, v in inspector.items() if v.get("status") == "ENABLED"
                ),
                "macie_regions_enabled": sorted(
                    r for r, v in macie.items() if v.get("status") == "ENABLED"
                ),
            },
        )
