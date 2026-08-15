"""Rules must fire when they should and stay silent when they should not.

The second half is the harder one and the reason these tests exist. A rule that
fires on a healthy estate produces a report people stop reading, and the finding
that mattered goes with it. So every rule gets a negative case built from a
snapshot where the control is correctly configured.
"""

from __future__ import annotations

import pytest
from discovery.rules import RULES, evaluate


def snapshot(**collectors: dict) -> dict:
    """A snapshot containing only the collectors a test cares about."""
    return {
        "assessed_account": "123456789012",
        "collectors": {
            name: {"domain": "identity", "checklist": [1], "status": "observed", "data": data}
            for name, data in collectors.items()
        },
        "api_calls": {"total": 0, "by_outcome": {}, "denied": [], "errors": []},
    }


def fired(result: list, rule_id: str) -> bool:
    return any(f.rule_id == rule_id for f in result)


class TestRuleCatalogueIntegrity:
    def test_rule_ids_are_unique(self) -> None:
        ids = [r.id for r in RULES]
        assert len(ids) == len(set(ids))

    def test_every_rule_has_a_remediation(self) -> None:
        for rule in RULES:
            assert rule.remediation.strip(), f"{rule.id} has no remediation"

    def test_every_rule_declares_a_checklist_item(self) -> None:
        for rule in RULES:
            assert rule.checklist, f"{rule.id} maps to no checklist item"

    def test_severities_are_from_the_sla_matrix(self) -> None:
        allowed = {"critical", "high", "medium", "low", "info"}
        for rule in RULES:
            assert rule.severity in allowed, f"{rule.id} has severity {rule.severity}"

    def test_a_clean_snapshot_produces_no_findings(self) -> None:
        # An empty snapshot means no collector reported, so no rule has grounds
        # to fire. A rule that fires on absent data is asserting something it
        # cannot know.
        assert evaluate(snapshot()) == []

    def test_a_failed_collector_suppresses_its_rules_rather_than_passing(self) -> None:
        broken = snapshot()
        broken["collectors"]["iam"] = {
            "domain": "identity",
            "checklist": [4],
            "status": "error",
            "data": {},
        }
        assert not [f for f in evaluate(broken) if f.rule_id.startswith("IAM-")]


class TestOrganizationRules:
    def test_delegated_admin_fires_when_none_configured(self) -> None:
        s = snapshot(organizations={
            "in_organization": True,
            "security_services_without_delegated_admin": ["guardduty.amazonaws.com"],
        })
        assert fired(evaluate(s), "ORG-001")

    def test_delegated_admin_silent_when_all_delegated(self) -> None:
        s = snapshot(organizations={
            "in_organization": True,
            "security_services_without_delegated_admin": [],
        })
        assert not fired(evaluate(s), "ORG-001")

    def test_delegated_admin_silent_for_standalone_account(self) -> None:
        s = snapshot(organizations={"in_organization": False})
        assert not fired(evaluate(s), "ORG-001")

    def test_scp_on_empty_ou_fires(self) -> None:
        s = snapshot(organizations={
            "in_organization": True,
            "roots": [{
                "id": "r-1", "name": "Root",
                "organizational_units": [
                    {"id": "ou-empty", "name": "Prod", "account_ids": [], "children": []},
                ],
            }],
            "policies": {"SERVICE_CONTROL_POLICY": [
                {"name": "require-mfa", "aws_managed": False,
                 "targets": [{"id": "ou-empty", "name": "Prod", "type": "ORGANIZATIONAL_UNIT"}]},
            ]},
        })
        assert fired(evaluate(s), "ORG-002")

    def test_scp_on_populated_ou_is_silent(self) -> None:
        s = snapshot(organizations={
            "in_organization": True,
            "roots": [{
                "id": "r-1", "name": "Root",
                "organizational_units": [
                    {"id": "ou-full", "name": "Prod", "account_ids": ["1"], "children": []},
                ],
            }],
            "policies": {"SERVICE_CONTROL_POLICY": [
                {"name": "require-mfa", "aws_managed": False,
                 "targets": [{"id": "ou-full", "name": "Prod", "type": "ORGANIZATIONAL_UNIT"}]},
            ]},
        })
        assert not fired(evaluate(s), "ORG-002")

    def test_scp_on_ou_whose_child_has_accounts_is_silent(self) -> None:
        # The rule must look through the tree, not just at direct membership.
        s = snapshot(organizations={
            "in_organization": True,
            "roots": [{
                "id": "r-1", "name": "Root",
                "organizational_units": [{
                    "id": "ou-parent", "name": "Workloads", "account_ids": [],
                    "children": [
                        {"id": "ou-child", "name": "Prod", "account_ids": ["1"], "children": []}
                    ],
                }],
            }],
            "policies": {"SERVICE_CONTROL_POLICY": [
                {"name": "encrypt", "aws_managed": False,
                 "targets": [{"id": "ou-parent", "name": "Workloads",
                              "type": "ORGANIZATIONAL_UNIT"}]},
            ]},
        })
        assert not fired(evaluate(s), "ORG-002")


class TestIamRules:
    def test_admin_on_user_fires(self) -> None:
        s = snapshot(iam={"users": [{"name": "alice", "has_admin_policy": True,
                                     "access_keys": []}], "roles": []})
        assert fired(evaluate(s), "IAM-001")

    def test_admin_on_user_silent_without_admin(self) -> None:
        s = snapshot(iam={"users": [{"name": "alice", "has_admin_policy": False,
                                     "access_keys": []}], "roles": []})
        assert not fired(evaluate(s), "IAM-001")

    def test_admin_execution_role_fires_for_lambda(self) -> None:
        s = snapshot(iam={"users": [], "roles": [{
            "name": "fn-role", "has_admin_policy": True, "service_linked": False,
            "permission_boundary": None,
            "trust": {"service_principals": ["lambda.amazonaws.com"]},
        }]})
        assert fired(evaluate(s), "IAM-004")

    def test_admin_role_for_humans_is_not_an_execution_role_finding(self) -> None:
        s = snapshot(iam={"users": [], "roles": [{
            "name": "break-glass", "has_admin_policy": True, "service_linked": False,
            "permission_boundary": "arn:aws:iam::1:policy/b",
            "trust": {"service_principals": []},
        }]})
        assert not fired(evaluate(s), "IAM-004")

    def test_service_linked_roles_do_not_trigger_boundary_rule(self) -> None:
        s = snapshot(iam={"users": [], "roles": [{
            "name": "AWSServiceRoleForX", "service_linked": True,
            "permission_boundary": None, "has_admin_policy": False,
            "trust": {"service_principals": []},
        }]})
        assert not fired(evaluate(s), "IAM-003")

    @pytest.mark.parametrize("duration,should_fire", [
        ("PT1H", False), ("PT4H", False), ("PT12H", True), ("PT30M", False),
    ])
    def test_session_duration_threshold(self, duration: str, should_fire: bool) -> None:
        s = snapshot(identity_center={
            "enabled": True,
            "permission_sets": [{"name": "Admin", "grants_admin": True,
                                 "session_duration": duration,
                                 "has_permission_boundary": True}],
        })
        assert fired(evaluate(s), "IAM-009") is should_fire


class TestDetectionRules:
    def test_config_not_recording_mentions_orphaned_rules(self) -> None:
        s = snapshot(config={
            "regions_not_recording": ["eu-north-1"],
            "by_region": {"eu-north-1": {"recording": False, "rule_count": 343}},
        })
        findings = [f for f in evaluate(s) if f.rule_id == "LOG-004"]
        assert findings
        # The correlation is the whole value of the finding: rules exist and
        # evaluate nothing.
        assert "343" in findings[0].detail

    def test_config_recording_everywhere_is_silent(self) -> None:
        s = snapshot(config={
            "regions_not_recording": [],
            "by_region": {"eu-north-1": {"recording": True, "rule_count": 343}},
        })
        assert not fired(evaluate(s), "LOG-004")

    def test_unused_access_analyzer_alone_still_fires(self) -> None:
        s = snapshot(access_analyzer={
            "analyzer_types_present": ["ACCOUNT_UNUSED_ACCESS"], "by_region": {},
        })
        assert fired(evaluate(s), "DET-005")

    def test_external_access_analyzer_present_is_silent(self) -> None:
        s = snapshot(access_analyzer={
            "analyzer_types_present": ["ACCOUNT", "ACCOUNT_UNUSED_ACCESS"], "by_region": {},
        })
        assert not fired(evaluate(s), "DET-005")


class TestSeverityOrdering:
    def test_findings_are_returned_most_severe_first(self) -> None:
        s = snapshot(
            iam={"users": [{"name": "a", "has_admin_policy": True, "access_keys": []}],
                 "roles": [{"name": "fn", "has_admin_policy": True, "service_linked": False,
                            "permission_boundary": None,
                            "trust": {"service_principals": ["lambda.amazonaws.com"]}}]},
        )
        result = evaluate(s)
        assert result[0].severity == "critical"
