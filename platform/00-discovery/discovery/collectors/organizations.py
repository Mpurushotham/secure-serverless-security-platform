"""Checklist 1, 2, 7 — Organization, accounts, OUs, and organization policies.

The management account is the highest-value target in any AWS estate: it can
create accounts, attach policies that constrain every other account, and remove
the guardrails that constrain itself. Everything here is read from it.
"""

from __future__ import annotations

from typing import Any

from ..session import DiscoverySession
from .base import CollectorResult, register

# Policy types Organizations supports. Enumerated rather than derived, because
# "which policy types exist but are switched off" is a question the report must
# answer for a reader who does not already know that RCPs, declarative policies
# and the per-service policy types arrived long after SCPs.
#
# This list is a floor, not a ceiling: `roots` is also scanned for types AWS
# reports that are not named here, so a newly launched policy type shows up as
# enabled rather than being silently dropped. Getting this wrong once already —
# BEDROCK_POLICY and S3_POLICY were enabled on the assessed org and absent from
# an earlier version of this tuple — is why that fallback exists.
POLICY_TYPES = (
    "SERVICE_CONTROL_POLICY",
    "RESOURCE_CONTROL_POLICY",
    "DECLARATIVE_POLICY_EC2",
    "TAG_POLICY",
    "BACKUP_POLICY",
    "AISERVICES_OPT_OUT_POLICY",
    "CHATBOT_POLICY",
    "S3_POLICY",
    "BEDROCK_POLICY",
)

# Services AWS SRA expects to be administered from a delegated account rather
# than from the management account.
EXPECTED_DELEGATED_SERVICES = (
    "guardduty.amazonaws.com",
    "securityhub.amazonaws.com",
    "config.amazonaws.com",
    "access-analyzer.amazonaws.com",
    "inspector2.amazonaws.com",
    "macie.amazonaws.com",
    "detective.amazonaws.com",
    "auditmanager.amazonaws.com",
)


@register
class OrganizationsCollector:
    name = "organizations"
    domain = "identity"
    checklist = (1, 2, 7)

    def collect(self, session: DiscoverySession, regions: list[str]) -> CollectorResult:
        org = session.client("organizations")

        described = session.call(org, "describe_organization")
        if described is None:
            # Either this is a standalone account or the identity cannot read
            # Organizations. Those are very different findings, so the audit
            # trail's outcome for DescribeOrganization decides which — the
            # report must not print "no organization" for an AccessDenied.
            last = session.calls[-1] if session.calls else None
            denied = last is not None and last.outcome == "denied"
            return CollectorResult(
                name=self.name,
                domain=self.domain,
                checklist=self.checklist,
                status="not-permitted" if denied else "observed",
                note=(
                    "DescribeOrganization was denied; organization structure was not assessed"
                    if denied
                    else "Account is not a member of an AWS Organization"
                ),
                data={"in_organization": False},
            )

        organization = described["Organization"]
        roots = session.paginate(org, "list_roots", "Roots")

        # Only enabled types can be listed or attached; querying a disabled type
        # returns PolicyTypeNotEnabledException, which would fill the audit trail
        # with errors that are not findings. Taking the union across roots also
        # picks up any type AWS has launched since POLICY_TYPES was last edited.
        enabled_types = sorted(
            {
                p["Type"]
                for root in roots
                for p in root.get("PolicyTypes", [])
                if p.get("Status") == "ENABLED"
            }
        )

        data: dict[str, Any] = {
            "in_organization": True,
            "organization_id": organization["Id"],
            "feature_set": organization.get("FeatureSet"),
            "management_account_id": organization.get("MasterAccountId"),
            "management_account_email": organization.get("MasterAccountEmail"),
            "policy_types_enabled": enabled_types,
            "policy_types_disabled": sorted(set(POLICY_TYPES) - set(enabled_types)),
            "roots": [],
            "accounts": [],
            "policies": {},
            "delegated_administrators": [],
        }

        for root in roots:
            enabled = {
                p["Type"] for p in root.get("PolicyTypes", []) if p.get("Status") == "ENABLED"
            }
            data["roots"].append(
                {
                    "id": root["Id"],
                    "name": root.get("Name"),
                    "policy_types_enabled": sorted(enabled),
                    "policy_types_available_but_disabled": sorted(
                        set(POLICY_TYPES) - enabled
                    ),
                    "account_ids": [
                        a["Id"]
                        for a in session.paginate(
                            org, "list_accounts_for_parent", "Accounts", ParentId=root["Id"]
                        )
                    ],
                    "attached_policy_ids": self._attached(
                        session, org, root["Id"], enabled_types
                    ),
                    "organizational_units": self._walk(
                        session, org, root["Id"], enabled_types
                    ),
                }
            )

        for account in session.paginate(org, "list_accounts", "Accounts"):
            data["accounts"].append(
                {
                    "id": account["Id"],
                    "name": account.get("Name"),
                    "email": account.get("Email"),
                    "status": account.get("Status"),
                    "joined_method": account.get("JoinedMethod"),
                    "is_management_account": account["Id"]
                    == organization.get("MasterAccountId"),
                }
            )

        for policy_type in enabled_types:
            policies = session.paginate(
                org, "list_policies", "Policies", Filter=policy_type
            )
            data["policies"][policy_type] = [
                {
                    "id": p["Id"],
                    "name": p.get("Name"),
                    "aws_managed": p.get("AwsManaged", False),
                    "description": p.get("Description"),
                    "targets": self._targets(session, org, p["Id"]),
                }
                for p in policies
            ]

        delegated = session.paginate(
            org, "list_delegated_administrators", "DelegatedAdministrators"
        )
        for admin in delegated:
            services = session.paginate(
                org,
                "list_delegated_services_for_account",
                "DelegatedServices",
                AccountId=admin["Id"],
            )
            data["delegated_administrators"].append(
                {
                    "account_id": admin["Id"],
                    "name": admin.get("Name"),
                    "services": [s["ServicePrincipal"] for s in services],
                }
            )

        administered = {
            svc
            for admin in data["delegated_administrators"]
            for svc in admin["services"]
        }
        data["security_services_without_delegated_admin"] = sorted(
            set(EXPECTED_DELEGATED_SERVICES) - administered
        )

        return CollectorResult(
            name=self.name, domain=self.domain, checklist=self.checklist, data=data
        )

    def _walk(
        self,
        session: DiscoverySession,
        org: Any,
        parent_id: str,
        enabled_types: list[str],
        depth: int = 0,
    ) -> list[dict[str, Any]]:
        """Recursively map the OU tree beneath a parent, with member accounts.

        Depth is capped at the Organizations service limit of five nested levels
        below the root. A cycle is impossible in a tree AWS validates, but an
        unbounded recursion driven by remote data is the kind of thing that is
        cheap to bound and expensive to debug.
        """
        if depth > 5:
            return []

        out: list[dict[str, Any]] = []
        for ou in session.paginate(
            org, "list_organizational_units_for_parent", "OrganizationalUnits",
            ParentId=parent_id,
        ):
            accounts = session.paginate(
                org, "list_accounts_for_parent", "Accounts", ParentId=ou["Id"]
            )
            out.append(
                {
                    "id": ou["Id"],
                    "name": ou.get("Name"),
                    "depth": depth,
                    "account_ids": [a["Id"] for a in accounts],
                    "attached_policy_ids": self._attached(
                        session, org, ou["Id"], enabled_types
                    ),
                    "children": self._walk(
                        session, org, ou["Id"], enabled_types, depth + 1
                    ),
                }
            )
        return out

    def _targets(self, session: DiscoverySession, org: Any, policy_id: str) -> list[dict[str, str]]:
        targets = session.paginate(
            org, "list_targets_for_policy", "Targets", PolicyId=policy_id
        )
        return [
            {"id": t["TargetId"], "name": t.get("Name", ""), "type": t.get("Type", "")}
            for t in targets
        ]

    def _attached(
        self,
        session: DiscoverySession,
        org: Any,
        target_id: str,
        enabled_types: list[str],
    ) -> list[str]:
        """IDs of policies attached directly to one target, across enabled types."""
        attached: list[str] = []
        for policy_type in enabled_types:
            attached.extend(
                p["Id"]
                for p in session.paginate(
                    org,
                    "list_policies_for_target",
                    "Policies",
                    TargetId=target_id,
                    Filter=policy_type,
                )
            )
        return attached
