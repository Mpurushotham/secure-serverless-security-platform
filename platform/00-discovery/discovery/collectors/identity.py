"""Checklist 5, 22 — root-account controls and third-party trust.

Root is the account's ultimate authority: it cannot be denied by an SCP in the
management account, it can undo any IAM policy, and it is the one identity that
must never be used for routine work. Almost every control that matters about it
is binary, which makes it cheap to check and inexcusable to skip.
"""

from __future__ import annotations

from typing import Any

from ..session import DiscoverySession
from .base import CollectorResult, register

# Vendors commonly given a cross-account role. Used only to label a trust as
# recognisable — an unrecognised external account is not automatically a
# finding, and a recognised one is not automatically safe.
KNOWN_VENDOR_ACCOUNTS: dict[str, str] = {
    "464622532012": "Datadog",
    "749430749651": "Datadog (EU)",
    "081625241005": "CrowdStrike",
    "292230061137": "Wiz",
    "197997052768": "Orca Security",
    "623664269543": "Lacework",
    "934182578557": "Snyk",
    "245132294130": "Sysdig",
}


@register
class RootControlsCollector:
    name = "root_controls"
    domain = "identity"
    checklist = (5,)

    def collect(self, session: DiscoverySession, regions: list[str]) -> CollectorResult:
        iam = session.client("iam", "us-east-1")
        summary = session.call(iam, "get_account_summary") or {}
        summary_map = summary.get("SummaryMap", {})

        virtual_mfa = session.paginate(
            iam, "list_virtual_mfa_devices", "VirtualMFADevices"
        )
        root_virtual_mfa = [
            d
            for d in virtual_mfa
            if (d.get("User") or {}).get("Arn", "").endswith(":root")
        ]

        # Organizations root-credential management: when enabled, member account
        # root credentials are centrally removable, which closes the "every
        # account has an unmonitored root" gap that grows with account count.
        org = session.client("organizations")
        # Not a paginated operation — it returns the full feature list in one
        # response, and asking for a paginator raises KeyError.
        # Also absent from botocore before ~1.36, in which case the session
        # records "unsupported" and this reports unknown rather than "off" — a
        # control we could not see is not a control that is missing.
        feature_response = session.call(org, "list_organizations_features")
        features = (feature_response or {}).get("EnabledFeatures", [])
        features_readable = feature_response is not None

        data: dict[str, Any] = {
            "root_mfa_enabled": bool(summary_map.get("AccountMFAEnabled", 0)),
            "root_access_keys": int(summary_map.get("AccountAccessKeysPresent", 0)),
            "root_signing_certificates": int(
                summary_map.get("AccountSigningCertificatesPresent", 0)
            ),
            "root_mfa_is_virtual": bool(root_virtual_mfa),
            # A virtual MFA app on a phone is materially weaker than a hardware
            # key for the identity that can undo every other control.
            "root_mfa_is_hardware": bool(summary_map.get("AccountMFAEnabled", 0))
            and not root_virtual_mfa,
            "organization_features_readable": features_readable,
            "organization_features_enabled": sorted(features),
            "root_credentials_management_enabled": (
                "RootCredentialsManagement" in features if features_readable else None
            ),
            "root_sessions_enabled": (
                "RootSessions" in features if features_readable else None
            ),
        }

        return CollectorResult(
            name=self.name, domain=self.domain, checklist=self.checklist, data=data
        )


@register
class ThirdPartyTrustCollector:
    name = "third_party"
    domain = "identity"
    checklist = (22,)

    def collect(self, session: DiscoverySession, regions: list[str]) -> CollectorResult:
        from .iam import analyse_trust_policy  # local import avoids a cycle

        iam = session.client("iam", "us-east-1")
        account_id = session.caller_identity().get("Account")

        external: list[dict[str, Any]] = []
        for role in session.paginate(iam, "list_roles", "Roles"):
            if role.get("Path", "/").startswith("/aws-service-role/"):
                continue

            trust = analyse_trust_policy(role.get("AssumeRolePolicyDocument"), account_id)
            if not (trust["external_accounts"] or trust["federated_principals"]):
                continue

            attached = session.paginate(
                iam, "list_attached_role_policies", "AttachedPolicies",
                RoleName=role["RoleName"],
            )
            external.append(
                {
                    "role": role["RoleName"],
                    "external_accounts": trust["external_accounts"],
                    "vendors": [
                        KNOWN_VENDOR_ACCOUNTS.get(a, "unrecognised")
                        for a in trust["external_accounts"]
                    ],
                    "federated_principals": trust["federated_principals"],
                    "has_external_id": trust["has_external_id_condition"],
                    "has_any_condition": trust["has_any_condition"],
                    "attached_policies": [p["PolicyName"] for p in attached],
                    "grants_admin": any(
                        p["PolicyName"] in {"AdministratorAccess", "PowerUserAccess"}
                        for p in attached
                    ),
                }
            )

        return CollectorResult(
            name=self.name,
            domain=self.domain,
            checklist=self.checklist,
            data={
                "external_trusts": external,
                "total": len(external),
                # A cross-account role with no ExternalId is the confused-deputy
                # shape: the vendor can be tricked into using your role on
                # someone else's behalf.
                "cross_account_without_external_id": [
                    e["role"]
                    for e in external
                    if e["external_accounts"] and not e["has_external_id"]
                ],
                # OIDC/SAML trust with no condition means any subject the
                # provider will issue a token for can assume the role — for
                # GitHub's provider, that is every repository on GitHub.
                "federated_without_conditions": [
                    e["role"]
                    for e in external
                    if e["federated_principals"] and not e["has_any_condition"]
                ],
                "external_granting_admin": [
                    e["role"] for e in external if e["grants_admin"]
                ],
            },
        )
