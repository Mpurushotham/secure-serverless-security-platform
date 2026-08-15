"""Checklist 4, 5, 22 — IAM identities, trust policies, and root controls.

Identity is the primary security boundary in AWS, so this is the collector whose
output matters most. It reads *metadata and policy documents*, never credentials.

The trust-policy analysis is the part worth reading. Most IAM review tooling
scores permission policies — what a principal can do — and skips trust policies,
which decide *who gets to be that principal*. An over-permissive trust policy on
a modestly-privileged role is usually worse than a wildcard on a role nobody can
assume.
"""

from __future__ import annotations

import csv
import datetime as dt
import io
from typing import Any

from ..session import DiscoverySession
from .base import CollectorResult, register

# Managed policies that confer effective administrator access.
ADMIN_POLICIES = {
    "AdministratorAccess",
    "IAMFullAccess",
    "PowerUserAccess",
    "AdministratorAccess-Amplify",
    "AWSOrganizationsFullAccess",
}

# Federation providers that are principals in a trust policy rather than an
# account. Treated separately because "trusted by an OIDC provider" needs the
# subject condition inspected, not just the principal.
_FEDERATED_KEYS = ("Federated",)


@register
class IamCollector:
    name = "iam"
    domain = "identity"
    checklist = (4, 22)

    def collect(self, session: DiscoverySession, regions: list[str]) -> CollectorResult:
        # IAM is global; it is only ever queried in one region.
        iam = session.client("iam", "us-east-1")
        account_id = session.caller_identity().get("Account")

        summary = session.call(iam, "get_account_summary") or {}
        summary_map = summary.get("SummaryMap", {})

        data: dict[str, Any] = {
            "account_summary": summary_map,
            "password_policy": self._password_policy(session, iam),
            "users": self._users(session, iam),
            "roles": self._roles(session, iam, account_id),
            "identity_providers": self._providers(session, iam),
            "credential_report": self._credential_report(session, iam),
        }

        data["totals"] = {
            "users": len(data["users"]),
            "roles": len(data["roles"]),
            "users_with_admin": sum(1 for u in data["users"] if u["has_admin_policy"]),
            "roles_with_admin": sum(1 for r in data["roles"] if r["has_admin_policy"]),
            "users_with_access_keys": sum(1 for u in data["users"] if u["access_keys"]),
            "roles_trusting_external_accounts": sum(
                1 for r in data["roles"] if r["trust"]["external_accounts"]
            ),
            "roles_without_permission_boundary": sum(
                1 for r in data["roles"] if not r["permission_boundary"]
            ),
        }

        return CollectorResult(
            name=self.name, domain=self.domain, checklist=self.checklist, data=data
        )

    # -- users ------------------------------------------------------------

    def _users(self, session: DiscoverySession, iam: Any) -> list[dict[str, Any]]:
        out = []
        for user in session.paginate(iam, "list_users", "Users"):
            name = user["UserName"]
            attached = session.paginate(
                iam, "list_attached_user_policies", "AttachedPolicies", UserName=name
            )
            groups = session.paginate(
                iam, "list_groups_for_user", "Groups", UserName=name
            )
            inline = session.paginate(
                iam, "list_user_policies", "PolicyNames", UserName=name
            )
            keys = session.paginate(
                iam, "list_access_keys", "AccessKeyMetadata", UserName=name
            )
            mfa = session.paginate(iam, "list_mfa_devices", "MFADevices", UserName=name)

            group_policies: list[str] = []
            for group in groups:
                group_policies.extend(
                    p["PolicyName"]
                    for p in session.paginate(
                        iam,
                        "list_attached_group_policies",
                        "AttachedPolicies",
                        GroupName=group["GroupName"],
                    )
                )

            policy_names = [p["PolicyName"] for p in attached] + group_policies
            out.append(
                {
                    "name": name,
                    "arn": user["Arn"],
                    "created": _iso(user.get("CreateDate")),
                    "password_last_used": _iso(user.get("PasswordLastUsed")),
                    "groups": [g["GroupName"] for g in groups],
                    "attached_policies": [p["PolicyName"] for p in attached],
                    "group_policies": group_policies,
                    "inline_policies": list(inline),
                    # Attached directly to a human identity, with no boundary and
                    # no session constraint — the shape SRA moves to federation.
                    "has_admin_policy": bool(set(policy_names) & ADMIN_POLICIES),
                    "admin_via": sorted(set(policy_names) & ADMIN_POLICIES),
                    "mfa_devices": len(mfa),
                    "access_keys": [
                        {
                            "id_suffix": k["AccessKeyId"][-4:],
                            "status": k["Status"],
                            "created": _iso(k.get("CreateDate")),
                            "age_days": _age_days(k.get("CreateDate")),
                        }
                        for k in keys
                    ],
                }
            )
        return out

    # -- roles ------------------------------------------------------------

    def _roles(
        self, session: DiscoverySession, iam: Any, account_id: str | None
    ) -> list[dict[str, Any]]:
        out = []
        for role in session.paginate(iam, "list_roles", "Roles"):
            name = role["RoleName"]
            path = role.get("Path", "/")
            # Service-linked roles are created and owned by AWS services; their
            # trust and permissions are not the customer's to change, so listing
            # them as findings is noise that buries the real ones.
            service_linked = path.startswith("/aws-service-role/")

            attached = (
                []
                if service_linked
                else session.paginate(
                    iam, "list_attached_role_policies", "AttachedPolicies", RoleName=name
                )
            )
            inline = (
                []
                if service_linked
                else session.paginate(
                    iam, "list_role_policies", "PolicyNames", RoleName=name
                )
            )
            policy_names = [p["PolicyName"] for p in attached]

            out.append(
                {
                    "name": name,
                    "arn": role["Arn"],
                    "path": path,
                    "service_linked": service_linked,
                    "created": _iso(role.get("CreateDate")),
                    "last_used": _iso((role.get("RoleLastUsed") or {}).get("LastUsedDate")),
                    "max_session_duration": role.get("MaxSessionDuration"),
                    "permission_boundary": (role.get("PermissionsBoundary") or {}).get(
                        "PermissionsBoundaryArn"
                    ),
                    "attached_policies": policy_names,
                    "inline_policies": list(inline),
                    "has_admin_policy": bool(set(policy_names) & ADMIN_POLICIES),
                    "admin_via": sorted(set(policy_names) & ADMIN_POLICIES),
                    "trust": analyse_trust_policy(
                        role.get("AssumeRolePolicyDocument"), account_id
                    ),
                }
            )
        return out

    # -- supporting -------------------------------------------------------

    def _providers(self, session: DiscoverySession, iam: Any) -> dict[str, list[Any]]:
        saml = session.call(iam, "list_saml_providers") or {}
        oidc = session.call(iam, "list_open_id_connect_providers") or {}
        return {
            "saml": [p["Arn"] for p in saml.get("SAMLProviderList", [])],
            "oidc": [p["Arn"] for p in oidc.get("OpenIDConnectProviderList", [])],
        }

    def _password_policy(self, session: DiscoverySession, iam: Any) -> dict[str, Any] | None:
        result = session.call(iam, "get_account_password_policy")
        if result is None:
            # NoSuchEntity means no policy is configured, which is itself the
            # finding. The audit trail distinguishes that from AccessDenied.
            return None
        return result.get("PasswordPolicy")

    def _credential_report(self, session: DiscoverySession, iam: Any) -> dict[str, Any]:
        """Root credential facts, from the account credential report.

        The report is the only place that answers "does root have access keys"
        and "when was root last used" directly. Generation is asynchronous, so a
        first call may report in-progress; that is recorded rather than retried
        in a loop, because a missing report is not worth blocking a sweep.
        """
        session.call(iam, "generate_credential_report")
        report = session.call(iam, "get_credential_report")
        if report is None or "Content" not in report:
            return {"available": False}

        rows = list(csv.DictReader(io.StringIO(report["Content"].decode("utf-8"))))
        root = next((r for r in rows if r.get("user") == "<root_account>"), None)

        stale_keys = [
            {"user": r["user"], "age_days": _age_days_from_iso(r.get("access_key_1_last_rotated"))}
            for r in rows
            if r.get("access_key_1_active") == "true"
            and _age_days_from_iso(r.get("access_key_1_last_rotated")) is not None
        ]

        return {
            "available": True,
            "user_count": len(rows),
            "root": None
            if root is None
            else {
                "mfa_active": root.get("mfa_active") == "true",
                "access_key_1_active": root.get("access_key_1_active") == "true",
                "access_key_2_active": root.get("access_key_2_active") == "true",
                "password_last_used": root.get("password_last_used"),
            },
            "active_access_keys": stale_keys,
        }


def analyse_trust_policy(document: Any, account_id: str | None = None) -> dict[str, Any]:
    """Classify who is allowed to assume a role, and under what conditions.

    The three things worth knowing, in order of how often they are missed:

    1. A wildcard principal (``"AWS": "*"``). With no condition this is the
       whole internet; with a condition it may be fine. Both are reported, and
       the presence of a condition is reported alongside — a scanner that says
       only "wildcard principal" produces findings people learn to dismiss.
    2. A trusted account that is not this one. Legitimate for vendors and
       cross-account automation, and the single most common way an estate is
       reached from outside it. ``sts:ExternalId`` is the confused-deputy
       control, so its absence is recorded per principal.
    3. A federated principal, where the security of the trust depends entirely
       on the ``sub``/``aud`` conditions rather than on the principal itself.

    ``account_id`` is what makes point 2 usable. A role that names its **own**
    account in the trust policy is the ordinary way to let principals in the
    account assume it — it is not cross-account access, and ``sts:ExternalId``
    is meaningless there because there is no third party to confuse. Reporting
    it as an external trust produces a finding on almost every estate, which is
    how a report teaches its reader to skip that column.
    """
    statements = (document or {}).get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    trusted_accounts: set[str] = set()
    federated: set[str] = set()
    services: set[str] = set()
    wildcard = False
    wildcard_conditioned = False
    has_external_id = False
    has_source_arn = False
    conditions_present = False

    for statement in statements:
        if statement.get("Effect") != "Allow":
            continue

        principal = statement.get("Principal", {})
        if isinstance(principal, str):
            principal = {"AWS": principal}

        condition = statement.get("Condition", {}) or {}
        if condition:
            conditions_present = True
        flat_condition_keys = {
            key.lower() for operator in condition.values() if isinstance(operator, dict)
            for key in operator
        }
        if "sts:externalid" in flat_condition_keys:
            has_external_id = True
        if "aws:sourcearn" in flat_condition_keys:
            has_source_arn = True

        for value in _as_list(principal.get("AWS")):
            if value == "*":
                wildcard = True
                wildcard_conditioned = bool(condition)
            elif value.startswith("arn:aws:iam::"):
                trusted_accounts.add(value.split(":")[4])
            elif value.isdigit():
                trusted_accounts.add(value)

        for key in _FEDERATED_KEYS:
            federated.update(_as_list(principal.get(key)))
        services.update(_as_list(principal.get("Service")))

    external = trusted_accounts - ({account_id} if account_id else set())
    return {
        "wildcard_principal": wildcard,
        "wildcard_has_condition": wildcard_conditioned,
        "trusted_accounts": sorted(trusted_accounts),
        "same_account_trust": bool(account_id and account_id in trusted_accounts),
        "external_accounts": sorted(external),
        "federated_principals": sorted(federated),
        "service_principals": sorted(services),
        "has_external_id_condition": has_external_id,
        "has_source_arn_condition": has_source_arn,
        "has_any_condition": conditions_present,
    }


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [v for v in value if isinstance(v, str)]
    return []


def _iso(value: Any) -> str | None:
    if isinstance(value, dt.datetime):
        return value.astimezone(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    return None


def _age_days(value: Any) -> int | None:
    if not isinstance(value, dt.datetime):
        return None
    return (dt.datetime.now(dt.UTC) - value.astimezone(dt.UTC)).days


def _age_days_from_iso(value: str | None) -> int | None:
    if not value or value in {"N/A", "not_supported", "no_information"}:
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return (dt.datetime.now(dt.UTC) - parsed).days
