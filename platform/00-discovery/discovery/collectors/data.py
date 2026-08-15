"""Checklist 12, 13, 17 — encryption, S3 exposure, and secrets management.

Everything here is configuration. No object is read, no secret value is
retrieved, no parameter value is fetched. ``readonly_guard`` refuses those calls
outright, so a mistake in this file becomes an exception rather than a leak.
"""

from __future__ import annotations

import datetime as dt
from typing import Any

from ..session import DiscoverySession
from .base import CollectorResult, register


@register
class KmsCollector:
    name = "kms"
    domain = "data"
    checklist = (12,)

    def collect(self, session: DiscoverySession, regions: list[str]) -> CollectorResult:
        keys: list[dict[str, Any]] = []

        for region in regions:
            client = session.client("kms", region)
            for entry in session.paginate(client, "list_keys", "Keys"):
                described = session.call(client, "describe_key", KeyId=entry["KeyId"])
                if described is None:
                    continue
                meta = described["KeyMetadata"]

                # AWS-managed keys cannot have their rotation or policy changed
                # by the customer, so reporting on them is noise. The customer's
                # own keys are the ones with decisions attached.
                if meta.get("KeyManager") != "CUSTOMER":
                    continue

                rotation = session.call(client, "get_key_rotation_status", KeyId=meta["KeyId"])
                keys.append(
                    {
                        "key_id": meta["KeyId"],
                        "region": region,
                        "arn": meta.get("Arn"),
                        "description": meta.get("Description"),
                        "enabled": meta.get("Enabled", False),
                        "state": meta.get("KeyState"),
                        "spec": meta.get("KeySpec"),
                        "usage": meta.get("KeyUsage"),
                        "origin": meta.get("Origin"),
                        "multi_region": meta.get("MultiRegion", False),
                        "rotation_enabled": (rotation or {}).get("KeyRotationEnabled"),
                    }
                )

        active = [k for k in keys if k["state"] == "Enabled"]
        return CollectorResult(
            name=self.name,
            domain=self.domain,
            checklist=self.checklist,
            data={
                "customer_managed_keys": keys,
                "total": len(keys),
                "without_rotation": [
                    k["key_id"] for k in active if k["rotation_enabled"] is False
                ],
            },
        )


@register
class S3Collector:
    name = "s3"
    domain = "data"
    checklist = (13,)

    def collect(self, session: DiscoverySession, regions: list[str]) -> CollectorResult:
        client = session.client("s3")
        control = session.client("s3control")
        account_id = session.caller_identity().get("Account")

        listed = session.call(client, "list_buckets") or {}
        buckets: list[dict[str, Any]] = []

        for bucket in listed.get("Buckets", []):
            name = bucket["Name"]
            location = session.call(client, "get_bucket_location", Bucket=name) or {}
            # us-east-1 is reported as None, a long-standing API quirk.
            region = location.get("LocationConstraint") or "us-east-1"
            regional = session.client("s3", region)

            pab = session.call(
                regional, "get_public_access_block", Bucket=name
            ) or {}
            pab_config = pab.get("PublicAccessBlockConfiguration", {})
            encryption = session.call(
                regional, "get_bucket_encryption", Bucket=name
            ) or {}
            versioning = session.call(regional, "get_bucket_versioning", Bucket=name) or {}
            policy_status = session.call(
                regional, "get_bucket_policy_status", Bucket=name
            ) or {}
            logging_cfg = session.call(regional, "get_bucket_logging", Bucket=name) or {}

            rules = encryption.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
            algorithms = [
                (r.get("ApplyServerSideEncryptionByDefault") or {}).get("SSEAlgorithm")
                for r in rules
            ]

            buckets.append(
                {
                    "name": name,
                    "region": region,
                    "created": _iso(bucket.get("CreationDate")),
                    "public_access_block": {
                        "block_public_acls": pab_config.get("BlockPublicAcls", False),
                        "block_public_policy": pab_config.get("BlockPublicPolicy", False),
                        "ignore_public_acls": pab_config.get("IgnorePublicAcls", False),
                        "restrict_public_buckets": pab_config.get(
                            "RestrictPublicBuckets", False
                        ),
                    },
                    "fully_blocked": all(
                        pab_config.get(k, False)
                        for k in (
                            "BlockPublicAcls",
                            "BlockPublicPolicy",
                            "IgnorePublicAcls",
                            "RestrictPublicBuckets",
                        )
                    ),
                    "policy_is_public": policy_status.get("PolicyStatus", {}).get(
                        "IsPublic", False
                    ),
                    "encryption_algorithms": [a for a in algorithms if a],
                    "bucket_key_enabled": any(r.get("BucketKeyEnabled") for r in rules),
                    "versioning": versioning.get("Status", "Disabled"),
                    "mfa_delete": versioning.get("MFADelete", "Disabled"),
                    "access_logging": bool(logging_cfg.get("LoggingEnabled")),
                }
            )

        account_pab = session.call(
            control, "get_public_access_block", AccountId=account_id
        ) or {}
        account_pab_config = account_pab.get("PublicAccessBlockConfiguration", {})

        return CollectorResult(
            name=self.name,
            domain=self.domain,
            checklist=self.checklist,
            data={
                "buckets": buckets,
                "total": len(buckets),
                # The account-level block is the control that matters: it applies
                # to buckets that do not exist yet, so it cannot be forgotten on
                # the next one somebody creates.
                "account_public_access_block": {
                    "block_public_acls": account_pab_config.get("BlockPublicAcls", False),
                    "block_public_policy": account_pab_config.get("BlockPublicPolicy", False),
                    "ignore_public_acls": account_pab_config.get("IgnorePublicAcls", False),
                    "restrict_public_buckets": account_pab_config.get(
                        "RestrictPublicBuckets", False
                    ),
                },
                "account_fully_blocked": all(
                    account_pab_config.get(k, False)
                    for k in (
                        "BlockPublicAcls",
                        "BlockPublicPolicy",
                        "IgnorePublicAcls",
                        "RestrictPublicBuckets",
                    )
                ),
                "buckets_not_fully_blocked": [
                    b["name"] for b in buckets if not b["fully_blocked"]
                ],
                "buckets_unencrypted": [
                    b["name"] for b in buckets if not b["encryption_algorithms"]
                ],
                "buckets_public_by_policy": [
                    b["name"] for b in buckets if b["policy_is_public"]
                ],
            },
        )


@register
class SecretsCollector:
    name = "secrets"
    domain = "data"
    checklist = (17,)

    def collect(self, session: DiscoverySession, regions: list[str]) -> CollectorResult:
        secrets: list[dict[str, Any]] = []
        parameters: list[dict[str, Any]] = []

        for region in regions:
            sm = session.client("secretsmanager", region)
            for secret in session.paginate(sm, "list_secrets", "SecretList"):
                secrets.append(
                    {
                        "name": secret.get("Name"),
                        "region": region,
                        "rotation_enabled": secret.get("RotationEnabled", False),
                        "rotation_days": (secret.get("RotationRules") or {}).get(
                            "AutomaticallyAfterDays"
                        ),
                        "kms_key_id": secret.get("KmsKeyId"),
                        "last_rotated": _iso(secret.get("LastRotatedDate")),
                        "last_changed": _iso(secret.get("LastChangedDate")),
                        "days_since_rotation": _age_days(secret.get("LastRotatedDate")),
                    }
                )

            ssm = session.client("ssm", region)
            # describe_parameters returns metadata only. get_parameter, which
            # returns values, is in readonly_guard's denied set.
            for param in session.paginate(ssm, "describe_parameters", "Parameters"):
                parameters.append(
                    {
                        "name": param.get("Name"),
                        "region": region,
                        "type": param.get("Type"),
                        "kms_key_id": param.get("KeyId"),
                        "tier": param.get("Tier"),
                    }
                )

        return CollectorResult(
            name=self.name,
            domain=self.domain,
            checklist=self.checklist,
            data={
                "secrets": secrets,
                "parameters": parameters,
                "secrets_total": len(secrets),
                "secrets_without_rotation": [
                    s["name"] for s in secrets if not s["rotation_enabled"]
                ],
                "parameters_total": len(parameters),
                # A plaintext String parameter whose name suggests a credential
                # is the classic "secret in config" pattern. The value is never
                # read; the name and type are enough to raise the question.
                "plaintext_parameters_with_secret_names": [
                    p["name"]
                    for p in parameters
                    if p["type"] == "String" and _looks_secret(p["name"] or "")
                ],
            },
        )


_SECRET_HINTS = (
    "secret", "password", "passwd", "token", "apikey", "api_key",
    "credential", "private_key", "privatekey", "access_key",
)


def _looks_secret(name: str) -> bool:
    lowered = name.lower()
    return any(hint in lowered for hint in _SECRET_HINTS)


def _iso(value: Any) -> str | None:
    if isinstance(value, dt.datetime):
        return value.astimezone(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    return None


def _age_days(value: Any) -> int | None:
    if not isinstance(value, dt.datetime):
        return None
    return (dt.datetime.now(dt.UTC) - value.astimezone(dt.UTC)).days
