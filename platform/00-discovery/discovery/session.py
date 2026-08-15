"""Session construction, region enumeration, and the API-call audit trail.

Every AWS call this tool makes is recorded: service, operation, region,
outcome, duration. That record is the difference between "we ran an assessment"
and "here is exactly what we touched, and you can check it against CloudTrail".
It reuses the audit record shape from ``mcp_core.audit`` rather than inventing a
second one.
"""

from __future__ import annotations

import json
import shutil

# subprocess is used for exactly one thing: invoking the AWS CLI to mint
# short-lived credentials for a profile boto3 cannot resolve on its own.
# See _export_credentials for why that call is safe.
import subprocess  # noqa: S404  # nosec B404
import time
from dataclasses import dataclass, field
from typing import Any

import boto3
import botocore.exceptions
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError, OperationNotPageableError

from . import readonly_guard

# Adaptive retries back off when an account is being swept across many regions
# at once; the default "legacy" mode gives up too early on throttling and
# produces gaps that look like absent resources.
_BOTO_CONFIG = Config(
    retries={"max_attempts": 6, "mode": "adaptive"},
    user_agent_extra="ssp-discovery/0.1",
)


@dataclass
class ApiCall:
    """One AWS API call, as it will appear in the audit trail."""

    service: str
    operation: str
    region: str | None
    outcome: str  # "ok" | "denied" | "unsupported" | "error" | "refused"
    duration_ms: float
    error_code: str | None = None

    def to_dict(self) -> dict[str, Any]:
        body: dict[str, Any] = {
            "service": self.service,
            "operation": self.operation,
            "outcome": self.outcome,
            "duration_ms": round(self.duration_ms, 1),
        }
        if self.region:
            body["region"] = self.region
        if self.error_code:
            body["error_code"] = self.error_code
        return body


@dataclass
class DiscoverySession:
    """A boto3 session with the read-only guard installed and calls recorded."""

    profile: str | None = None
    default_region: str = "us-east-1"
    calls: list[ApiCall] = field(default_factory=list)
    _session: Any = None

    def __post_init__(self) -> None:
        self._session = self._build_session()
        # Fail closed before any client is built.
        readonly_guard.install(self._session)

    def _build_session(self) -> Any:
        session = boto3.Session(profile_name=self.profile, region_name=self.default_region)
        if self.profile is None:
            return session
        try:
            session.get_credentials()
        except botocore.exceptions.InvalidConfigError:
            # The profile resolves in the AWS CLI but not in boto3.
            #
            # This is not an edge case: `aws login` caches a session under
            # ~/.aws/login/, and a profile that role-chains from it has no
            # static credentials for boto3 to find. The CLI can still mint
            # short-lived credentials for that chain, so we ask it to.
            #
            # These are STS session credentials (ASIA…) with an expiry. They
            # are held in this process only and never written to disk.
            creds = _export_credentials(self.profile)
            session = boto3.Session(region_name=self.default_region, **creds)
        return session

    # -- identity ---------------------------------------------------------

    def caller_identity(self) -> dict[str, str]:
        sts = self.client("sts")
        return self.call(sts, "get_caller_identity") or {}

    # -- clients ----------------------------------------------------------

    def client(self, service: str, region: str | None = None) -> Any:
        return self._session.client(
            service, region_name=region or self.default_region, config=_BOTO_CONFIG
        )

    # -- calling ----------------------------------------------------------

    def call(self, client: Any, operation: str, **kwargs: Any) -> Any:
        """Invoke one operation, recording the outcome and never raising.

        Returning ``None`` on failure rather than raising is deliberate. A
        single unavailable API in one region must not abort a sweep of
        seventeen. The *reason* is preserved in the audit trail and surfaces in
        the report as ``not-permitted`` or ``error`` — never silently as an
        absent resource, which is the failure mode that makes an assessment
        actively misleading.
        """
        service = client.meta.service_model.service_name
        region = client.meta.region_name
        started = time.perf_counter()

        method = getattr(client, operation, None)
        if method is None:
            # The installed botocore predates this API. Recorded as unsupported
            # rather than crashing: which AWS APIs exist is a property of the
            # SDK version, and an assessment tool that dies on an older SDK is
            # useless in exactly the estates most likely to be running one.
            self._record(service, operation, region, "unsupported", started, "NotInSDK")
            return None

        try:
            result = method(**kwargs)
        except readonly_guard.ReadOnlyViolation:
            # Never swallowed. A collector reaching for data is a defect in this
            # tool, not a condition to report on.
            self._record(service, operation, region, "refused", started)
            raise
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            self._record(service, operation, region, _outcome_for(code), started, code)
            return None
        except BotoCoreError as exc:
            self._record(service, operation, region, "error", started, type(exc).__name__)
            return None
        self._record(service, operation, region, "ok", started)
        return result

    def paginate(self, client: Any, operation: str, key: str, **kwargs: Any) -> list[Any]:
        """Collect every page of a paginated operation into one list."""
        service = client.meta.service_model.service_name
        region = client.meta.region_name
        started = time.perf_counter()
        items: list[Any] = []
        try:
            paginator = client.get_paginator(operation)
        except (KeyError, OperationNotPageableError):
            # Asking for a paginator on a non-paginated operation is a defect in
            # a collector, not a condition of the account. Record it so it shows
            # up in the report's error list rather than silently losing the
            # call, but do not let it take out the other twenty collectors.
            self._record(service, operation, region, "error", started, "NotPageable")
            return items

        try:
            for page in paginator.paginate(**kwargs):
                items.extend(page.get(key, []))
        except readonly_guard.ReadOnlyViolation:
            self._record(service, operation, region, "refused", started)
            raise
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "Unknown")
            self._record(service, operation, region, _outcome_for(code), started, code)
            return items
        except BotoCoreError as exc:
            self._record(service, operation, region, "error", started, type(exc).__name__)
            return items
        self._record(service, operation, region, "ok", started)
        return items

    def _record(
        self,
        service: str,
        operation: str,
        region: str | None,
        outcome: str,
        started: float,
        error_code: str | None = None,
    ) -> None:
        self.calls.append(
            ApiCall(
                service=service,
                operation=operation,
                region=region,
                outcome=outcome,
                duration_ms=(time.perf_counter() - started) * 1000,
                error_code=error_code,
            )
        )

    # -- regions ----------------------------------------------------------

    def enabled_regions(self) -> list[str]:
        """Regions actually enabled for this account.

        ``account:ListRegions`` is authoritative and reflects opt-in status.
        ``ec2:DescribeRegions`` is the fallback for identities without the
        account permission. If both fail we return only the default region and
        the report says the sweep was single-region — an assessment that
        quietly covers one region while implying seventeen is worse than one
        that admits its scope.
        """
        account = self.client("account")
        listed = self.paginate(
            account,
            "list_regions",
            "Regions",
            RegionOptStatusContains=["ENABLED", "ENABLED_BY_DEFAULT"],
        )
        if listed:
            return sorted(r["RegionName"] for r in listed)

        ec2 = self.client("ec2")
        described = self.call(ec2, "describe_regions", AllRegions=False)
        if described:
            return sorted(r["RegionName"] for r in described.get("Regions", []))

        return [self.default_region]


def _export_credentials(profile: str) -> dict[str, str]:
    """Mint short-lived credentials for a profile via the AWS CLI.

    Uses ``aws configure export-credentials``, which resolves the full profile
    chain — including ``aws login`` sessions and SSO — and returns STS session
    credentials. Invoked in argv form with an absolute path and no shell, so the
    profile name cannot be interpreted as anything but an argument.
    """
    cli = shutil.which("aws")
    if cli is None:
        raise RuntimeError(
            f"Profile {profile!r} needs credentials boto3 cannot resolve, and the AWS CLI "
            f"is not on PATH to mint them. Either install the AWS CLI or run with static "
            f"credentials in the environment."
        )

    # Justification for the suppression below: argv form with an absolute path
    # resolved by shutil.which and no shell, so nothing here is parsed by a
    # shell. Every element but the profile name is a fixed literal, and the
    # profile name reaches subprocess as a single argv entry — it cannot become
    # a second command, a redirect, or a flag to a different program. The
    # alternative, having the operator run
    # `eval $(aws configure export-credentials …)` by hand, moves the same
    # credential through a shell, which is strictly worse.
    completed = subprocess.run(  # noqa: S603  # nosec B603
        [cli, "configure", "export-credentials", "--profile", profile, "--format", "process"],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"Could not obtain credentials for profile {profile!r}: "
            f"{completed.stderr.strip() or 'aws configure export-credentials failed'}"
        )

    payload = json.loads(completed.stdout)
    return {
        "aws_access_key_id": payload["AccessKeyId"],
        "aws_secret_access_key": payload["SecretAccessKey"],
        "aws_session_token": payload.get("SessionToken"),
    }


# Error codes that mean "this thing is not configured", which is an answer, not
# a failure. A Lambda with no function URL, a bucket with no policy, and a
# permission set with no boundary all report this way.
#
# Keeping these out of the error bucket matters: an assessment that reports
# eight errors nobody can act on teaches its reader to skim the error list, and
# the ninth one — the real failure — goes with it.
_ABSENT_CODES = frozenset(
    {
        "ResourceNotFoundException",
        "ResourceNotFound",
        "NoSuchEntity",
        "NoSuchBucketPolicy",
        "NoSuchPublicAccessBlockConfiguration",
        "NoSuchBucketLifecycleConfiguration",
        "ServerSideEncryptionConfigurationNotFoundError",
        "NoSuchTagSet",
        "NoSuchConfiguration",
        "NoSuchWebsiteConfiguration",
        "NoSuchCORSConfiguration",
        "ConfigurationRecorderNotFoundException",
        "DetectorNotFoundException",
        "InvalidAccessException",
        "AWSOrganizationsNotInUseException",
    }
)


def _outcome_for(error_code: str) -> str:
    """Map an AWS error code to an assessment outcome.

    Four outcomes, because they mean different things in a report: *denied* is a
    gap in the assessing identity, *absent* is a control that is simply not
    configured, *unsupported* is a service that does not exist in that region,
    and *error* is a real problem. Collapsing them is how assessments end up
    claiming a control is missing when it was only ever invisible.
    """
    if error_code in _ABSENT_CODES:
        return "absent"
    if error_code in {
        "AccessDenied",
        "AccessDeniedException",
        "UnauthorizedOperation",
        "AuthorizationError",
        "InsufficientPrivilegesException",
    }:
        return "denied"
    if error_code in {
        "InvalidAction",
        "UnsupportedOperation",
        "OptInRequired",
        "EndpointConnectionError",
        "UnrecognizedClientException",
        "InvalidClientTokenId",
        "SubscriptionRequiredException",
    }:
        return "unsupported"
    return "error"
