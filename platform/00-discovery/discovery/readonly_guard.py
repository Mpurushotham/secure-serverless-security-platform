"""A fail-closed guard that refuses any AWS call which is not read-only.

Where this sits in the defence
------------------------------
This is layer 2, and it is application code, so it can have bugs. Layer 3 — the
one that actually holds — is the IAM policy in ``iam/discovery-readonly.json``,
enforced by AWS itself and unaffected by anything wrong in this file. The same
ordering as the rest of this repository: the SQL guardrail is layer 2, the
``mcp_readonly`` database role is layer 3.

So why have layer 2 at all? Because the assessment is meant to run under an
over-privileged identity at least once. The first live run uses an existing
admin role, since creating the purpose-built read-only role is itself a change
to the account being assessed. Under an admin credential IAM will happily allow
``s3:GetObject``. This guard is what stops a collector bug from reading customer
data during an assessment that was only ever supposed to look at configuration.

The two-layer test
------------------
An operation must pass **both** checks:

1. **Structural.** The operation name must begin with a read-only verb.
   ``PutBucketPolicy`` and ``DeleteUser`` fail here, and so does anything new
   that AWS adds with a mutating verb — the check does not need updating to
   refuse an API nobody has thought about yet.

2. **Data-plane.** The operation must not appear in ``DATA_PLANE_READS``.
   This exists because the first check is not sufficient: ``GetObject``,
   ``GetSecretValue``, ``GetParameter`` and ``Decrypt`` are all "read-only" in
   the sense that they change nothing, and all four return exactly the data an
   inventory tool has no business seeing.

The distinction that matters is *configuration versus content*. This tool reads
how a bucket is configured. It never reads what is in it.

Failure is an exception, not a warning. A guard that logs and proceeds is not a
guard.
"""

from __future__ import annotations

from typing import Any

# Verbs that cannot change state. Anything not starting with one of these is
# refused, which makes the default answer "no" for every API that does not yet
# exist.
_READ_ONLY_PREFIXES: tuple[str, ...] = (
    "Describe",
    "List",
    "Get",
    "BatchGet",
    "Lookup",
    "Search",
    "Select",  # narrowed below — SelectObjectContent is denied by name
    "Simulate",  # iam:SimulatePrincipalPolicy — evaluates, does not mutate
    "Generate",  # iam:GenerateCredentialReport / GenerateServiceLastAccessedDetails
    "Check",
    "Estimate",
    "Preview",
    "Query",  # narrowed below — dynamodb:Query is denied by name
    "Scan",  # narrowed below — dynamodb:Scan is denied by name
    "Validate",
    "Test",
    "Head",
)

# Operations that pass the structural test and must still be refused, because
# they return data rather than configuration.
#
# Keyed by botocore service id. The value is the set of operation names.
DATA_PLANE_READS: dict[str, frozenset[str]] = {
    "s3": frozenset(
        {
            "GetObject",
            "GetObjectTorrent",
            "GetObjectAttributes",
            "SelectObjectContent",
            "ListObjects",  # object *keys* are frequently personal data
            "ListObjectsV2",
            "ListObjectVersions",
        }
    ),
    "secretsmanager": frozenset({"GetSecretValue", "BatchGetSecretValue"}),
    "ssm": frozenset({"GetParameter", "GetParameters", "GetParametersByPath"}),
    "kms": frozenset({"Decrypt", "GenerateDataKey", "GenerateDataKeyPair", "GenerateRandom"}),
    "dynamodb": frozenset({"GetItem", "BatchGetItem", "Query", "Scan"}),
    "rds-data": frozenset({"ExecuteStatement", "BatchExecuteStatement"}),
    "sqs": frozenset({"ReceiveMessage"}),
    "logs": frozenset({"GetLogEvents", "FilterLogEvents", "GetQueryResults"}),
    "lambda": frozenset(
        {
            # Returns a presigned URL to download the deployment package — the
            # application's source code. GetFunctionConfiguration carries
            # everything an inventory actually needs.
            "GetFunction",
        }
    ),
    "cloudtrail": frozenset(
        {
            # Event history includes request parameters, which routinely carry
            # resource names and occasionally personal data. Coverage of the
            # trail is assessed from its configuration, not its contents.
            "LookupEvents",
        }
    ),
    "codecommit": frozenset({"GetFile", "GetBlob", "GetFolder"}),
    "sts": frozenset(),  # GetCallerIdentity is fine and is used deliberately
}


class ReadOnlyViolation(RuntimeError):
    """Raised when a collector attempts a call this tool must never make.

    Deliberately not a subclass of ``botocore.exceptions.ClientError``: a
    collector's ``except ClientError`` block must not be able to swallow this.
    """

    def __init__(self, service: str, operation: str, reason: str) -> None:
        self.service = service
        self.operation = operation
        self.reason = reason
        super().__init__(
            f"Refused {service}:{operation} — {reason}. "
            f"Discovery reads configuration, never content. "
            f"If this call is genuinely needed, it belongs in the allowlist with a "
            f"written justification, and in iam/discovery-readonly.json."
        )


def classify(service: str, operation: str) -> str | None:
    """Return the refusal reason, or ``None`` if the call is permitted.

    Kept separate from the botocore hook so it is directly testable without
    constructing a session.
    """
    denied = DATA_PLANE_READS.get(service, frozenset())
    if operation in denied:
        return "reads data rather than configuration"

    if not operation.startswith(_READ_ONLY_PREFIXES):
        return "is not a read-only operation"

    return None


def _handler(**kwargs: Any) -> None:
    """botocore ``before-call`` hook.

    botocore passes ``model``, ``params``, ``request_signer``, ``context`` and
    ``event_name``. The service is taken from the model rather than parsed out
    of the event name, so the guard does not depend on event-name formatting.
    """
    model = kwargs.get("model")
    if model is None:  # pragma: no cover — botocore always supplies it
        return

    service = model.service_model.service_name
    reason = classify(service, model.name)
    if reason is not None:
        raise ReadOnlyViolation(service, model.name, reason)


def install(session: Any) -> None:
    """Attach the guard to a boto3 Session.

    ``before-call`` fires after request signing is set up but before anything
    goes on the wire, so a refused call never reaches AWS — it does not appear
    in CloudTrail as an AccessDenied that somebody then has to triage, and it
    cannot partially succeed.
    """
    session.events.register("before-call.*.*", _handler, unique_id="ssp-readonly-guard")
