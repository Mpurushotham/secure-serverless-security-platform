"""Redaction applied to every snapshot before it can be committed.

The raw snapshot is an accurate description of how to attack the estate it
describes: account IDs, role ARNs, bucket names, VPC and subnet IDs, the
management account's email address. That is fine on the assessor's disk and not
fine in a public repository.

What is redacted and what is not
--------------------------------
Identifiers are replaced with **stable salted hashes**, so ``acct_4f2a91`` is
the same account everywhere in the document and a reader can still follow a
finding from the account table to the role that caused it. Structure, counts,
configuration and severity all survive untouched — the report has to stay
readable and checkable.

The salt is derived from the assessed account ID rather than being random, so
re-running discovery produces the same pseudonyms and the diff between two
snapshots shows real change rather than noise. That also means the mapping is
reproducible by anyone who knows the account ID, which is the point: this is
pseudonymisation to keep identifiers out of a public index, not encryption. It
is not a control against someone who already knows the account.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

# 12-digit AWS account IDs, anywhere in a string.
_ACCOUNT = re.compile(r"\b(\d{12})\b")
# Organization, OU, root, and policy identifiers.
_ORG_IDS = re.compile(
    r"\b(o-[a-z0-9]{10,32}"
    r"|ou-[a-z0-9]{4,32}-[a-z0-9]{8,32}"
    r"|r-[a-z0-9]{4,32}"
    r"|p-[a-z0-9]{8,32})\b"
)
# Email addresses.
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
# Resource identifiers whose names frequently encode a company or product.
_RESOURCE_IDS = re.compile(r"\b(vpc|subnet|sg|igw|nat|eni|i|vol|snap|ami)-[0-9a-f]{8,17}\b")
# AWS access key identifiers, in case one ever appears in a description field.
_ACCESS_KEY = re.compile(r"\b((?:AKIA|ASIA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{12,})\b")


# Where customer-chosen *names* live, as (collector, path, prefix). Paths are
# explicit rather than matched on a key like "name", because a broad match
# would also pseudonymise the values that carry the meaning: AWS-managed policy
# names, permission-set names, service principals, regions and statuses. A
# report whose central finding reads "attached policy pol_3f21ab" says nothing.
#
# Only names the account owner chose are collected. Everything AWS names stays
# readable.
_NAME_PATHS: tuple[tuple[str, tuple[str, ...], str], ...] = (
    ("organizations", ("accounts", "name"), "account"),
    ("iam", ("users", "name"), "user"),
    ("iam", ("roles", "name"), "role"),
    ("s3", ("buckets", "name"), "bucket"),
    ("lambda", ("functions", "name"), "fn"),
    ("secrets", ("secrets", "name"), "secret"),
    ("secrets", ("parameters", "name"), "param"),
    ("security_groups", ("internet_open_rules", "group_name"), "sg"),
    ("cloudtrail", ("trails", "name"), "trail"),
    ("api_gateway", ("stages", "name"), "api"),
    ("vpc", ("vpcs", "vpc_id"), "vpc"),
    ("third_party", ("external_trusts", "role"), "role"),
)

# Names nested one level deeper than a flat list of dicts: IAM group membership,
# inline policy names, and the organization's own policy names. Collected as
# (collector, path-to-list, list-valued field, prefix).
_NESTED_NAME_PATHS: tuple[tuple[str, str, str, str], ...] = (
    ("iam", "users", "groups", "group"),
    ("iam", "users", "inline_policies", "policy"),
    ("iam", "users", "attached_policies", "policy"),
    ("iam", "users", "group_policies", "policy"),
    ("iam", "roles", "inline_policies", "policy"),
    ("iam", "roles", "attached_policies", "policy"),
)

# Names AWS chose, which must survive redaction or the findings stop meaning
# anything. Matched case-sensitively and in full.
_AWS_OWNED = frozenset(
    {
        "AdministratorAccess",
        "PowerUserAccess",
        "ReadOnlyAccess",
        "IAMFullAccess",
        "AWSOrganizationsFullAccess",
        "FullAWSAccess",
        "RCPFullAWSAccess",
        "Root",
        "default",
    }
)

# Short strings are not redacted: a two-character name produces a replacement
# that corrupts unrelated text, and a name that short carries no identifying
# information anyway.
_MIN_NAME_LENGTH = 4

# Names that are ordinary words. These are excluded because they appear inside
# unrelated strings, and replacing them there changes meaning.
#
# This is not a theoretical concern. An earlier version replaced names by plain
# substring match, and OUs called `audit` and `security` were rewritten inside
# `auditmanager.amazonaws.com` and `securityhub.amazonaws.com` — which silently
# removed four findings from the report, including "security services have no
# delegated administrator". Redaction that changes findings is worse than no
# redaction, because the report still looks complete.
#
# Word-boundary matching (below) fixes the general case; this list covers the
# remainder, where the name is a whole word inside a longer identifier.
_COMMON_WORDS = frozenset(
    {
        "audit", "security", "network", "operations", "testing", "development",
        "production", "staging", "sandbox", "shared", "core", "prod", "test",
        "dev", "logs", "data", "admin", "main", "root", "default", "backup",
        "archive", "management", "workloads", "infrastructure", "platform",
        "api", "web", "app", "service", "services", "public", "private",
    }
)


class Redactor:
    """Replaces identifiers, and account-chosen names, with stable pseudonyms."""

    def __init__(self, account_id: str, salt: str | None = None) -> None:
        self._salt = salt or f"ssp-discovery-{account_id}"
        self._names: dict[str, str] = {}
        self._name_pattern: re.Pattern[str] | None = None

    def token(self, prefix: str, value: str) -> str:
        digest = hashlib.sha256(f"{self._salt}:{value}".encode()).hexdigest()[:6]
        return f"{prefix}_{digest}"

    def text(self, value: str) -> str:
        # Names first. A bucket called `example-logs-210987654321` embeds the
        # account ID; substituting that first would leave a name no longer
        # matching anything collected, and the rest of it would survive.
        if self._name_pattern is not None:
            value = self._name_pattern.sub(lambda m: self._names[m.group(0)], value)

        value = _ACCESS_KEY.sub(lambda m: self.token("key", m.group(1)), value)
        value = _ACCOUNT.sub(lambda m: self.token("acct", m.group(1)), value)
        value = _ORG_IDS.sub(lambda m: self.token(_org_prefix(m.group(1)), m.group(1)), value)
        value = _EMAIL.sub(lambda m: self.token("email", m.group(0)) + "@redacted.invalid", value)
        value = _RESOURCE_IDS.sub(
            lambda m: self.token(m.group(1), m.group(0)), value
        )
        return value

    def _compile_names(self) -> None:
        """Build one alternation, longest first, anchored on word boundaries.

        Longest-first ordering makes `example-lab-api` win over `example-lab`,
        which would otherwise leave a mangled `bucket_3f21ab-api`. The
        boundaries are what stop a name being rewritten inside a longer
        identifier that merely contains it.
        """
        if not self._names:
            self._name_pattern = None
            return
        alternation = "|".join(
            re.escape(name) for name in sorted(self._names, key=len, reverse=True)
        )
        self._name_pattern = re.compile(rf"(?<![\w-])(?:{alternation})(?![\w-])")

    def apply(self, node: Any) -> Any:
        """Redact a whole snapshot.

        Two passes. The first walks the known name paths to build the mapping;
        the second rewrites every string in the document. It has to be two,
        because a bucket name collected from ``buckets[].name`` also appears in
        ``buckets_unencrypted``, in ARNs, and in prose the report renders — and
        a single pass would only catch the first of those.
        """
        self._collect_names(node)
        self._compile_names()
        return self._rewrite(node)

    def _collect_names(self, snapshot: Any) -> None:
        if not isinstance(snapshot, dict):
            return
        collectors = snapshot.get("collectors")
        if not isinstance(collectors, dict):
            return

        for collector, (container, field), prefix in _NAME_PATHS:
            data = (collectors.get(collector) or {}).get("data")
            if not isinstance(data, dict):
                continue
            for item in data.get(container) or []:
                if not isinstance(item, dict):
                    continue
                name = item.get(field)
                if not isinstance(name, str):
                    continue
                if not _redactable(name):
                    continue
                self._names.setdefault(name, self.token(prefix, name))

        for collector, container, field, prefix in _NESTED_NAME_PATHS:
            data = (collectors.get(collector) or {}).get("data")
            if not isinstance(data, dict):
                continue
            for item in data.get(container) or []:
                if not isinstance(item, dict):
                    continue
                for name in item.get(field) or []:
                    if isinstance(name, str) and _redactable(name):
                        self._names.setdefault(name, self.token(prefix, name))

        org = (collectors.get("organizations") or {}).get("data") or {}

        # OU names live in a recursive tree rather than a flat list.
        for root in org.get("roots") or []:
            self._collect_ou_names(root.get("organizational_units") or [])

        # Organization policy names, but only the ones this account wrote.
        # AWS-managed policies (FullAWSAccess, RCPFullAWSAccess) must stay
        # readable — they are the difference between "no guardrail is attached"
        # and "a guardrail whose name we hid is attached".
        for policies in (org.get("policies") or {}).values():
            for policy in policies or []:
                if not isinstance(policy, dict) or policy.get("aws_managed"):
                    continue
                name = policy.get("name")
                if isinstance(name, str) and _redactable(name):
                    self._names.setdefault(name, self.token("scp", name))

    def _collect_ou_names(self, ous: list[Any]) -> None:
        for ou in ous:
            if not isinstance(ou, dict):
                continue
            name = ou.get("name")
            if isinstance(name, str) and _redactable(name):
                self._names.setdefault(name, self.token("ou", name))
            self._collect_ou_names(ou.get("children") or [])

    def _rewrite(self, node: Any) -> Any:
        if isinstance(node, str):
            return self.text(node)
        if isinstance(node, dict):
            return {self._rewrite(k): self._rewrite(v) for k, v in node.items()}
        if isinstance(node, list):
            return [self._rewrite(v) for v in node]
        return node


def _redactable(name: str) -> bool:
    """Whether a name is specific enough to be worth pseudonymising.

    Excluding ordinary words costs a little privacy — an OU genuinely called
    `security` stays visible — and buys correctness, which matters more: those
    names carry no information about who owns the estate, and rewriting them
    corrupts the identifiers that do carry meaning.
    """
    return (
        len(name) >= _MIN_NAME_LENGTH
        and name not in _AWS_OWNED
        and name.lower() not in _COMMON_WORDS
    )


def _org_prefix(value: str) -> str:
    return {"o": "org", "ou": "ou", "r": "root", "p": "pol"}.get(
        value.split("-", 1)[0], "id"
    )
