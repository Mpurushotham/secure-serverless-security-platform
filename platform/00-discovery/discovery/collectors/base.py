"""Collector contract and registry.

A collector answers one question from the 25-point baseline in
``docs/aws_security_engineering_plan.md`` §3. Each is independent: it takes a
session, returns plain JSON-serialisable data, and never raises for an AWS-side
failure — that is the session's job, and the outcome lands in the audit trail.

Collectors record observations. They do **not** decide whether an observation is
a finding; that is ``rules/``. Keeping the two apart means the severity of a
control can be argued about, and re-argued, without re-running a sweep against a
live account.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

from ..session import DiscoverySession

# The five domains from the AWS serverless security workshop. Findings are
# grouped on these rather than by AWS service: a report organised by service
# tells you what is broken, a report organised by domain tells you who fixes it.
DOMAINS = ("identity", "infrastructure", "data", "code", "logging")


@dataclass
class CollectorResult:
    """What one collector observed."""

    name: str
    domain: str
    #: Checklist item numbers from the engineering plan §3 Step 1.
    checklist: tuple[int, ...]
    data: dict[str, Any] = field(default_factory=dict)
    #: Set when the collector could not complete — surfaced in the report as
    #: `not-permitted` or `error`, never as an absent resource.
    status: str = "observed"
    note: str | None = None

    def to_dict(self) -> dict[str, Any]:
        body: dict[str, Any] = {
            "domain": self.domain,
            "checklist": list(self.checklist),
            "status": self.status,
            "data": self.data,
        }
        if self.note:
            body["note"] = self.note
        return body


class Collector(Protocol):
    name: str
    domain: str
    checklist: tuple[int, ...]

    def collect(self, session: DiscoverySession, regions: list[str]) -> CollectorResult: ...


_REGISTRY: dict[str, Callable[[], Collector]] = {}


def register(factory: Callable[[], Collector]) -> Callable[[], Collector]:
    """Class decorator: add a collector to the registry under its own name."""
    instance = factory()
    _REGISTRY[instance.name] = factory
    return factory


def registry() -> dict[str, Callable[[], Collector]]:
    return dict(_REGISTRY)


def build_all() -> list[Collector]:
    return [factory() for factory in _REGISTRY.values()]
