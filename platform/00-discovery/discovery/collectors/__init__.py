"""Collector registry.

Importing this package registers every collector. The import order below is the
order the report presents them in, which is roughly the order a reviewer would
want to read: what the organisation looks like, who can act in it, what is
reachable from outside, then what watches it.
"""

from . import (  # noqa: F401 — imported for registration side effects
    data,
    detection,
    iam,
    identity,
    network,
    organizations,
    repo,
    serverless,
)
from .base import (  # noqa: F401
    DOMAINS,
    Collector,
    CollectorResult,
    build_all,
    register,
    registry,
)

__all__ = [
    "DOMAINS",
    "Collector",
    "CollectorResult",
    "build_all",
    "register",
    "registry",
]
