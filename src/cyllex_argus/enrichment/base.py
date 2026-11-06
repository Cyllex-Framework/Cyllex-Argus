"""Enricher protocol and the narrow data types that cross its boundary.

The request type is deliberately minimal: just the indicator value and its STIX observable type.
Nothing an enricher receives tells it which investigation the indicator came from, what actor the
analyst is researching, or which other indicators are in the same case. The whole point of the
default-off opt-in model is to prevent *intent* from leaking; keeping the request narrow is how we
enforce that structurally rather than by convention.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Literal, Protocol, runtime_checkable

# STIX 2.1 observable types this framework understands. New types are added here as enrichers
# that know how to handle them are introduced; the runner refuses unknown types up front.
EnrichedIndicatorType = Literal[
    "domain-name", "ipv4-addr", "ipv6-addr", "url", "file-hash", "vulnerability",
]


class EnrichmentDisabledError(Exception):
    """Raised when `enrich(...)` is called on an enricher the operator has not opted into."""


class EnrichmentUnavailable(Exception):
    """Raised when the enricher does not exist, or does not accept this indicator type."""


@dataclass(frozen=True)
class EnrichmentRequest:
    indicator: str
    indicator_type: EnrichedIndicatorType


@dataclass(frozen=True)
class EnrichmentFinding:
    """One datum returned by an enricher. The schema is deliberately open: each enricher decides
    which `key` names it emits so the trace shows exactly what came back without re-interpreting."""
    source: str                       # the enricher's `name`
    key: str                          # e.g. "common-name", "asn", "resolution"
    value: str
    observed_at: str | None = None    # ISO-8601 date or datetime, if the enricher reports one
    detail: str | None = None         # free-form extra context the enricher wants shown


@dataclass(frozen=True)
class EnrichmentResult:
    request: EnrichmentRequest
    findings: list[EnrichmentFinding] = field(default_factory=list)
    duration_ms: int = 0
    error: str | None = None          # None on success; a short reason string on failure


@runtime_checkable
class Enricher(Protocol):
    """Public contract of an enricher. The `outbound` docstring field is what a Settings page or
    confirmation prompt shows the operator so the OPSEC trade-off is explicit."""

    name: str
    description: str
    # One sentence: WHAT leaves the machine and WHERE. Shown in Settings and warning banners.
    outbound: str
    supported_types: tuple[EnrichedIndicatorType, ...]

    def enrich(self, request: EnrichmentRequest) -> EnrichmentResult: ...


# Convenience alias for callers that pass their own time source (keeps tests hermetic).
Clock = Callable[[], float]
