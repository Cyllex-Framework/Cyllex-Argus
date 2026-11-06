"""External-data enrichment with explicit opt-in.

The pipeline's default stance is receive-only (see the README's 'Nothing leaves the machine except…'
section). Enrichment is the escape hatch for operators who deliberately accept that a specific
indicator will be sent to a specific third party in exchange for extra context. Every enricher is
disabled by default; the configuration key per enricher is explicit; the runner refuses to call a
disabled enricher; and each call is traceable.
"""

from cyllex_argus.enrichment.base import (
    EnrichedIndicatorType,
    Enricher,
    EnrichmentDisabledError,
    EnrichmentFinding,
    EnrichmentRequest,
    EnrichmentResult,
    EnrichmentUnavailable,
)
from cyllex_argus.enrichment.detect import detect_observable_type
from cyllex_argus.enrichment.registry import available_enrichers
from cyllex_argus.enrichment.runner import EnrichmentRunner

__all__ = [
    "EnrichedIndicatorType",
    "Enricher",
    "EnrichmentDisabledError",
    "EnrichmentFinding",
    "EnrichmentRequest",
    "EnrichmentResult",
    "EnrichmentRunner",
    "EnrichmentUnavailable",
    "available_enrichers",
    "detect_observable_type",
]
