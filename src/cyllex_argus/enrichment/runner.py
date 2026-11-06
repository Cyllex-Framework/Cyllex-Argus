"""EnrichmentRunner — the single place where an enrichment call can actually fire.

Two gates sit between a request and the enricher:

1. The runner refuses to call a disabled enricher. The default of every enricher's config entry is
   `enabled = false`, so an operator who installs Argus and never touches `argus.toml` cannot
   accidentally talk to a third party.
2. The enricher's own `supported_types` tuple decides which observables it can receive; anything
   else is refused up front with `EnrichmentUnavailable`.

Every enrichment call is also traceable: when the runner is constructed with a trace recorder and
an investigation id, each call writes a `stage='enrichment'` event with the enricher's name, the
indicator, the number of findings and the duration — the same audit shape the pipeline stages use.
"""

from __future__ import annotations

from collections.abc import Callable

from cyllex_argus.config.settings import EnrichmentConfig
from cyllex_argus.enrichment.base import (
    Enricher,
    EnrichmentDisabledError,
    EnrichmentRequest,
    EnrichmentResult,
    EnrichmentUnavailable,
)
from cyllex_argus.knowledge.trace import PipelineEvent, TraceRecorder


class EnrichmentRunner:
    def __init__(
        self,
        config: EnrichmentConfig,
        enrichers: dict[str, Enricher],
        trace: TraceRecorder | None = None,
        investigation_id: int | None = None,
        log: Callable[[str], None] = lambda _: None,
    ) -> None:
        self._config = config
        self._enrichers = enrichers
        self._trace = trace
        self._investigation_id = investigation_id
        self._log = log

    def enabled_names(self) -> list[str]:
        """Names of enrichers the operator has opted into. For UI/CLI listings."""
        return sorted(name for name, cfg in self._config.enrichers.items() if cfg.enabled)

    def is_enabled(self, name: str) -> bool:
        cfg = self._config.enrichers.get(name)
        return bool(cfg and cfg.enabled)

    def enrichers_for(self, indicator_type: str) -> list[str]:
        """Enabled enrichers that accept this observable type."""
        return [
            name for name, enricher in self._enrichers.items()
            if self.is_enabled(name) and indicator_type in enricher.supported_types
        ]

    def enrich_all(self, request: EnrichmentRequest) -> list[EnrichmentResult]:
        """Dispatch to every enabled enricher that accepts the request's type.

        Each call is traced (when wired) and errors are kept in the result rather than raised,
        so a single enricher's outage does not stop the others. Returns an empty list when no
        enabled enricher accepts the type — the common case for a fresh install.
        """
        return [self.enrich(request, name) for name in self.enrichers_for(request.indicator_type)]

    def enrich(self, request: EnrichmentRequest, enricher_name: str) -> EnrichmentResult:
        if enricher_name not in self._enrichers:
            raise EnrichmentUnavailable(f"unknown enricher {enricher_name!r}")
        enricher = self._enrichers[enricher_name]
        if request.indicator_type not in enricher.supported_types:
            raise EnrichmentUnavailable(
                f"enricher {enricher_name!r} does not accept {request.indicator_type!r} "
                f"(supports: {', '.join(enricher.supported_types)})"
            )
        if not self.is_enabled(enricher_name):
            raise EnrichmentDisabledError(
                f"enricher {enricher_name!r} is disabled in config. Set "
                f"[enrichment.enrichers.\"{enricher_name}\"] enabled = true to opt in. "
                f"Outbound: {enricher.outbound}"
            )
        self._log(f"enrichment {enricher_name}: {request.indicator} ({request.indicator_type})")
        result = enricher.enrich(request)
        self._record(enricher_name, request, result)
        return result

    def _record(self, enricher_name: str, request: EnrichmentRequest, result: EnrichmentResult) -> None:
        if self._trace is None or self._investigation_id is None:
            return
        decision = "failed" if result.error else "enriched"
        reason = (
            f"{enricher_name} <- {request.indicator} ({request.indicator_type}): "
            f"{len(result.findings)} finding(s)" + (f" — {result.error}" if result.error else "")
        )
        self._trace.record(PipelineEvent(
            investigation_id=self._investigation_id,
            stage="enrichment",
            decision=decision,
            reason=reason,
            duration_ms=result.duration_ms,
        ))
