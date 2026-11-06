"""crt.sh enricher: pivot a domain to its Certificate Transparency history.

CT logs are a public, cryptographic ledger of every TLS certificate issued by participating CAs.
Querying crt.sh for a domain leaks nothing beyond what every CA has already published to the
whole Internet when it issued a cert — unlike a lookup against VirusTotal or Shodan, which signals
to the provider (and anyone with privileged access there) that *you* are interested in that domain.
Because of this, crt.sh is a safe default-eligible enricher: enabling it does not reveal intent.
"""

from __future__ import annotations

import json
import time
from collections.abc import Iterable

import httpx

from cyllex_argus.enrichment.base import (
    EnrichedIndicatorType,
    EnrichmentFinding,
    EnrichmentRequest,
    EnrichmentResult,
)

CRT_SH_URL = "https://crt.sh/"
DEFAULT_LIMIT = 50
# The response can be very large for popular domains; cap the download so a surprise 50 MB
# document does not blow up memory or quota.
MAX_RESPONSE_BYTES = 5_000_000


class CrtShEnricher:
    name: str = "crt.sh"
    description: str = "Certificate Transparency log lookup via crt.sh"
    outbound: str = (
        "The exact domain is sent as an HTTP GET to crt.sh. Public CT logs record every cert; "
        "no intent is leaked by this query."
    )
    supported_types: tuple[EnrichedIndicatorType, ...] = ("domain-name",)

    def __init__(self, client: httpx.Client | None = None, limit: int = DEFAULT_LIMIT) -> None:
        self._client = client if client is not None else httpx.Client(timeout=15.0)
        self._limit = limit

    def enrich(self, request: EnrichmentRequest) -> EnrichmentResult:
        start = time.monotonic()
        if request.indicator_type not in self.supported_types:
            return _done(request, start, error=f"unsupported indicator type {request.indicator_type!r}")
        domain = request.indicator.strip().lower()
        if not domain or " " in domain:
            return _done(request, start, error=f"not a domain: {request.indicator!r}")
        try:
            response = self._client.get(
                CRT_SH_URL,
                params={"q": f"%.{domain}", "output": "json"},
            )
            response.raise_for_status()
            body = response.content[:MAX_RESPONSE_BYTES]
        except httpx.HTTPError as exc:
            return _done(request, start, error=f"crt.sh unreachable: {exc}")
        try:
            rows = json.loads(body) if body else []
        except json.JSONDecodeError as exc:
            return _done(request, start, error=f"crt.sh answer was not JSON: {exc}")
        if not isinstance(rows, list):
            return _done(request, start, error="crt.sh answer had an unexpected shape")
        findings = list(_findings(rows, self._limit, self.name))
        return _done(request, start, findings=findings)


def _findings(rows: Iterable[dict], limit: int, source: str) -> Iterable[EnrichmentFinding]:
    seen: set[str] = set()
    count = 0
    for row in rows:
        if not isinstance(row, dict):
            continue
        for name in str(row.get("name_value", "")).splitlines():
            name = name.strip().lower()
            if not name or name in seen:
                continue
            seen.add(name)
            yield EnrichmentFinding(
                source=source,
                key="common-name",
                value=name,
                observed_at=str(row.get("not_before") or "") or None,
                detail=str(row.get("issuer_name") or "") or None,
            )
            count += 1
            if count >= limit:
                return


def _done(
    request: EnrichmentRequest, start: float, *,
    findings: list[EnrichmentFinding] | None = None, error: str | None = None,
) -> EnrichmentResult:
    return EnrichmentResult(
        request=request,
        findings=findings or [],
        duration_ms=int((time.monotonic() - start) * 1000),
        error=error,
    )
