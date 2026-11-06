"""CISA KEV enricher: flag a CVE as a Known Exploited Vulnerability.

The CISA Known Exploited Vulnerabilities catalog is the single most important vulnerability
prioritization signal published publicly. If a CVE is in KEV, it is being actively exploited in
the wild — meaning emergency patching, not quarterly. For federal agencies the KEV catalog is
also the basis of BOD 22-01's binding patch deadlines ("due date").

Unlike the per-indicator enrichers that call a remote API every time, KEV is a static catalog of
~1300 entries. This enricher downloads the catalog once per process (cached by URL + mtime in a
module-level dict), parses it into a map keyed by CVE id, and answers lookups from memory. The
only outbound traffic is the single catalog download and only when the cache has aged past
`CACHE_TTL_SECONDS` or has not been populated yet.
"""

from __future__ import annotations

import json
import re
import time

import httpx

from cyllex_argus.enrichment.base import (
    EnrichedIndicatorType,
    EnrichmentFinding,
    EnrichmentRequest,
    EnrichmentResult,
)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
MAX_RESPONSE_BYTES = 10_000_000
CACHE_TTL_SECONDS = 24 * 3600  # KEV updates no more than once a day.
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

# Module-level cache so a batched run (dozens of CVE claims from one investigation) downloads once.
_CATALOG_CACHE: dict[str, tuple[float, dict[str, dict]]] = {}


class CisaKevEnricher:
    name: str = "cisa-kev"
    description: str = "CISA Known Exploited Vulnerabilities (KEV) catalog lookup"
    outbound: str = (
        "A single HTTP GET to cisa.gov downloads the KEV catalog (~1 MB). The catalog is a "
        "public register of CVEs under active exploitation; the download leaks no intent."
    )
    supported_types: tuple[EnrichedIndicatorType, ...] = ("vulnerability",)

    def __init__(
        self, client: httpx.Client | None = None,
        catalog_url: str = KEV_URL,
        cache_ttl_seconds: float = CACHE_TTL_SECONDS,
        now: callable | None = None,
    ) -> None:
        self._client = client if client is not None else httpx.Client(timeout=30.0)
        self._catalog_url = catalog_url
        self._ttl = cache_ttl_seconds
        self._now = now or time.monotonic

    def enrich(self, request: EnrichmentRequest) -> EnrichmentResult:
        start = time.monotonic()
        if request.indicator_type not in self.supported_types:
            return _done(request, start, error=f"unsupported indicator type {request.indicator_type!r}")
        cve = request.indicator.strip().upper()
        if not _CVE_RE.match(cve):
            return _done(request, start, error=f"not a CVE id: {request.indicator!r}")
        try:
            catalog = self._catalog()
        except httpx.HTTPError as exc:
            return _done(request, start, error=f"KEV catalog unreachable: {exc}")
        except (json.JSONDecodeError, ValueError) as exc:
            return _done(request, start, error=f"KEV catalog malformed: {exc}")
        entry = catalog.get(cve)
        if entry is None:
            return _done(request, start, findings=[])
        return _done(request, start, findings=list(_findings(entry, self.name)))

    def _catalog(self) -> dict[str, dict]:
        cached = _CATALOG_CACHE.get(self._catalog_url)
        if cached is not None and self._now() - cached[0] < self._ttl:
            return cached[1]
        response = self._client.get(self._catalog_url)
        response.raise_for_status()
        body = response.content[:MAX_RESPONSE_BYTES]
        data = json.loads(body) if body else {}
        if not isinstance(data, dict):
            raise ValueError("KEV catalog is not a JSON object")
        vulnerabilities = data.get("vulnerabilities") or []
        if not isinstance(vulnerabilities, list):
            raise ValueError("KEV catalog has no 'vulnerabilities' list")
        catalog: dict[str, dict] = {}
        for item in vulnerabilities:
            if not isinstance(item, dict):
                continue
            cve_id = str(item.get("cveID", "")).strip().upper()
            if cve_id:
                catalog[cve_id] = item
        _CATALOG_CACHE[self._catalog_url] = (self._now(), catalog)
        return catalog


def _findings(entry: dict, source: str):
    yield EnrichmentFinding(
        source=source, key="kev-listed", value="true",
        detail=str(entry.get("shortDescription") or entry.get("vulnerabilityName") or "")[:400] or None,
    )
    added = entry.get("dateAdded")
    if isinstance(added, str) and added:
        yield EnrichmentFinding(source=source, key="date-added", value=added, observed_at=added)
    due = entry.get("dueDate")
    if isinstance(due, str) and due:
        yield EnrichmentFinding(
            source=source, key="due-date", value=due,
            detail="CISA BOD 22-01 remediation deadline for US federal agencies",
        )
    product = entry.get("product")
    vendor = entry.get("vendorProject")
    if isinstance(product, str) and product:
        yield EnrichmentFinding(
            source=source, key="product", value=product,
            detail=str(vendor) if isinstance(vendor, str) and vendor else None,
        )
    required_action = entry.get("requiredAction")
    if isinstance(required_action, str) and required_action:
        yield EnrichmentFinding(
            source=source, key="required-action", value=required_action[:400],
        )
    ransomware = entry.get("knownRansomwareCampaignUse")
    if isinstance(ransomware, str) and ransomware:
        yield EnrichmentFinding(source=source, key="known-ransomware-use", value=ransomware)


def _done(request, start, *, findings=None, error=None):
    return EnrichmentResult(
        request=request, findings=findings or [], error=error,
        duration_ms=int((time.monotonic() - start) * 1000),
    )
