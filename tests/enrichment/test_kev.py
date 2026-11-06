"""CISA KEV enricher: catalog download, in-memory cache, per-CVE lookup, graceful errors."""

from __future__ import annotations

import httpx

from cyllex_argus.enrichment.base import EnrichmentRequest
from cyllex_argus.enrichment.kev import _CATALOG_CACHE, CisaKevEnricher


def _reset_cache():
    _CATALOG_CACHE.clear()


KEV_SAMPLE = {
    "catalogVersion": "2024.06.01",
    "vulnerabilities": [
        {
            "cveID": "CVE-2024-12345",
            "vendorProject": "Acme",
            "product": "Widget",
            "vulnerabilityName": "Acme Widget Buffer Overflow",
            "dateAdded": "2024-05-15",
            "shortDescription": "Buffer overflow in Acme Widget allows RCE.",
            "requiredAction": "Apply updates per vendor instructions.",
            "dueDate": "2024-06-05",
            "knownRansomwareCampaignUse": "Known",
        },
        {
            "cveID": "CVE-2023-99999",
            "vendorProject": "Beta",
            "product": "App",
            "vulnerabilityName": "Beta App RCE",
            "dateAdded": "2023-11-01",
            "shortDescription": "Remote code execution in Beta App.",
            "requiredAction": "Apply updates.",
            "dueDate": "2023-11-22",
            "knownRansomwareCampaignUse": "Unknown",
        },
    ],
}


def _enricher(handler, catalog_url="https://test.local/kev.json"):
    _reset_cache()
    return CisaKevEnricher(
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        catalog_url=catalog_url,
    )


def test_cve_in_catalog_returns_the_full_entry():
    def handler(request):
        return httpx.Response(200, json=KEV_SAMPLE)
    result = _enricher(handler).enrich(EnrichmentRequest("CVE-2024-12345", "vulnerability"))
    assert result.error is None
    pairs = {(f.key, f.value) for f in result.findings}
    assert ("kev-listed", "true") in pairs
    assert ("date-added", "2024-05-15") in pairs
    assert ("due-date", "2024-06-05") in pairs
    assert ("product", "Widget") in pairs
    assert ("known-ransomware-use", "Known") in pairs


def test_cve_absent_from_catalog_is_zero_findings_not_an_error():
    def handler(request):
        return httpx.Response(200, json=KEV_SAMPLE)
    result = _enricher(handler).enrich(EnrichmentRequest("CVE-2099-99999", "vulnerability"))
    assert result.error is None and result.findings == []


def test_catalog_is_cached_across_calls():
    """Two successive queries download the catalog once; the second reads from cache."""
    hits = []
    def handler(request):
        hits.append(request)
        return httpx.Response(200, json=KEV_SAMPLE)
    enricher = _enricher(handler)
    enricher.enrich(EnrichmentRequest("CVE-2024-12345", "vulnerability"))
    enricher.enrich(EnrichmentRequest("CVE-2023-99999", "vulnerability"))
    assert len(hits) == 1


def test_lowercased_cve_is_normalised():
    def handler(request):
        return httpx.Response(200, json=KEV_SAMPLE)
    result = _enricher(handler).enrich(EnrichmentRequest("cve-2024-12345", "vulnerability"))
    assert any(f.key == "kev-listed" for f in result.findings)


def test_non_cve_input_is_refused_without_a_network_call():
    hits = []
    def handler(request):
        hits.append(request)
        return httpx.Response(200, json=KEV_SAMPLE)
    _reset_cache()
    enricher = CisaKevEnricher(
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        catalog_url="https://test.local/kev.json",
    )
    # Pre-populate the cache so the "network call" path cannot hide the refusal.
    enricher.enrich(EnrichmentRequest("CVE-2024-12345", "vulnerability"))
    hits.clear()
    result = enricher.enrich(EnrichmentRequest("not-a-cve", "vulnerability"))
    assert result.error and "CVE" in result.error
    assert hits == []


def test_unsupported_type_is_an_error():
    _reset_cache()
    result = CisaKevEnricher(
        client=httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200))),
        catalog_url="https://test.local/kev.json",
    ).enrich(EnrichmentRequest("example.com", "domain-name"))
    assert result.error and "unsupported" in result.error


def test_malformed_catalog_is_a_clean_error():
    def handler(request):
        return httpx.Response(200, content=b"<html>nope</html>")
    result = _enricher(handler).enrich(EnrichmentRequest("CVE-2024-12345", "vulnerability"))
    assert result.error and "malformed" in result.error


def test_http_error_on_catalog_download_is_a_clean_error():
    def handler(request):
        return httpx.Response(503)
    result = _enricher(handler).enrich(EnrichmentRequest("CVE-2024-12345", "vulnerability"))
    assert result.error and "unreachable" in result.error


def test_outbound_statement_names_cisa_gov_and_claims_no_intent_leak():
    enricher = CisaKevEnricher()
    assert "cisa.gov" in enricher.outbound
    assert "intent" in enricher.outbound.lower()
