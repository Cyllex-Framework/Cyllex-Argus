"""URLhaus enricher: parses URL and payload lookups; handles no_results and network errors."""

from __future__ import annotations

import httpx

from cyllex_argus.enrichment.base import EnrichmentRequest
from cyllex_argus.enrichment.urlhaus import UrlhausEnricher


def _enricher(handler) -> UrlhausEnricher:
    return UrlhausEnricher(client=httpx.Client(transport=httpx.MockTransport(handler)))


URL_SAMPLE = {
    "query_status": "ok",
    "url_status": "online",
    "threat": "malware_download",
    "date_added": "2024-05-01 12:00:00 UTC",
    "reporter": "abuse_ch",
    "tags": ["agenttesla", "exe"],
    "payloads": [
        {"signature": "AgentTesla", "filename": "invoice.exe"},
        {"signature": "AgentTesla", "filename": "update.scr"},
    ],
}


def test_url_lookup_parses_the_relevant_fields():
    def handler(request):
        assert request.method == "POST"
        assert "urlhaus-api" in str(request.url)
        return httpx.Response(200, json=URL_SAMPLE)
    result = _enricher(handler).enrich(EnrichmentRequest("http://evil.example/bin", "url"))
    assert result.error is None
    pairs = [(f.key, f.value) for f in result.findings]
    assert ("url-status", "online") in pairs
    assert ("threat", "malware_download") in pairs
    assert ("date-added", "2024-05-01 12:00:00 UTC") in pairs
    assert ("tag", "agenttesla") in pairs
    assert ("malware-family", "AgentTesla") in pairs


def test_no_results_is_zero_findings_not_an_error():
    def handler(request):
        return httpx.Response(200, json={"query_status": "no_results"})
    result = _enricher(handler).enrich(EnrichmentRequest("http://clean.example/", "url"))
    assert result.error is None and result.findings == []


def test_non_ok_query_status_is_an_error():
    def handler(request):
        return httpx.Response(200, json={"query_status": "invalid_url"})
    result = _enricher(handler).enrich(EnrichmentRequest("not-a-url", "url"))
    assert result.error and "invalid_url" in result.error


PAYLOAD_SAMPLE = {
    "query_status": "ok",
    "signature": "Emotet",
    "file_type": "exe",
    "file_size": 350000,
    "firstseen": "2024-01-01",
    "lastseen": "2024-04-15",
    "tags": ["banking-trojan"],
}


def test_payload_lookup_dispatches_by_hash_length():
    seen_endpoints = []
    def handler(request):
        seen_endpoints.append(str(request.url))
        return httpx.Response(200, json=PAYLOAD_SAMPLE)
    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    result = _enricher(handler).enrich(EnrichmentRequest(sha256, "file-hash"))
    assert result.error is None
    assert any("payload/" in url for url in seen_endpoints)
    pairs = [(f.key, f.value) for f in result.findings]
    assert ("malware-family", "Emotet") in pairs
    assert ("file-type", "exe") in pairs
    assert ("file-size", "350000") in pairs


def test_bad_hash_is_refused_without_a_network_call():
    calls = []
    def handler(request):
        calls.append(request)
        return httpx.Response(200)
    result = _enricher(handler).enrich(EnrichmentRequest("not-a-hash", "file-hash"))
    assert result.error and "MD5" in result.error
    assert calls == []


def test_unsupported_type_is_an_error():
    result = _enricher(lambda _: httpx.Response(200)).enrich(
        EnrichmentRequest("example.com", "domain-name"),
    )
    assert result.error and "unsupported" in result.error


def test_http_error_is_a_clean_error_result():
    def handler(request):
        return httpx.Response(502)
    result = _enricher(handler).enrich(EnrichmentRequest("http://x.example/", "url"))
    assert result.error and "502" in result.error


def test_outbound_statement_mentions_urlhaus_and_defensive_sharing():
    enricher = UrlhausEnricher()
    assert "urlhaus-api.abuse.ch" in enricher.outbound
    assert "defensive" in enricher.outbound.lower()
