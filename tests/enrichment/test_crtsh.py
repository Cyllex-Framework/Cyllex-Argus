"""crt.sh enricher: parses CT log entries, caps the output, degrades gracefully on bad input."""

from __future__ import annotations

import httpx

from cyllex_argus.enrichment.base import EnrichmentRequest
from cyllex_argus.enrichment.crtsh import CrtShEnricher


def _client(handler, limit=50) -> CrtShEnricher:
    return CrtShEnricher(client=httpx.Client(transport=httpx.MockTransport(handler)), limit=limit)


def test_parses_name_value_entries_and_dedupes_subdomains():
    def handler(request):
        return httpx.Response(200, json=[
            {"name_value": "a.example.com\nmail.example.com", "not_before": "2024-01-01", "issuer_name": "Let's Encrypt"},
            {"name_value": "a.example.com", "not_before": "2024-05-01", "issuer_name": "DigiCert"},
            {"name_value": "api.example.com", "not_before": "2024-02-15", "issuer_name": "Google Trust Services"},
        ])
    result = _client(handler).enrich(EnrichmentRequest("example.com", "domain-name"))
    assert result.error is None
    values = [f.value for f in result.findings]
    assert values == ["a.example.com", "mail.example.com", "api.example.com"]
    assert all(f.key == "common-name" for f in result.findings)


def test_limit_caps_the_number_of_findings():
    def handler(request):
        return httpx.Response(200, json=[
            {"name_value": f"host{i}.example.com"} for i in range(100)
        ])
    result = _client(handler, limit=5).enrich(EnrichmentRequest("example.com", "domain-name"))
    assert len(result.findings) == 5


def test_http_error_returns_error_result_without_raising():
    def handler(request):
        return httpx.Response(503)
    result = _client(handler).enrich(EnrichmentRequest("example.com", "domain-name"))
    assert result.findings == []
    assert result.error and "503" in result.error


def test_non_json_body_is_an_error_not_a_crash():
    def handler(request):
        return httpx.Response(200, content=b"<html>not json</html>")
    result = _client(handler).enrich(EnrichmentRequest("example.com", "domain-name"))
    assert result.error and "not JSON" in result.error


def test_empty_response_is_zero_findings_not_an_error():
    def handler(request):
        return httpx.Response(200, content=b"")
    result = _client(handler).enrich(EnrichmentRequest("example.com", "domain-name"))
    assert result.error is None
    assert result.findings == []


def test_unsupported_type_is_an_error():
    result = _client(lambda _: httpx.Response(200)).enrich(
        EnrichmentRequest("1.1.1.1", "ipv4-addr"),
    )
    assert result.error and "unsupported" in result.error


def test_malformed_rows_are_skipped_but_do_not_crash():
    def handler(request):
        return httpx.Response(200, json=[
            {"name_value": "good.example.com"},
            "not-a-dict",   # ignored
            {"missing_name_value": True},  # yields empty name, skipped
            {"name_value": "   "},  # whitespace only, skipped
        ])
    result = _client(handler).enrich(EnrichmentRequest("example.com", "domain-name"))
    assert [f.value for f in result.findings] == ["good.example.com"]


def test_outbound_description_names_crtsh_and_claims_no_intent_leak():
    """A UI showing this to the operator before enabling should mention crt.sh explicitly."""
    enricher = CrtShEnricher()
    assert "crt.sh" in enricher.outbound
    assert "intent" in enricher.outbound.lower()
