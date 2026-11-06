"""GreyNoise Community enricher: parse classification, handle 404 as a finding (not error)."""

from __future__ import annotations

import httpx

from cyllex_argus.enrichment.base import EnrichmentRequest
from cyllex_argus.enrichment.greynoise import GreyNoiseEnricher


def _enricher(handler) -> GreyNoiseEnricher:
    return GreyNoiseEnricher(client=httpx.Client(transport=httpx.MockTransport(handler)))


SAMPLE = {
    "ip": "198.51.100.10",
    "noise": True,
    "riot": False,
    "classification": "malicious",
    "name": "Mirai",
    "link": "https://viz.greynoise.io/riot/198.51.100.10",
    "last_seen": "2024-05-15",
    "message": "Success",
}


def test_known_scanner_returns_classification_and_name():
    def handler(request):
        assert "198.51.100.10" in str(request.url)
        return httpx.Response(200, json=SAMPLE)
    result = _enricher(handler).enrich(EnrichmentRequest("198.51.100.10", "ipv4-addr"))
    assert result.error is None
    pairs = {(f.key, f.value) for f in result.findings}
    assert ("noise", "True") in pairs
    assert ("classification", "malicious") in pairs
    assert ("scanner-name", "Mirai") in pairs
    assert ("last-seen", "2024-05-15") in pairs


def test_unseen_ip_returns_noise_false_as_a_finding_not_an_error():
    """GreyNoise 404 = 'never seen scanning the Internet'. For an SOC this is the signal, not a
    failure — a targeted-looking IP that is NOT in the noise feed is more interesting."""
    def handler(request):
        return httpx.Response(404, json={"message": "IP not observed scanning the Internet"})
    result = _enricher(handler).enrich(EnrichmentRequest("203.0.113.5", "ipv4-addr"))
    assert result.error is None
    [finding] = result.findings
    assert finding.key == "noise" and finding.value == "false"


def test_rate_limit_is_a_clean_error():
    def handler(request):
        return httpx.Response(429)
    result = _enricher(handler).enrich(EnrichmentRequest("198.51.100.10", "ipv4-addr"))
    assert result.error and "429" in result.error


def test_bad_ip_is_refused_without_a_network_call():
    calls = []
    def handler(request):
        calls.append(request)
        return httpx.Response(200)
    result = _enricher(handler).enrich(EnrichmentRequest("not-an-ip", "ipv4-addr"))
    assert result.error and "valid IP" in result.error
    assert calls == []


def test_unsupported_type_is_an_error():
    result = _enricher(lambda _: httpx.Response(200)).enrich(
        EnrichmentRequest("example.com", "domain-name"),
    )
    assert result.error and "unsupported" in result.error


def test_outbound_statement_mentions_greynoise_and_the_opsec_reality():
    enricher = GreyNoiseEnricher()
    assert "api.greynoise.io" in enricher.outbound
    assert "scanning" in enricher.outbound.lower()


def test_ipv6_is_accepted():
    def handler(request):
        return httpx.Response(200, json={"noise": False, "classification": "unknown"})
    result = _enricher(handler).enrich(EnrichmentRequest("2001:db8::1", "ipv6-addr"))
    assert result.error is None
