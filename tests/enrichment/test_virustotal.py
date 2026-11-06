"""Tests for the VirusTotal v3 enricher.

Covers the four observable paths (file-hash, url, domain-name, ip), the API-key resolution
precedence (env > toml > unavailable), the 404-as-finding contract (VT has never seen it),
and the common error shapes (401, 429, 5xx, non-JSON).
"""

from __future__ import annotations

import base64

import httpx
import pytest

from cyllex_argus.enrichment.base import EnrichmentRequest
from cyllex_argus.enrichment.virustotal import VT_API_KEY_ENV, VirusTotalEnricher


def _mock_client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def _url_report(**over):
    base = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "harmless": 60, "malicious": 7, "suspicious": 2, "undetected": 12, "timeout": 0,
                },
                "reputation": -8,
                "last_final_url": "https://evil.example.com/final",
                "title": "Fake Microsoft 365 login",
                "first_submission_date": 1715731200,  # 2026-05-15 UTC
                "last_analysis_date": 1718323200,
            }
        }
    }
    base.update(over)
    return base


# ---- API key resolution ------------------------------------------------------------


def test_missing_api_key_returns_an_actionable_error(monkeypatch):
    """The enricher does not fail silently when there is no key — it returns an EnrichmentResult
    with an error message pointing at the env var the operator should set."""
    monkeypatch.delenv(VT_API_KEY_ENV, raising=False)
    enricher = VirusTotalEnricher(api_key="", client=_mock_client(lambda r: httpx.Response(500)))
    result = enricher.enrich(EnrichmentRequest(indicator="example.com", indicator_type="domain-name"))
    assert result.error is not None
    assert VT_API_KEY_ENV in result.error


def test_env_api_key_wins_over_toml_api_key(monkeypatch):
    monkeypatch.setenv(VT_API_KEY_ENV, "env-wins")
    seen = {}

    def handler(request):
        seen["apikey"] = request.headers.get("x-apikey")
        return httpx.Response(200, json=_url_report())

    enricher = VirusTotalEnricher(api_key="from-toml", client=_mock_client(handler))
    enricher.enrich(EnrichmentRequest(indicator="example.com", indicator_type="domain-name"))
    assert seen["apikey"] == "env-wins"


def test_toml_api_key_is_used_when_env_is_not_set(monkeypatch):
    monkeypatch.delenv(VT_API_KEY_ENV, raising=False)
    seen = {}

    def handler(request):
        seen["apikey"] = request.headers.get("x-apikey")
        return httpx.Response(200, json=_url_report())

    enricher = VirusTotalEnricher(api_key="from-toml", client=_mock_client(handler))
    enricher.enrich(EnrichmentRequest(indicator="example.com", indicator_type="domain-name"))
    assert seen["apikey"] == "from-toml"


def test_custom_env_var_name_is_honored(monkeypatch):
    """A configured env_api_key names a custom variable, and that variable wins — the same way
    TAXII/MISP servers honor a custom env-var name. (With env_api_key empty, VIRUSTOTAL_API_KEY
    stays the default, covered by the two tests above.)"""
    monkeypatch.delenv(VT_API_KEY_ENV, raising=False)       # the default name is NOT set
    monkeypatch.setenv("MY_VT_KEY", "from-custom-env")
    seen = {}

    def handler(request):
        seen["apikey"] = request.headers.get("x-apikey")
        return httpx.Response(200, json=_url_report())

    enricher = VirusTotalEnricher(api_key="from-toml", env_api_key="MY_VT_KEY", client=_mock_client(handler))
    enricher.enrich(EnrichmentRequest(indicator="example.com", indicator_type="domain-name"))
    assert seen["apikey"] == "from-custom-env"              # custom env beats the toml key


# ---- Observable paths --------------------------------------------------------------


def test_file_hash_returns_last_analysis_stats_and_verdict(monkeypatch):
    monkeypatch.setenv(VT_API_KEY_ENV, "k")
    attrs = {
        "last_analysis_stats": {"harmless": 10, "malicious": 20, "suspicious": 3, "undetected": 5, "timeout": 0},
        "reputation": -42,
        "meaningful_name": "invoice.exe",
        "type_description": "Win32 Executable",
        "size": 123456,
        "first_submission_date": 1715731200,
        "last_submission_date": 1718323200,
        "times_submitted": 17,
        "popular_threat_classification": {
            "suggested_threat_label": "trojan.emotet",
            "popular_threat_category": [{"value": "trojan"}, {"value": "banker"}],
        },
    }
    sha = "a" * 64
    handler = lambda r: httpx.Response(200, json={"data": {"attributes": attrs}})
    enricher = VirusTotalEnricher(client=_mock_client(handler))
    result = enricher.enrich(EnrichmentRequest(indicator=sha, indicator_type="file-hash"))
    assert result.error is None
    keys = {f.key: f.value for f in result.findings}
    assert keys["stat-malicious"] == "20"
    assert keys["verdict"] == "malicious"
    assert keys["reputation"] == "-42"
    assert keys["filename"] == "invoice.exe"
    assert keys["threat-label"] == "trojan.emotet"
    # observed_at parsed from epoch (1715731200 → 2024-05-15 UTC)
    first_seen = next(f for f in result.findings if f.key == "first-seen")
    assert first_seen.observed_at and first_seen.observed_at.startswith("2024-05-15")


def test_file_hash_rejects_wrong_lengths(monkeypatch):
    monkeypatch.setenv(VT_API_KEY_ENV, "k")
    enricher = VirusTotalEnricher(client=_mock_client(lambda r: httpx.Response(200)))
    result = enricher.enrich(EnrichmentRequest(indicator="not-a-hash", indicator_type="file-hash"))
    assert result.error is not None
    assert "MD5" in result.error or "SHA" in result.error


def test_url_lookup_uses_base64url_no_padding_id(monkeypatch):
    monkeypatch.setenv(VT_API_KEY_ENV, "k")
    captured = {}

    def handler(request):
        captured["path"] = request.url.path
        return httpx.Response(200, json=_url_report())

    enricher = VirusTotalEnricher(client=_mock_client(handler))
    enricher.enrich(EnrichmentRequest(indicator="https://evil.example/path", indicator_type="url"))
    expected = base64.urlsafe_b64encode(b"https://evil.example/path").decode("ascii").rstrip("=")
    assert captured["path"].endswith(f"/urls/{expected}")


def test_url_lookup_extracts_the_right_fields(monkeypatch):
    monkeypatch.setenv(VT_API_KEY_ENV, "k")
    handler = lambda r: httpx.Response(200, json=_url_report())
    enricher = VirusTotalEnricher(client=_mock_client(handler))
    result = enricher.enrich(EnrichmentRequest(
        indicator="https://evil.example/path", indicator_type="url",
    ))
    assert result.error is None
    keys = {f.key: f.value for f in result.findings}
    assert keys["verdict"] == "malicious"   # 7 malicious >= 5
    assert keys["final-url"] == "https://evil.example.com/final"
    assert keys["page-title"] == "Fake Microsoft 365 login"


def test_url_must_be_http_or_https(monkeypatch):
    monkeypatch.setenv(VT_API_KEY_ENV, "k")
    enricher = VirusTotalEnricher(client=_mock_client(lambda r: httpx.Response(200)))
    result = enricher.enrich(EnrichmentRequest(indicator="ftp://x", indicator_type="url"))
    assert result.error is not None
    assert "valid URL" in result.error


def test_domain_lookup_extracts_registrar_and_categories(monkeypatch):
    monkeypatch.setenv(VT_API_KEY_ENV, "k")
    attrs = {
        "last_analysis_stats": {"harmless": 70, "malicious": 1, "suspicious": 0, "undetected": 10, "timeout": 0},
        "registrar": "ACME Inc.",
        "creation_date": 1715731200,
        "categories": {"Google Safebrowsing": "malware", "Forcepoint": "phishing"},
    }
    handler = lambda r: httpx.Response(200, json={"data": {"attributes": attrs}})
    enricher = VirusTotalEnricher(client=_mock_client(handler))
    result = enricher.enrich(EnrichmentRequest(indicator="example.com", indicator_type="domain-name"))
    assert result.error is None
    keys = {f.key for f in result.findings}
    assert "registrar" in keys
    assert "creation-date" in keys
    categories = {f.detail: f.value for f in result.findings if f.key == "category"}
    assert categories["Google Safebrowsing"] == "malware"


def test_ip_lookup_rejects_malformed_input(monkeypatch):
    monkeypatch.setenv(VT_API_KEY_ENV, "k")
    enricher = VirusTotalEnricher(client=_mock_client(lambda r: httpx.Response(200)))
    result = enricher.enrich(EnrichmentRequest(indicator="not-an-ip", indicator_type="ipv4-addr"))
    assert result.error is not None
    assert "valid IP" in result.error


def test_ip_lookup_extracts_asn_and_country(monkeypatch):
    monkeypatch.setenv(VT_API_KEY_ENV, "k")
    attrs = {
        "last_analysis_stats": {"harmless": 65, "malicious": 10, "suspicious": 1, "undetected": 5, "timeout": 0},
        "asn": 14618, "as_owner": "Amazon.com, Inc.", "country": "US", "network": "198.51.100.0/24",
    }
    handler = lambda r: httpx.Response(200, json={"data": {"attributes": attrs}})
    enricher = VirusTotalEnricher(client=_mock_client(handler))
    result = enricher.enrich(EnrichmentRequest(indicator="198.51.100.42", indicator_type="ipv4-addr"))
    keys = {f.key: f.value for f in result.findings}
    assert keys["asn"] == "14618"
    assert keys["as-owner"] == "Amazon.com, Inc."
    assert keys["country"] == "US"


# ---- 404-as-finding + error shapes --------------------------------------------------


def test_404_is_a_finding_not_an_error(monkeypatch):
    """VT has never seen the indicator — that is the signal, not a failure. Return a
    `known=false` finding so the operator can distinguish "no report" from "lookup broke"."""
    monkeypatch.setenv(VT_API_KEY_ENV, "k")
    handler = lambda r: httpx.Response(404, text="not found")
    enricher = VirusTotalEnricher(client=_mock_client(handler))
    result = enricher.enrich(EnrichmentRequest(indicator="example.com", indicator_type="domain-name"))
    assert result.error is None
    assert len(result.findings) == 1
    assert result.findings[0].key == "known"
    assert result.findings[0].value == "false"


def test_401_is_an_error(monkeypatch):
    monkeypatch.setenv(VT_API_KEY_ENV, "bad")
    handler = lambda r: httpx.Response(401, text="forbidden")
    enricher = VirusTotalEnricher(client=_mock_client(handler))
    result = enricher.enrich(EnrichmentRequest(indicator="example.com", indicator_type="domain-name"))
    assert result.error is not None
    assert "401" in result.error


def test_429_is_an_error(monkeypatch):
    monkeypatch.setenv(VT_API_KEY_ENV, "k")
    handler = lambda r: httpx.Response(429, text="slow down")
    enricher = VirusTotalEnricher(client=_mock_client(handler))
    result = enricher.enrich(EnrichmentRequest(indicator="example.com", indicator_type="domain-name"))
    assert result.error is not None
    assert "429" in result.error


def test_non_json_response_is_an_error(monkeypatch):
    monkeypatch.setenv(VT_API_KEY_ENV, "k")
    handler = lambda r: httpx.Response(200, text="<html>")
    enricher = VirusTotalEnricher(client=_mock_client(handler))
    result = enricher.enrich(EnrichmentRequest(indicator="example.com", indicator_type="domain-name"))
    assert result.error is not None


# ---- Verdict thresholds -------------------------------------------------------------


@pytest.mark.parametrize("malicious,suspicious,expected", [
    (10, 0, "malicious"),
    (5, 0, "malicious"),
    (1, 0, "suspicious"),
    (0, 3, "suspicious"),
    (0, 2, "clean"),
    (0, 0, "clean"),
])
def test_verdict_thresholds(monkeypatch, malicious, suspicious, expected):
    monkeypatch.setenv(VT_API_KEY_ENV, "k")
    attrs = {"last_analysis_stats": {"malicious": malicious, "suspicious": suspicious,
                                     "harmless": 50, "undetected": 10, "timeout": 0}}
    handler = lambda r: httpx.Response(200, json={"data": {"attributes": attrs}})
    enricher = VirusTotalEnricher(client=_mock_client(handler))
    result = enricher.enrich(EnrichmentRequest(indicator="example.com", indicator_type="domain-name"))
    verdict = next(f for f in result.findings if f.key == "verdict")
    assert verdict.value == expected
