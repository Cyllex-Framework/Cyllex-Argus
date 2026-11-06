"""NVD enricher: parses CVSS, description, CWE and refs; validates CVE shape; fails loud."""

from __future__ import annotations

import httpx

from cyllex_argus.enrichment.base import EnrichmentRequest
from cyllex_argus.enrichment.nvd import NvdEnricher


def _client(handler) -> NvdEnricher:
    return NvdEnricher(client=httpx.Client(transport=httpx.MockTransport(handler)))


# A hand-shaped sample of what the real NVD 2.0 API returns, pruned to what the enricher reads.
NVD_SAMPLE = {
    "vulnerabilities": [{
        "cve": {
            "id": "CVE-2024-12345",
            "published": "2024-06-01T10:00:00.000",
            "lastModified": "2024-06-15T12:00:00.000",
            "descriptions": [
                {"lang": "es", "value": "Vulnerabilidad en …"},
                {"lang": "en", "value": "Buffer overflow in Acme Widget allows remote code execution."},
            ],
            "metrics": {
                "cvssMetricV31": [
                    {"cvssData": {
                        "baseScore": 9.8, "baseSeverity": "CRITICAL",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    }},
                ],
            },
            "weaknesses": [
                {"description": [{"lang": "en", "value": "CWE-120 Buffer Copy without Checking Size of Input"}]},
            ],
            "references": [
                {"url": "https://acme.example/advisory", "tags": ["Vendor Advisory"]},
                {"url": "https://nvd.nist.gov/vuln/detail/CVE-2024-12345", "tags": []},
            ],
        },
    }],
}


def test_parses_the_canonical_fields_from_an_nvd_response():
    def handler(request):
        assert request.url.params["cveId"] == "CVE-2024-12345"
        return httpx.Response(200, json=NVD_SAMPLE)
    result = _client(handler).enrich(EnrichmentRequest("CVE-2024-12345", "vulnerability"))
    assert result.error is None
    out = {(f.key, f.value) for f in result.findings}
    assert ("cvss-v31", "9.8") in out
    assert ("description", "Buffer overflow in Acme Widget allows remote code execution.") in out
    assert ("cwe", "CWE-120 Buffer Copy without Checking Size of Input") in out
    assert ("published", "2024-06-01T10:00:00.000") in out
    assert ("last-modified", "2024-06-15T12:00:00.000") in out
    assert ("reference", "https://acme.example/advisory") in out
    # The CVSS detail must include the severity so the operator sees it at a glance.
    cvss = next(f for f in result.findings if f.key == "cvss-v31")
    assert cvss.detail is not None and "CRITICAL" in cvss.detail


def test_lowercased_cve_is_accepted_after_normalization():
    def handler(request):
        return httpx.Response(200, json=NVD_SAMPLE)
    result = _client(handler).enrich(EnrichmentRequest("cve-2024-12345", "vulnerability"))
    assert result.error is None
    assert any(f.key == "cvss-v31" for f in result.findings)


def test_rejects_non_cve_input():
    result = _client(lambda _: httpx.Response(200)).enrich(
        EnrichmentRequest("not-a-cve", "vulnerability"),
    )
    assert result.error and "CVE" in result.error


def test_rejects_unsupported_type():
    result = _client(lambda _: httpx.Response(200)).enrich(
        EnrichmentRequest("example.com", "domain-name"),
    )
    assert result.error and "unsupported" in result.error


def test_empty_vulnerabilities_list_is_zero_findings_not_an_error():
    def handler(request):
        return httpx.Response(200, json={"vulnerabilities": []})
    result = _client(handler).enrich(EnrichmentRequest("CVE-2099-99999", "vulnerability"))
    assert result.error is None
    assert result.findings == []


def test_http_error_returns_error_result_without_raising():
    def handler(request):
        return httpx.Response(503)
    result = _client(handler).enrich(EnrichmentRequest("CVE-2024-12345", "vulnerability"))
    assert result.findings == []
    assert result.error and "503" in result.error


def test_malformed_body_is_an_error_not_a_crash():
    def handler(request):
        return httpx.Response(200, content=b"<html>nope</html>")
    result = _client(handler).enrich(EnrichmentRequest("CVE-2024-12345", "vulnerability"))
    assert result.error and "not JSON" in result.error


def test_outbound_statement_names_nvd_and_claims_no_intent_leak():
    enricher = NvdEnricher()
    assert "services.nvd.nist.gov" in enricher.outbound
    assert "intent" in enricher.outbound.lower()


def test_description_is_capped_so_a_wall_of_text_does_not_bloat_the_trace():
    long_description = "x" * 10_000
    def handler(request):
        return httpx.Response(200, json={"vulnerabilities": [{"cve": {
            "id": "CVE-2024-12345",
            "descriptions": [{"lang": "en", "value": long_description}],
            "metrics": {}, "weaknesses": [], "references": [],
        }}]})
    result = _client(handler).enrich(EnrichmentRequest("CVE-2024-12345", "vulnerability"))
    desc = next(f for f in result.findings if f.key == "description")
    assert len(desc.value) <= 400
