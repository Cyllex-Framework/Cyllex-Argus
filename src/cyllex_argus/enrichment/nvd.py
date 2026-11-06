"""NVD enricher: CVE lookup via the National Vulnerability Database 2.0 API.

NVD is a US government public resource. A query for a CVE id leaks no 'intent' in the OPSEC sense:
the CVE is already a public record the moment it is issued. For an operator this is one of the
cheapest-to-enable enrichments: it adds CVSS score, severity, description and CWE to every CVE
claim the Analyst already extracts, pulling the vulnerability intelligence that priority-driven
patching needs.

Rate limit note: without an API key NVD throttles to ~5 requests per 30 seconds per IP. The
enricher does not implement its own retry/backoff; the pipeline-level backoff and the single-call
nature of a `uses` claim keep this well below the limit in practice.
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

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
MAX_DESCRIPTION_CHARS = 400
MAX_RESPONSE_BYTES = 2_000_000


class NvdEnricher:
    name: str = "nvd"
    description: str = "NVD (National Vulnerability Database) CVE lookup"
    outbound: str = (
        "The CVE id is sent as a query parameter to services.nvd.nist.gov. NVD is a US government "
        "public resource; CVE ids are themselves public records, so this leaks no intent."
    )
    supported_types: tuple[EnrichedIndicatorType, ...] = ("vulnerability",)

    def __init__(self, client: httpx.Client | None = None) -> None:
        self._client = client if client is not None else httpx.Client(timeout=15.0)

    def enrich(self, request: EnrichmentRequest) -> EnrichmentResult:
        start = time.monotonic()
        if request.indicator_type not in self.supported_types:
            return _done(request, start, error=f"unsupported indicator type {request.indicator_type!r}")
        cve = request.indicator.strip().upper()
        if not _CVE_RE.match(cve):
            return _done(request, start, error=f"not a CVE id: {request.indicator!r}")
        try:
            response = self._client.get(NVD_URL, params={"cveId": cve})
            response.raise_for_status()
            body = response.content[:MAX_RESPONSE_BYTES]
        except httpx.HTTPError as exc:
            return _done(request, start, error=f"NVD unreachable: {exc}")
        try:
            data = json.loads(body) if body else {}
        except json.JSONDecodeError as exc:
            return _done(request, start, error=f"NVD answer was not JSON: {exc}")
        if not isinstance(data, dict):
            return _done(request, start, error="NVD answer had an unexpected shape")
        vulns = data.get("vulnerabilities") or []
        if not vulns:
            return _done(request, start, findings=[])
        cve_obj = (vulns[0] or {}).get("cve", {}) if isinstance(vulns[0], dict) else {}
        if not isinstance(cve_obj, dict):
            return _done(request, start, error="NVD answer had an unexpected shape")
        return _done(request, start, findings=list(_findings(cve_obj, self.name)))


def _findings(cve: dict, source: str) -> list[EnrichmentFinding]:
    findings: list[EnrichmentFinding] = []
    # CVSS metrics. NVD exposes "cvssMetricV31" / "cvssMetricV30" / "cvssMetricV2" lists.
    metrics = cve.get("metrics", {}) or {}
    for scheme, items in metrics.items():
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            block = item.get("cvssData", {}) or {}
            score = block.get("baseScore")
            severity = block.get("baseSeverity") or block.get("severity") or ""
            vector = block.get("vectorString") or ""
            if score is None:
                continue
            findings.append(EnrichmentFinding(
                source=source,
                key=f"cvss-{scheme.replace('cvssMetric', '').lower()}" or "cvss",
                value=str(score),
                detail=f"{severity}; {vector}".strip("; "),
            ))
    # First English description.
    for desc in cve.get("descriptions", []) or []:
        if isinstance(desc, dict) and desc.get("lang") == "en" and desc.get("value"):
            findings.append(EnrichmentFinding(
                source=source,
                key="description",
                value=str(desc["value"])[:MAX_DESCRIPTION_CHARS],
            ))
            break
    # Published / last-modified dates.
    for key_in, key_out in (("published", "published"), ("lastModified", "last-modified")):
        value = cve.get(key_in)
        if isinstance(value, str) and value:
            findings.append(EnrichmentFinding(
                source=source, key=key_out, value=value, observed_at=value,
            ))
    # CWE (one entry per weakness description).
    for weakness in cve.get("weaknesses", []) or []:
        for desc in (weakness or {}).get("description", []) or []:
            if isinstance(desc, dict) and desc.get("lang") == "en":
                value = str(desc.get("value", "")).strip()
                if value:
                    findings.append(EnrichmentFinding(source=source, key="cwe", value=value))
    # References (first few, kept short).
    for ref in (cve.get("references", []) or [])[:3]:
        if isinstance(ref, dict) and ref.get("url"):
            findings.append(EnrichmentFinding(
                source=source, key="reference", value=str(ref["url"]),
                detail=", ".join(ref.get("tags", []) or []) or None,
            ))
    return findings


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
