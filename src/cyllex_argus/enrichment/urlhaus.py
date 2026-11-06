"""URLhaus enricher: URL and payload (file-hash) reputation via abuse.ch.

URLhaus is a free, public threat-sharing database run by abuse.ch. A lookup against it leaks only
the queried URL or hash to a well-known defensive provider; the service does not log who looks up
what in a way that reveals operator intent to adversaries (unlike VirusTotal where privileged
accounts see queries).

Two endpoints are used:

- `POST /v1/url/` with `url=<value>` — URL lookup. Returns the current status, assigned
  threat label, tags and the malware family URLhaus has mapped to it, plus a count of related
  payloads.
- `POST /v1/payload/` with `<hash_type>_hash=<value>` — Payload lookup by MD5/SHA256. Returns
  file metadata and the signatures/signatures URLhaus has for it.

See https://urlhaus-api.abuse.ch/ for the API reference.
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

URLHAUS_URL_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/url/"
URLHAUS_PAYLOAD_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/payload/"
MAX_RESPONSE_BYTES = 2_000_000
_MD5 = re.compile(r"^[A-Fa-f0-9]{32}$")
_SHA256 = re.compile(r"^[A-Fa-f0-9]{64}$")


class UrlhausEnricher:
    name: str = "urlhaus"
    description: str = "URLhaus (abuse.ch) URL and payload reputation"
    outbound: str = (
        "The exact URL or hash is sent as an HTTP POST to urlhaus-api.abuse.ch. URLhaus is a "
        "defensive-sharing database; the service does not expose per-query logs to adversaries."
    )
    supported_types: tuple[EnrichedIndicatorType, ...] = ("url", "file-hash")

    def __init__(self, client: httpx.Client | None = None) -> None:
        self._client = client if client is not None else httpx.Client(timeout=15.0)

    def enrich(self, request: EnrichmentRequest) -> EnrichmentResult:
        start = time.monotonic()
        if request.indicator_type == "url":
            return self._lookup(start, request, URLHAUS_URL_ENDPOINT, {"url": request.indicator.strip()},
                                _url_findings)
        if request.indicator_type == "file-hash":
            value = request.indicator.strip().lower()
            if _SHA256.match(value):
                data = {"sha256_hash": value}
            elif _MD5.match(value):
                data = {"md5_hash": value}
            else:
                return _done(request, start, error=f"not an MD5 or SHA256: {request.indicator!r}")
            return self._lookup(start, request, URLHAUS_PAYLOAD_ENDPOINT, data, _payload_findings)
        return _done(request, start, error=f"unsupported indicator type {request.indicator_type!r}")

    def _lookup(self, start, request, endpoint, data, extract):
        try:
            response = self._client.post(endpoint, data=data)
            response.raise_for_status()
            body = response.content[:MAX_RESPONSE_BYTES]
        except httpx.HTTPError as exc:
            return _done(request, start, error=f"URLhaus unreachable: {exc}")
        try:
            payload = json.loads(body) if body else {}
        except json.JSONDecodeError as exc:
            return _done(request, start, error=f"URLhaus answer was not JSON: {exc}")
        if not isinstance(payload, dict):
            return _done(request, start, error="URLhaus answer had an unexpected shape")
        query_status = str(payload.get("query_status", "")).strip()
        if query_status == "no_results":
            return _done(request, start, findings=[])
        if query_status and query_status != "ok":
            return _done(request, start, error=f"URLhaus query_status={query_status!r}")
        return _done(request, start, findings=list(extract(payload, self.name)))


def _url_findings(payload, source):
    status = payload.get("url_status")
    if isinstance(status, str) and status:
        yield EnrichmentFinding(source=source, key="url-status", value=status)
    threat = payload.get("threat")
    if isinstance(threat, str) and threat:
        yield EnrichmentFinding(source=source, key="threat", value=threat)
    date_added = payload.get("date_added")
    if isinstance(date_added, str) and date_added:
        yield EnrichmentFinding(
            source=source, key="date-added", value=date_added, observed_at=date_added,
        )
    reporter = payload.get("reporter")
    if isinstance(reporter, str) and reporter:
        yield EnrichmentFinding(source=source, key="reporter", value=reporter)
    for tag in payload.get("tags") or []:
        if isinstance(tag, str) and tag:
            yield EnrichmentFinding(source=source, key="tag", value=tag)
    payloads = payload.get("payloads") or []
    if isinstance(payloads, list):
        for item in payloads[:5]:
            if not isinstance(item, dict):
                continue
            family = item.get("signature")
            file_name = item.get("filename")
            if isinstance(family, str) and family:
                yield EnrichmentFinding(
                    source=source, key="malware-family", value=family,
                    detail=file_name if isinstance(file_name, str) else None,
                )


def _payload_findings(payload, source):
    sig = payload.get("signature")
    if isinstance(sig, str) and sig:
        yield EnrichmentFinding(source=source, key="malware-family", value=sig)
    file_type = payload.get("file_type")
    if isinstance(file_type, str) and file_type:
        yield EnrichmentFinding(source=source, key="file-type", value=file_type)
    first_seen = payload.get("firstseen")
    if isinstance(first_seen, str) and first_seen:
        yield EnrichmentFinding(
            source=source, key="first-seen", value=first_seen, observed_at=first_seen,
        )
    last_seen = payload.get("lastseen")
    if isinstance(last_seen, str) and last_seen:
        yield EnrichmentFinding(
            source=source, key="last-seen", value=last_seen, observed_at=last_seen,
        )
    file_size = payload.get("file_size")
    if file_size is not None:
        yield EnrichmentFinding(source=source, key="file-size", value=str(file_size))
    for tag in payload.get("tags") or []:
        if isinstance(tag, str) and tag:
            yield EnrichmentFinding(source=source, key="tag", value=tag)


def _done(request, start, *, findings=None, error=None):
    return EnrichmentResult(
        request=request, findings=findings or [], error=error,
        duration_ms=int((time.monotonic() - start) * 1000),
    )
