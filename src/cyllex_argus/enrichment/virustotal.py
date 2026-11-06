"""VirusTotal enricher: file/url/domain/IP reputation via the public v3 API.

VirusTotal is a cross-vendor malware/indicator intelligence service owned by Google. A lookup
leaks the queried value to a well-known defensive provider. Public-API tier is anonymous as
far as adversaries are concerned (no per-request logs exposed), but Enterprise/Premium
customers of VirusTotal — which includes well-funded adversaries — can see aggregated query
patterns, same OPSEC trade-off as any other third-party enrichment.

Four endpoints are used, one per observable type:

- `GET /api/v3/files/{sha256|sha1|md5}`
- `GET /api/v3/urls/{base64url(url_no_padding)}`
- `GET /api/v3/domains/{domain}`
- `GET /api/v3/ip_addresses/{ip}`

Every call carries `x-apikey: <key>`. The key resolves from
`VIRUSTOTAL_API_KEY` env > `[enrichment.virustotal] api_key` toml > unavailable. See
https://docs.virustotal.com/reference/overview for the full reference.

The enricher does NOT re-upload files; `files/{hash}` only queries by hash. There is no
information disclosure beyond the hash itself.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import os
import re
import time
from typing import Any

import httpx

from cyllex_argus.enrichment.base import (
    EnrichedIndicatorType,
    EnrichmentFinding,
    EnrichmentRequest,
    EnrichmentResult,
)

VT_API_BASE = "https://www.virustotal.com/api/v3"
VT_API_KEY_ENV = "VIRUSTOTAL_API_KEY"
MAX_RESPONSE_BYTES = 4_000_000  # VT /files responses can be fat with sandbox verdicts
_MD5 = re.compile(r"^[A-Fa-f0-9]{32}$")
_SHA1 = re.compile(r"^[A-Fa-f0-9]{40}$")
_SHA256 = re.compile(r"^[A-Fa-f0-9]{64}$")


def _resolve_api_key(explicit: str | None, env_name: str | None = None) -> str:
    """Env wins; then the enricher's own stored key (passed in by the config loader at
    instantiation time); then empty. Mirrors the admin-password + LLM provider patterns.

    `env_name` is the toml `env_api_key`: the name of the variable to read, so an operator can
    point it at their own secret manager's variable, exactly as TAXII/MISP servers do. Empty
    falls back to the documented default VIRUSTOTAL_API_KEY, so existing setups keep working."""
    name = (env_name or "").strip() or VT_API_KEY_ENV
    from_env = os.environ.get(name, "").strip()
    if from_env:
        return from_env
    if explicit:
        return explicit.strip()
    return ""


def _url_id(url: str) -> str:
    """VirusTotal addresses URL reports by the base64url-no-padding encoding of the URL. The
    scheme stays as the operator typed it (`http://` vs `https://` → different reports)."""
    encoded = base64.urlsafe_b64encode(url.strip().encode("utf-8")).decode("ascii")
    return encoded.rstrip("=")


class VirusTotalEnricher:
    name: str = "virustotal"
    description: str = "VirusTotal (Google) multi-engine reputation for file, URL, domain, IP"
    outbound: str = (
        "The exact indicator (hash / URL / domain / IP) is sent to www.virustotal.com with the "
        "VirusTotal API key in the x-apikey header. Public-tier anonymous as far as adversaries "
        "are concerned; Enterprise VT customers can see aggregated query patterns."
    )
    supported_types: tuple[EnrichedIndicatorType, ...] = (
        "file-hash", "url", "domain-name", "ipv4-addr", "ipv6-addr",
    )

    def __init__(
        self,
        api_key: str | None = None,
        env_api_key: str | None = None,
        client: httpx.Client | None = None,
    ) -> None:
        self._configured_key = api_key or ""
        self._env_api_key = env_api_key or ""
        self._client = client if client is not None else httpx.Client(timeout=20.0)

    def enrich(self, request: EnrichmentRequest) -> EnrichmentResult:
        start = time.monotonic()
        key = _resolve_api_key(self._configured_key, self._env_api_key)
        if not key:
            env_name = self._env_api_key.strip() or VT_API_KEY_ENV
            return _done(
                request, start,
                error=(
                    f"VirusTotal API key not configured. Set the {env_name} env var (preferred) or "
                    "[enrichment.virustotal] api_key in argus.toml."
                ),
            )
        indicator = request.indicator.strip()
        if request.indicator_type == "file-hash":
            value = indicator.lower()
            if not (_SHA256.match(value) or _SHA1.match(value) or _MD5.match(value)):
                return _done(request, start, error=f"not a valid MD5/SHA1/SHA256 hash: {indicator!r}")
            return self._lookup(start, request, key, f"/files/{value}", _file_findings)
        if request.indicator_type == "url":
            if not indicator.startswith(("http://", "https://")):
                return _done(request, start, error=f"not a valid URL: {indicator!r}")
            return self._lookup(start, request, key, f"/urls/{_url_id(indicator)}", _url_findings)
        if request.indicator_type == "domain-name":
            return self._lookup(start, request, key, f"/domains/{indicator}", _domain_findings)
        if request.indicator_type in ("ipv4-addr", "ipv6-addr"):
            try:
                ipaddress.ip_address(indicator)
            except ValueError:
                return _done(request, start, error=f"not a valid IP address: {indicator!r}")
            return self._lookup(start, request, key, f"/ip_addresses/{indicator}", _ip_findings)
        return _done(request, start, error=f"unsupported indicator type {request.indicator_type!r}")

    def _lookup(self, start, request, key, path, extract):
        try:
            response = self._client.get(
                f"{VT_API_BASE}{path}", headers={"x-apikey": key, "Accept": "application/json"},
            )
            body = response.content[:MAX_RESPONSE_BYTES]
        except httpx.HTTPError as exc:
            return _done(request, start, error=f"VirusTotal unreachable: {exc}")
        if response.status_code == 404:
            # "No report for this indicator" is a finding, not an error — VT has never seen it.
            return _done(request, start, findings=[
                EnrichmentFinding(source=self.name, key="known", value="false",
                                  detail="VirusTotal has no report for this indicator"),
            ])
        if response.status_code == 401:
            return _done(request, start, error="VirusTotal rejected the API key (401).")
        if response.status_code == 429:
            return _done(request, start, error="VirusTotal rate-limit (HTTP 429).")
        if response.status_code != 200:
            return _done(request, start, error=f"VirusTotal HTTP {response.status_code}")
        try:
            payload = json.loads(body) if body else {}
        except json.JSONDecodeError as exc:
            return _done(request, start, error=f"VirusTotal answer was not JSON: {exc}")
        if not isinstance(payload, dict):
            return _done(request, start, error="VirusTotal answer had an unexpected shape")
        data = payload.get("data") or {}
        if not isinstance(data, dict):
            return _done(request, start, error="VirusTotal data block is not an object")
        attributes = data.get("attributes") or {}
        if not isinstance(attributes, dict):
            return _done(request, start, findings=[])
        return _done(request, start, findings=list(extract(attributes, self.name)))


def _emit_last_analysis(attributes: dict, source: str):
    stats = attributes.get("last_analysis_stats")
    if isinstance(stats, dict):
        for key, value in stats.items():
            if not isinstance(value, int):
                continue
            yield EnrichmentFinding(source=source, key=f"stat-{key}", value=str(value))
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        if isinstance(malicious, int) and isinstance(suspicious, int):
            verdict = _verdict(malicious, suspicious)
            yield EnrichmentFinding(
                source=source, key="verdict", value=verdict,
                detail=f"{malicious} malicious / {suspicious} suspicious across engines",
            )
    reputation = attributes.get("reputation")
    if isinstance(reputation, int):
        yield EnrichmentFinding(source=source, key="reputation", value=str(reputation))


def _verdict(malicious: int, suspicious: int) -> str:
    if malicious >= 5:
        return "malicious"
    if malicious >= 1 or suspicious >= 3:
        return "suspicious"
    return "clean"


def _file_findings(attributes: dict, source: str):
    yield from _emit_last_analysis(attributes, source)
    for key_in, key_out in (
        ("meaningful_name", "filename"),
        ("type_description", "file-type"),
        ("size", "file-size"),
        ("first_submission_date", "first-seen"),
        ("last_submission_date", "last-seen"),
        ("times_submitted", "times-submitted"),
    ):
        value = attributes.get(key_in)
        if value is None or value == "":
            continue
        observed = _epoch_to_iso(value) if key_out in ("first-seen", "last-seen") else None
        yield EnrichmentFinding(
            source=source, key=key_out, value=str(value), observed_at=observed,
        )
    labels = attributes.get("popular_threat_classification") or {}
    if isinstance(labels, dict):
        suggested = labels.get("suggested_threat_label")
        if isinstance(suggested, str) and suggested:
            yield EnrichmentFinding(source=source, key="threat-label", value=suggested)
        for category in labels.get("popular_threat_category") or []:
            if isinstance(category, dict):
                name = category.get("value")
                if isinstance(name, str) and name:
                    yield EnrichmentFinding(source=source, key="threat-category", value=name)


def _url_findings(attributes: dict, source: str):
    yield from _emit_last_analysis(attributes, source)
    for key_in, key_out in (
        ("last_final_url", "final-url"),
        ("title", "page-title"),
        ("first_submission_date", "first-seen"),
        ("last_analysis_date", "last-seen"),
    ):
        value = attributes.get(key_in)
        if value is None or value == "":
            continue
        observed = _epoch_to_iso(value) if key_out in ("first-seen", "last-seen") else None
        yield EnrichmentFinding(
            source=source, key=key_out, value=str(value), observed_at=observed,
        )


def _domain_findings(attributes: dict, source: str):
    yield from _emit_last_analysis(attributes, source)
    registrar = attributes.get("registrar")
    if isinstance(registrar, str) and registrar:
        yield EnrichmentFinding(source=source, key="registrar", value=registrar)
    creation = attributes.get("creation_date")
    if isinstance(creation, int):
        yield EnrichmentFinding(
            source=source, key="creation-date", value=str(creation),
            observed_at=_epoch_to_iso(creation),
        )
    for category_source, category in (attributes.get("categories") or {}).items():
        if isinstance(category, str) and category:
            yield EnrichmentFinding(
                source=source, key="category", value=category, detail=str(category_source),
            )


def _ip_findings(attributes: dict, source: str):
    yield from _emit_last_analysis(attributes, source)
    for key_in, key_out in (
        ("asn", "asn"),
        ("as_owner", "as-owner"),
        ("country", "country"),
        ("network", "network"),
    ):
        value = attributes.get(key_in)
        if value is None or value == "":
            continue
        yield EnrichmentFinding(source=source, key=key_out, value=str(value))


def _epoch_to_iso(value: Any) -> str | None:
    """VT dates are Unix epochs (seconds). Return an ISO-8601 string, or None on bad input."""
    try:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(value)))
    except (ValueError, TypeError, OSError):
        return None


def _done(request, start, *, findings=None, error=None):
    return EnrichmentResult(
        request=request, findings=findings or [], error=error,
        duration_ms=int((time.monotonic() - start) * 1000),
    )
