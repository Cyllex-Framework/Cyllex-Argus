"""GreyNoise Community enricher: classify an IP as internet-scanner noise or targeted activity.

GreyNoise sees the whole Internet's background scanning and classifies IPs that *scan* it. A
Community-API lookup for an IP returns one of:

- `classification = benign`  — a known-good scanner (Shodan, Censys, Rapid7, …).
- `classification = malicious` — a scanner GreyNoise's analysts have flagged.
- `classification = unknown`  — scanner activity observed but not classified.
- `noise = false`             — the IP has not been seen scanning the Internet. For an SOC
  this is the signal: an "unseen-in-scanner-noise" IP that attacks you is more likely a
  targeted operator than a mass-scanner.

The Community endpoint is anonymous (no API key), rate-limited at the IP level, and does not
expose per-query logs to adversaries. OPSEC note (realistic): a motivated adversary with a
GreyNoise Enterprise account can see aggregated query patterns, but not per-request mapping.
"""

from __future__ import annotations

import ipaddress
import json
import time

import httpx

from cyllex_argus.enrichment.base import (
    EnrichedIndicatorType,
    EnrichmentFinding,
    EnrichmentRequest,
    EnrichmentResult,
)

COMMUNITY_URL = "https://api.greynoise.io/v3/community/{ip}"
MAX_RESPONSE_BYTES = 2_000_000


class GreyNoiseEnricher:
    name: str = "greynoise"
    description: str = "GreyNoise Community API — is this IP background scanner noise?"
    outbound: str = (
        "The exact IP is sent as a path parameter to api.greynoise.io. GreyNoise sees all "
        "Internet-wide scanning anyway; this leaks minimal intent for an SOC filter query."
    )
    supported_types: tuple[EnrichedIndicatorType, ...] = ("ipv4-addr", "ipv6-addr")

    def __init__(self, client: httpx.Client | None = None) -> None:
        self._client = client if client is not None else httpx.Client(timeout=15.0)

    def enrich(self, request: EnrichmentRequest) -> EnrichmentResult:
        start = time.monotonic()
        if request.indicator_type not in self.supported_types:
            return _done(request, start, error=f"unsupported indicator type {request.indicator_type!r}")
        candidate = request.indicator.strip()
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            return _done(request, start, error=f"not a valid IP address: {request.indicator!r}")
        try:
            response = self._client.get(COMMUNITY_URL.format(ip=candidate))
            body = response.content[:MAX_RESPONSE_BYTES]
        except httpx.HTTPError as exc:
            return _done(request, start, error=f"GreyNoise unreachable: {exc}")
        # The Community API returns 404 for an IP it has never seen scan. That is a finding, not
        # an error — it is the "unseen in scanner noise" signal the SOC filter cares about.
        if response.status_code == 404:
            return _done(request, start, findings=[
                EnrichmentFinding(source=GreyNoiseEnricher.name, key="noise", value="false",
                                  detail="not seen scanning the Internet by GreyNoise"),
            ])
        if response.status_code == 429:
            return _done(request, start, error="GreyNoise Community rate-limit (HTTP 429)")
        if response.status_code != 200:
            return _done(request, start, error=f"GreyNoise HTTP {response.status_code}")
        try:
            payload = json.loads(body) if body else {}
        except json.JSONDecodeError as exc:
            return _done(request, start, error=f"GreyNoise answer was not JSON: {exc}")
        if not isinstance(payload, dict):
            return _done(request, start, error="GreyNoise answer had an unexpected shape")
        return _done(request, start, findings=list(_findings(payload, GreyNoiseEnricher.name)))


def _findings(payload: dict, source: str):
    for key_in, key_out in (
        ("noise", "noise"),
        ("riot", "riot"),               # recognized common service (NTP, Google, Cloudflare…)
        ("classification", "classification"),
        ("name", "scanner-name"),
        ("link", "greynoise-link"),
        ("last_seen", "last-seen"),
    ):
        value = payload.get(key_in)
        if value is None or value == "":
            continue
        yield EnrichmentFinding(
            source=source, key=key_out, value=str(value),
            observed_at=str(value) if key_out == "last-seen" else None,
        )
    message = payload.get("message")
    if isinstance(message, str) and message and not payload.get("noise"):
        yield EnrichmentFinding(source=source, key="message", value=message)


def _done(request, start, *, findings=None, error=None):
    return EnrichmentResult(
        request=request, findings=findings or [], error=error,
        duration_ms=int((time.monotonic() - start) * 1000),
    )
