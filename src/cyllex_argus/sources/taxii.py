"""TAXII 2.1 subscriber: pull STIX `report` objects from external CTI servers.

Each configured `[[taxii]]` block becomes one `TaxiiConnector` instance in the Collector line-up.
The connector queries the server's `/collections/<id>/objects/` endpoint with a `match[type]=report`
filter and an `added_after` window (default 180 days), then emits a `CandidateSource` for every
report whose `name` or `description` mentions one of the target's aliases. The URL comes from the
report's `external_references` (the public link to the write-up); the date from `published` or
`created`; the publisher stays as `TAXII:<server-name>` so the admiralty table can score it.

`collection` may be a literal collection id, or `"*"` to query every readable collection the
server advertises on its `/collections/` endpoint (the connector merges the results).

What this is NOT:
- Not a MITRE ATT&CK loader — `argus attack update` already does that from the GitHub mirror.
  A TAXII pull of MITRE would duplicate work (and MITRE's ATT&CK collections carry no `report`
  objects anyway, so this connector would return nothing from them).
- Not an indicator importer — IOCs (STIX `indicator` objects) do not fit the "candidate document"
  shape this connector returns. Indicator ingestion lives in a future enrichment pass.

Auth (precedence per server, matches the admin-password + API-key pattern):
1. env var named by `env_api_key` on the toml → Bearer token
2. `api_key` field on the toml → Bearer token (plaintext on disk, warn in UI later)
3. `username` + `password` on the toml → HTTP Basic
4. nothing → unauthenticated request (public servers like abuse.ch URLhaus allow this)
"""

from __future__ import annotations

import base64
import logging
import os
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

from cyllex_argus.config.settings import TaxiiServerConfig
from cyllex_argus.knowledge.names import count_mentions
from cyllex_argus.sources.base import CandidateSource, ResolvedTarget

_log = logging.getLogger(__name__)

TAXII_CONTENT_TYPE = "application/taxii+json;version=2.1"
MAX_RESULTS_PER_SERVER = 50  # safety cap: a chatty server must not drown the Collector queue
ALL_COLLECTIONS = "*"  # query every readable collection the server advertises


def _resolve_auth(cfg: TaxiiServerConfig) -> dict[str, str]:
    """Return the HTTP headers to authenticate with this server, or {} for an anonymous request."""
    if cfg.env_api_key:
        token = os.environ.get(cfg.env_api_key, "").strip()
        if token:
            return {"Authorization": f"Bearer {token}"}
    if cfg.api_key.strip():
        return {"Authorization": f"Bearer {cfg.api_key.strip()}"}
    if cfg.username and cfg.password:
        creds = f"{cfg.username}:{cfg.password}".encode()
        return {"Authorization": f"Basic {base64.b64encode(creds).decode('ascii')}"}
    return {}


def _added_after_iso(days: int | None) -> str | None:
    """TAXII 2.1 `added_after` parameter in RFC 3339 (UTC). None means "no filter"."""
    if days is None or days <= 0:
        return None
    cutoff = datetime.now(UTC) - timedelta(days=days)
    return cutoff.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _extract_url(report: dict) -> str | None:
    """Prefer the first `external_references[].url`. The STIX 2.1 spec puts the public link to the
    full write-up here; the `description` field has the summary, which is already in the object."""
    for ref in report.get("external_references") or []:
        url = ref.get("url")
        if isinstance(url, str) and url.startswith(("http://", "https://")):
            return url
    return None


def _extract_published(report: dict) -> str | None:
    """Preferred ordering: `published` (report-specific) → `created` (fallback). Both are RFC 3339."""
    for key in ("published", "created"):
        value = report.get(key)
        if isinstance(value, str):
            return value
    return None


def _as_date(iso: str | None):
    """`CandidateSource.published_at` is a `date` or None. Degrade gracefully on malformed input."""
    if not iso:
        return None
    try:
        # STIX always writes '...Z'; use fromisoformat with the Z→+00:00 trick for 3.11+ portability.
        return datetime.fromisoformat(iso.replace("Z", "+00:00")).date()
    except (ValueError, TypeError):
        return None


def _report_matches(report: dict, aliases: list[str]) -> bool:
    """Count the target's aliases in the report's name + description. One mention is enough; the
    whole-pipeline Triage step is strict later. This filter is just to avoid shipping every
    report in the collection as a candidate when the server does not accept a text filter."""
    haystack = f"{report.get('name') or ''} {report.get('description') or ''}"
    return count_mentions(haystack, aliases) > 0


class TaxiiClient:
    """Minimal TAXII 2.1 subscriber client: list the objects of a collection (with an optional
    `match[type]` and `added_after` filter). When the configured collection is `"*"`, discover
    the server's readable collections via its `/collections/` endpoint and list each. Read-only:
    no object write."""

    def __init__(self, cfg: TaxiiServerConfig, client: httpx.Client) -> None:
        self._cfg = cfg
        self._client = client
        self._base_url = cfg.url.rstrip("/")

    def list_objects(self, match_type: str = "report", limit: int = MAX_RESULTS_PER_SERVER) -> list[dict]:
        objects: list[dict] = []
        for collection_id in self._collection_ids():
            objects.extend(self._objects_for_collection(collection_id, match_type, limit))
            if len(objects) >= limit:
                return objects[:limit]
        return objects[:limit]

    def _collection_ids(self) -> list[str]:
        """The collection ids to query. A literal id queries just that one; `"*"` discovers every
        readable collection via the TAXII `/collections/` endpoint."""
        if self._cfg.collection != ALL_COLLECTIONS:
            return [self._cfg.collection]
        url = f"{self._base_url}/collections/"
        response = self._client.get(url, headers=self._headers())
        self._check(response, "collections endpoint")
        try:
            body = response.json()
        except ValueError as exc:
            raise TaxiiServerError(
                f"TAXII server {self._cfg.name} returned non-JSON for /collections/: {response.text[:200]}"
            ) from exc
        collections = body.get("collections") or []
        return [
            c["id"] for c in collections
            if isinstance(c, dict) and c.get("id") and c.get("can_read", True)
        ]

    def _objects_for_collection(self, collection_id: str, match_type: str, limit: int) -> list[dict]:
        url = f"{self._base_url}/collections/{collection_id}/objects/"
        params: dict[str, Any] = {"match[type]": match_type, "limit": str(limit)}
        added_after = _added_after_iso(self._cfg.added_after_days)
        if added_after is not None:
            params["added_after"] = added_after
        response = self._client.get(url, params=params, headers=self._headers())
        self._check(response, f"collection '{collection_id}'")
        try:
            envelope = response.json()
        except ValueError as exc:
            raise TaxiiServerError(f"TAXII server {self._cfg.name} returned non-JSON: {response.text[:200]}") from exc
        objects = envelope.get("objects") or []
        if not isinstance(objects, list):
            raise TaxiiServerError(f"TAXII server {self._cfg.name}: envelope.objects is not a list.")
        return objects

    def _headers(self) -> dict[str, str]:
        return {"Accept": TAXII_CONTENT_TYPE, **_resolve_auth(self._cfg)}

    def _check(self, response: httpx.Response, what: str) -> None:
        """Map a TAXII HTTP status onto the connector's recoverable-error hierarchy."""
        if response.status_code == 401:
            raise TaxiiAuthError(f"TAXII server {self._cfg.name} rejected the credentials (401).")
        if response.status_code == 404:
            raise TaxiiNotFound(f"TAXII {what} not found on {self._cfg.name}.")
        if response.status_code >= 500:
            raise TaxiiServerError(f"TAXII server {self._cfg.name} error {response.status_code}: {response.text[:200]}")
        if response.status_code != 200:
            raise TaxiiServerError(f"TAXII server {self._cfg.name} answered HTTP {response.status_code}: {response.text[:200]}")


class TaxiiError(Exception):
    """Base class for recoverable TAXII fetch failures. The connector logs and skips the server;
    the rest of the Collector line-up (RSS, WebSearch) keeps running."""


class TaxiiAuthError(TaxiiError):
    """401. Operator must rotate the key or fix the env var."""


class TaxiiNotFound(TaxiiError):
    """404. Collection id / alias is wrong on this server, or the collection was removed."""


class TaxiiServerError(TaxiiError):
    """5xx / unexpected status / malformed envelope. The server is sick; retry later."""


class TaxiiConnector:
    """One TAXII server as a SourceConnector. Returns up to MAX_RESULTS_PER_SERVER candidate URLs
    matching the target. Failures (network, auth, bad collection) are caught and logged — the
    Collector keeps going with the other sources."""
    name = "taxii"

    def __init__(
        self,
        cfg: TaxiiServerConfig,
        client: httpx.Client,
        log: Callable[[str], None] = lambda message: None,
    ) -> None:
        self._cfg = cfg
        self._client = TaxiiClient(cfg, client)
        self._log = log

    def search(self, target: ResolvedTarget, limit: int | None = None) -> list[CandidateSource]:
        if not self._cfg.enabled:
            return []
        try:
            objects = self._client.list_objects(match_type="report")
        except TaxiiError as exc:
            self._log(f"TAXII server {self._cfg.name} skipped: {exc}")
            return []
        except httpx.HTTPError as exc:
            self._log(f"TAXII server {self._cfg.name} unreachable: {type(exc).__name__}")
            return []

        aliases = [target.name, *target.aliases]
        candidates: list[CandidateSource] = []
        for report in objects:
            if not isinstance(report, dict):
                continue
            if report.get("type") != "report":
                continue
            if not _report_matches(report, aliases):
                continue
            url = _extract_url(report)
            if not url:
                continue
            candidates.append(CandidateSource(
                url=url,
                title=report.get("name"),
                publisher=f"TAXII:{self._cfg.name}",
                published_at=_as_date(_extract_published(report)),
            ))
        return candidates
