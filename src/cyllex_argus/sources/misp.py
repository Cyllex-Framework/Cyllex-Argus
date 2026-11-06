"""MISP subscriber: pull Events from an external MISP instance and turn link-shaped
Attributes into candidate URLs for the Collector.

Each configured `[[misp]]` block becomes one `MispConnector` in the Collector line-up. The
connector POSTs to the server's `/events/restSearch` with `value=<alias>` for each of the
target's aliases, then walks the returned `Attribute[]` for every matching Event looking
for `link`/`url`/`uri` types — those are the real external write-ups a MISP curator attached
to the event. The attribute's value is emitted as a `CandidateSource` with the publisher set
to `MISP:<server-name>` so the admiralty table can score it the same way as RSS and TAXII.

What this is NOT:
- Not an IOC importer. `Attribute[]` is overwhelmingly IOCs (ips, domains, hashes), which do
  not fit the "candidate document" shape this connector returns. Only link-shaped attributes
  (`link`, `url`, `uri`) become candidates; everything else is dropped. IOC enrichment lives
  in a future enrichment pass.
- Not an EventReport fetcher. MISP's `EventReport` is markdown content stored *inside* MISP,
  not an external URL. The connector could pull it, but Argus's Fetcher is HTTP-shaped and
  the Analyst is tuned for article prose; EventReport ingestion is a separate feature.

Auth (precedence per server, matches the admin-password + TAXII + API-key patterns):
1. env var named by `env_api_key` on the toml → `Authorization: <key>` header
2. `api_key` field on the toml → `Authorization: <key>` header (plaintext on disk)
3. nothing → unauthenticated request (public MISP instances allow this on specific feeds)

MISP uses a plain header (`Authorization: <key>`), NOT `Bearer <key>`. Several MISP
deployments ignore `Bearer` prefixes and 401 the request; keep this header shape verbatim.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Callable
from datetime import UTC, date, datetime
from typing import Any

import httpx

from cyllex_argus.config.settings import MispServerConfig
from cyllex_argus.knowledge.names import count_mentions
from cyllex_argus.sources.base import CandidateSource, ResolvedTarget

_log = logging.getLogger(__name__)

MISP_CONTENT_TYPE = "application/json"
MAX_EVENTS_PER_SERVER = 50       # safety cap: a chatty MISP must not drown the Collector queue
MAX_LINKS_PER_EVENT = 5          # one event with 500 link attributes would otherwise flood too
LINK_TYPES = frozenset({"link", "url", "uri"})


def _resolve_auth(cfg: MispServerConfig) -> dict[str, str]:
    """Return the HTTP headers to authenticate with this server, or {} for an anonymous request.

    MISP's own convention is a plain `Authorization: <key>` header (no Bearer prefix). The
    server's PHP auth middleware looks for the raw key; a `Bearer <key>` string lands as the
    full header value and the key does not match. Keep this header shape verbatim."""
    if cfg.env_api_key:
        token = os.environ.get(cfg.env_api_key, "").strip()
        if token:
            return {"Authorization": token}
    if cfg.api_key.strip():
        return {"Authorization": cfg.api_key.strip()}
    return {}


def _timestamp_window(days: int | None) -> str | None:
    """MISP's `timestamp` filter accepts a duration string (`180d`, `24h`, `3600`), a Unix epoch,
    or an ISO-8601. The duration form is the operator-friendly one and matches TAXII semantics."""
    if days is None or days <= 0:
        return None
    return f"{days}d"


def _as_date(value: Any) -> date | None:
    """MISP's `Event.date` is a date-only string (`YYYY-MM-DD`); `Event.publish_timestamp` is a
    Unix epoch. Try the date field first (what MISP shows in its UI), then the timestamp."""
    if isinstance(value, str) and value:
        try:
            return datetime.fromisoformat(value).date()
        except (ValueError, TypeError):
            pass
    if isinstance(value, (int, str)) and str(value).isdigit():
        try:
            return datetime.fromtimestamp(int(value), tz=UTC).date()
        except (ValueError, OSError, OverflowError):
            pass
    return None


def _extract_event_date(event: dict) -> date | None:
    """Preferred ordering: Event.date → Event.publish_timestamp → Event.timestamp."""
    for key in ("date", "publish_timestamp", "timestamp"):
        resolved = _as_date(event.get(key))
        if resolved is not None:
            return resolved
    return None


def _event_matches(event: dict, aliases: list[str]) -> bool:
    """Count the target's aliases in the event's info + tag names. One mention is enough; the
    full-pipeline Triage step is strict later. This filter is server-side (via `value`) but
    the client-side guard catches events MISP returned on tag/attribute matches that do not
    actually mention the alias in their title."""
    pieces = [event.get("info") or ""]
    for tag in event.get("Tag") or []:
        if isinstance(tag, dict):
            tag_name = tag.get("name")
            if isinstance(tag_name, str):
                pieces.append(tag_name)
    haystack = " ".join(pieces)
    return count_mentions(haystack, aliases) > 0


def _extract_links(event: dict) -> list[str]:
    """Return every link-shaped Attribute's value. MISP marks these with
    `type in {link, url, uri}`; the attribute's `value` is the URL string."""
    links: list[str] = []
    for attr in event.get("Attribute") or []:
        if not isinstance(attr, dict):
            continue
        if attr.get("type") not in LINK_TYPES:
            continue
        value = attr.get("value")
        if not isinstance(value, str):
            continue
        value = value.strip()
        if value.startswith(("http://", "https://")) and value not in links:
            links.append(value)
            if len(links) >= MAX_LINKS_PER_EVENT:
                break
    return links


class MispError(Exception):
    """Base class for recoverable MISP fetch failures. The connector logs and skips the server;
    the rest of the Collector line-up (RSS, TAXII, WebSearch) keeps running."""


class MispAuthError(MispError):
    """401. The operator must rotate the key or fix the env var."""


class MispNotFound(MispError):
    """404. `/events/restSearch` is wrong (older MISP) or the base URL is off."""


class MispServerError(MispError):
    """5xx / unexpected status / malformed envelope. The server is sick; retry later."""


class MispClient:
    """Minimal MISP REST client. Only the one endpoint the connector needs: `restSearch` for
    events, with a value filter + a `timestamp` window. No discovery, no event upload, no
    attribute add — we are a subscriber."""

    def __init__(self, cfg: MispServerConfig, client: httpx.Client) -> None:
        self._cfg = cfg
        self._client = client
        self._base_url = cfg.url.rstrip("/")

    def search_events(self, value: str, limit: int = MAX_EVENTS_PER_SERVER) -> list[dict]:
        """POST /events/restSearch with a text filter. Returns the raw `response[]` list."""
        url = f"{self._base_url}/events/restSearch"
        body: dict[str, Any] = {
            "returnFormat": "json",
            "value": value,
            "limit": limit,
            "metadata": False,  # we need Attribute[] for the link extraction
        }
        window = _timestamp_window(self._cfg.timestamp_days)
        if window is not None:
            body["timestamp"] = window
        headers = {
            "Accept": MISP_CONTENT_TYPE,
            "Content-Type": MISP_CONTENT_TYPE,
            **_resolve_auth(self._cfg),
        }
        response = self._client.post(url, json=body, headers=headers)
        if response.status_code == 401:
            raise MispAuthError(f"MISP server {self._cfg.name} rejected the credentials (401).")
        if response.status_code == 404:
            raise MispNotFound(f"MISP server {self._cfg.name}: /events/restSearch not found (check base URL).")
        if response.status_code >= 500:
            raise MispServerError(f"MISP server {self._cfg.name} error {response.status_code}: {response.text[:200]}")
        if response.status_code != 200:
            raise MispServerError(
                f"MISP server {self._cfg.name} answered HTTP {response.status_code}: {response.text[:200]}"
            )
        try:
            envelope = response.json()
        except ValueError as exc:
            raise MispServerError(
                f"MISP server {self._cfg.name} returned non-JSON: {response.text[:200]}"
            ) from exc
        # MISP wraps responses in different shapes depending on version:
        # - 2.4.x: {"response": [{"Event": {...}}, ...]}
        # - 2.5.x: {"response": {"Event": [{...}, ...]}}  (rare but seen on self-hosted)
        # - a bare list of events on some reverse-proxied setups
        return _unwrap_events(envelope, self._cfg.name)


def _unwrap_events(envelope: Any, name: str) -> list[dict]:
    if isinstance(envelope, list):
        # Bare list — either [{"Event": {...}}, ...] (reverse-proxied 2.4) or
        # [{...event...}, ...] (stripped wrapper). Try the wrapper first, fall through.
        events: list[dict] = []
        for item in envelope:
            if not isinstance(item, dict):
                continue
            inner = item.get("Event") if "Event" in item else item
            if isinstance(inner, dict):
                events.append(inner)
        return events
    if not isinstance(envelope, dict):
        raise MispServerError(f"MISP server {name}: top-level JSON is not an object or list.")
    response = envelope.get("response", envelope)
    if isinstance(response, list):
        # [{"Event": {...}}, ...] shape
        events = []
        for item in response:
            if isinstance(item, dict):
                event = item.get("Event", item)
                if isinstance(event, dict):
                    events.append(event)
        return events
    if isinstance(response, dict):
        inner = response.get("Event", [])
        if isinstance(inner, list):
            return [item for item in inner if isinstance(item, dict)]
        if isinstance(inner, dict):
            return [inner]
    raise MispServerError(f"MISP server {name}: envelope shape not understood.")


class MispConnector:
    """One MISP server as a SourceConnector. Returns up to MAX_EVENTS_PER_SERVER events' worth
    of link-shaped attributes matching the target. Failures (network, auth, bad base URL) are
    caught and logged — the Collector keeps going with the other sources."""
    name = "misp"

    def __init__(
        self,
        cfg: MispServerConfig,
        client: httpx.Client,
        log: Callable[[str], None] = lambda message: None,
    ) -> None:
        self._cfg = cfg
        self._client = MispClient(cfg, client)
        self._log = log

    def search(self, target: ResolvedTarget, limit: int | None = None) -> list[CandidateSource]:
        if not self._cfg.enabled:
            return []
        # One search per alias keeps the server-side filter precise (MISP's `value` is a
        # single string, not an array). The alias list is already de-duplicated upstream.
        seen_urls: set[str] = set()
        candidates: list[CandidateSource] = []
        aliases = [target.name, *target.aliases]
        for alias in aliases:
            if len(candidates) >= MAX_EVENTS_PER_SERVER:
                break
            try:
                events = self._client.search_events(alias)
            except MispError as exc:
                self._log(f"MISP server {self._cfg.name} skipped (alias {alias!r}): {exc}")
                return []  # a single alias failing is a server-wide problem; stop here
            except httpx.HTTPError as exc:
                self._log(f"MISP server {self._cfg.name} unreachable: {type(exc).__name__}")
                return []
            for event in events:
                if len(candidates) >= MAX_EVENTS_PER_SERVER:
                    break
                if not _event_matches(event, aliases):
                    continue
                event_title = event.get("info") or ""
                event_date = _extract_event_date(event)
                for link in _extract_links(event):
                    if len(candidates) >= MAX_EVENTS_PER_SERVER:
                        break
                    if link in seen_urls:
                        continue
                    seen_urls.add(link)
                    candidates.append(CandidateSource(
                        url=link,
                        title=event_title or None,
                        publisher=f"MISP:{self._cfg.name}",
                        published_at=event_date,
                    ))
        return candidates
