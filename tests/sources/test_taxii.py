"""Tests for the TAXII 2.1 subscriber connector.

Covers the happy pull-and-filter path, auth header shapes (env > toml > basic > none), the
error-to-skip contract (401/404/5xx/malformed/offline all return [] and leave the rest of the
Collector line-up running), the alias-mention filter, and the `added_after` cutoff.
"""

from __future__ import annotations

import base64
from datetime import UTC, date, datetime
from urllib.parse import parse_qs, urlparse

import httpx

from cyllex_argus.config.settings import TaxiiServerConfig
from cyllex_argus.sources.base import ResolvedTarget
from cyllex_argus.sources.taxii import (
    MAX_RESULTS_PER_SERVER,
    TAXII_CONTENT_TYPE,
    TaxiiConnector,
)

TARGET = ResolvedTarget(name="APT29", aliases=["APT29", "Cozy Bear", "Midnight Blizzard", "Nobelium"])


def _cfg(**over) -> TaxiiServerConfig:
    base = dict(
        name="TestServer",
        url="https://taxii.example.com/taxii2/api1",
        collection="collection-1",
    )
    base.update(over)
    return TaxiiServerConfig(**base)


def _report(**over) -> dict:
    base = {
        "type": "report",
        "id": "report--0",
        "name": "APT29 campaign write-up",
        "description": "Cozy Bear activity against Microsoft...",
        "published": "2026-05-15T12:00:00.000Z",
        "created": "2026-05-15T12:00:00.000Z",
        "external_references": [{"source_name": "Mandiant", "url": "https://mandiant.example/apt29.html"}],
    }
    base.update(over)
    return base


def _envelope(objects: list[dict]) -> dict:
    return {"objects": objects, "more": False}


def _mock_client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


# ---- Happy path ---------------------------------------------------------------------


def test_connector_returns_candidate_sources_for_matching_reports():
    """A STIX report whose name contains an alias is returned as a CandidateSource with the
    external_references URL, the server-prefixed publisher and the published date parsed."""
    captured: dict = {}

    def handler(request):
        captured["url"] = str(request.url)
        captured["accept"] = request.headers["accept"]
        reports = [
            _report(id="report--matching", name="APT29 campaign against Microsoft"),
            _report(id="report--off-topic", name="Lazarus Group Q2 activity", description="DPRK operations."),
        ]
        return httpx.Response(200, json=_envelope(reports))

    connector = TaxiiConnector(_cfg(), _mock_client(handler))
    results = connector.search(TARGET)
    assert len(results) == 1
    assert results[0].url == "https://mandiant.example/apt29.html"
    assert results[0].publisher == "TAXII:TestServer"
    assert results[0].published_at == date(2026, 5, 15)
    assert "collections/collection-1/objects" in captured["url"]
    assert captured["accept"] == TAXII_CONTENT_TYPE


def test_connector_filters_reports_whose_name_and_description_do_not_mention_the_target():
    """The alias filter sits on the connector side because many TAXII servers do not accept a
    text filter in the query; without this, every report in the collection becomes a candidate."""
    handler = lambda r: httpx.Response(200, json=_envelope([
        _report(id="report--1", name="Unrelated Vendor Blog", description="GRU operations."),
    ]))
    assert TaxiiConnector(_cfg(), _mock_client(handler)).search(TARGET) == []


def test_connector_skips_reports_without_a_usable_external_url():
    """A report that mentions the target but has no external_references.url is useless — the
    Collector downstream needs a URL to fetch. Dropping it silently is correct; the Analyst
    would just reject an empty document later."""
    handler = lambda r: httpx.Response(200, json=_envelope([
        _report(id="report--no-url", external_references=[{"source_name": "Mandiant"}]),  # no url
    ]))
    assert TaxiiConnector(_cfg(), _mock_client(handler)).search(TARGET) == []


def test_connector_ignores_non_report_objects_even_if_the_server_returned_them():
    """`match[type]=report` is a hint, not a guarantee; a strict parser on our side keeps
    indicator/attack-pattern/etc. out of the Collector queue."""
    handler = lambda r: httpx.Response(200, json=_envelope([
        {"type": "indicator", "id": "indicator--1", "name": "APT29 C2 domain"},
        {"type": "attack-pattern", "id": "attack-pattern--1", "name": "APT29 abuses OAuth"},
        _report(id="report--matching"),
    ]))
    results = TaxiiConnector(_cfg(), _mock_client(handler)).search(TARGET)
    assert len(results) == 1
    assert results[0].url == "https://mandiant.example/apt29.html"


# ---- Auth precedence (matches the admin + API-key patterns elsewhere) ---------------


def test_env_api_key_wins_over_toml_api_key(monkeypatch):
    """Env rotation without a file edit is the preferred path. If `env_api_key` names a non-
    empty env var, that value lands in `Authorization: Bearer`; the toml `api_key` is ignored."""
    monkeypatch.setenv("MY_TAXII_TOKEN", "from-env")
    seen = {}

    def handler(request):
        seen["auth"] = request.headers.get("authorization")
        return httpx.Response(200, json=_envelope([]))

    TaxiiConnector(_cfg(env_api_key="MY_TAXII_TOKEN", api_key="from-toml"), _mock_client(handler)).search(TARGET)
    assert seen["auth"] == "Bearer from-env"


def test_toml_api_key_is_used_when_env_is_not_set(monkeypatch):
    monkeypatch.delenv("MY_TAXII_TOKEN", raising=False)
    seen = {}

    def handler(request):
        seen["auth"] = request.headers.get("authorization")
        return httpx.Response(200, json=_envelope([]))

    TaxiiConnector(_cfg(env_api_key="MY_TAXII_TOKEN", api_key="from-toml"), _mock_client(handler)).search(TARGET)
    assert seen["auth"] == "Bearer from-toml"


def test_basic_auth_is_used_when_no_bearer_is_configured():
    seen = {}

    def handler(request):
        seen["auth"] = request.headers.get("authorization")
        return httpx.Response(200, json=_envelope([]))

    TaxiiConnector(_cfg(username="analyst", password="hunter2"), _mock_client(handler)).search(TARGET)
    expected = "Basic " + base64.b64encode(b"analyst:hunter2").decode("ascii")
    assert seen["auth"] == expected


def test_no_auth_header_when_server_is_public():
    """abuse.ch URLhaus TAXII and other public servers accept anonymous reads. The connector
    must NOT invent credentials; those requests would then 401 for no reason."""
    seen = {}

    def handler(request):
        seen["auth"] = request.headers.get("authorization")
        return httpx.Response(200, json=_envelope([]))

    TaxiiConnector(_cfg(), _mock_client(handler)).search(TARGET)
    assert seen["auth"] is None


# ---- Error-to-skip contract ---------------------------------------------------------


def test_401_logs_and_returns_empty_without_raising():
    """A single bad server must not abort the whole Collector pass. The log line names the
    server so the operator sees which one needs the credentials rotated."""
    logs = []
    handler = lambda r: httpx.Response(401, text="Unauthorized")
    results = TaxiiConnector(_cfg(), _mock_client(handler), log=logs.append).search(TARGET)
    assert results == []
    assert any("TestServer" in msg and "rejected" in msg for msg in logs)


def test_404_logs_the_collection_name_and_returns_empty():
    """A typo in the collection id is the usual 404 cause. Naming the collection in the log
    saves the operator a round-trip through the server's discovery endpoint to figure out
    which collection ids actually exist."""
    logs = []
    handler = lambda r: httpx.Response(404, text="Not Found")
    results = TaxiiConnector(_cfg(collection="typo-collection"),
                             _mock_client(handler), log=logs.append).search(TARGET)
    assert results == []
    assert any("typo-collection" in msg for msg in logs)


def test_5xx_logs_and_returns_empty():
    logs = []
    handler = lambda r: httpx.Response(503, text="busy")
    assert TaxiiConnector(_cfg(), _mock_client(handler), log=logs.append).search(TARGET) == []
    assert any("TestServer" in msg and ("503" in msg or "error" in msg.lower()) for msg in logs)


def test_network_error_logs_and_returns_empty():
    """A DNS failure / connect refused is a per-run condition, not a config bug. Keep the
    rest of the Collector running and let the next scheduled investigation try again."""
    logs = []

    def handler(_request):
        raise httpx.ConnectError("name resolution failed")

    assert TaxiiConnector(_cfg(), _mock_client(handler), log=logs.append).search(TARGET) == []
    assert any("TestServer" in msg and "unreachable" in msg for msg in logs)


def test_malformed_envelope_logs_and_returns_empty():
    """A server that answers 200 with non-JSON is broken, not malicious. The connector surfaces
    the server name in the log so the operator can call them, and moves on."""
    logs = []
    handler = lambda r: httpx.Response(200, text="<html>unexpected</html>",
                                       headers={"content-type": "text/html"})
    assert TaxiiConnector(_cfg(), _mock_client(handler), log=logs.append).search(TARGET) == []


def test_disabled_server_is_not_queried_at_all():
    """`enabled = false` on a server means "keep the toml entry around but do not pull from it".
    Equivalent to commenting the block out, without destroying the credentials."""
    called = {"count": 0}

    def handler(_request):
        called["count"] += 1
        return httpx.Response(200, json=_envelope([]))

    assert TaxiiConnector(_cfg(enabled=False), _mock_client(handler)).search(TARGET) == []
    assert called["count"] == 0


# ---- Query shape ---------------------------------------------------------------------


def test_added_after_is_passed_as_an_iso_cutoff():
    """The server-side filter saves bandwidth on a long-running server. 180 days is the default;
    older reports stay in the collection but are not pulled."""
    captured = {}

    def handler(request):
        captured["qs"] = parse_qs(urlparse(str(request.url)).query)
        return httpx.Response(200, json=_envelope([]))

    TaxiiConnector(_cfg(added_after_days=30), _mock_client(handler)).search(TARGET)
    added = captured["qs"]["added_after"][0]
    # Parses as RFC 3339; comes out at most 30 days before "now".
    parsed = datetime.fromisoformat(added.replace("Z", "+00:00"))
    assert (datetime.now(UTC) - parsed).days in (29, 30, 31)


def test_added_after_is_omitted_when_days_is_none():
    """Some servers do not accept the filter — None lets the operator opt out without an extra
    config shape."""
    captured = {}

    def handler(request):
        captured["qs"] = parse_qs(urlparse(str(request.url)).query)
        return httpx.Response(200, json=_envelope([]))

    TaxiiConnector(_cfg(added_after_days=None), _mock_client(handler)).search(TARGET)
    assert "added_after" not in captured["qs"]


def test_limit_matches_the_safety_cap():
    captured = {}

    def handler(request):
        captured["qs"] = parse_qs(urlparse(str(request.url)).query)
        return httpx.Response(200, json=_envelope([]))

    TaxiiConnector(_cfg(), _mock_client(handler)).search(TARGET)
    assert captured["qs"]["limit"][0] == str(MAX_RESULTS_PER_SERVER)


# ---- Wildcard collection ("*") -------------------------------------------------------


def test_wildcard_collection_queries_every_readable_collection():
    """collection = "*" discovers the server's collections and pulls reports from each one the
    caller can read, merging the results. Non-readable collections are skipped, not queried."""
    def handler(request):
        path = urlparse(str(request.url)).path
        if path.endswith("/collections/"):
            return httpx.Response(200, json={"collections": [
                {"id": "col-a", "can_read": True, "title": "A"},
                {"id": "col-b", "can_read": True, "title": "B"},
                {"id": "col-secret", "can_read": False, "title": "Secret"},
            ]})
        if "/collections/col-a/objects" in path:
            return httpx.Response(200, json=_envelope([_report(
                id="report--a", name="APT29 in A",
                external_references=[{"source_name": "V", "url": "https://a.example/x"}])]))
        if "/collections/col-b/objects" in path:
            return httpx.Response(200, json=_envelope([_report(
                id="report--b", name="Cozy Bear in B",
                external_references=[{"source_name": "V", "url": "https://b.example/y"}])]))
        if "/collections/col-secret/objects" in path:
            raise AssertionError("must not query a non-readable collection")
        return httpx.Response(404, text="unexpected path")

    results = TaxiiConnector(_cfg(collection="*"), _mock_client(handler)).search(TARGET)
    assert sorted(r.url for r in results) == ["https://a.example/x", "https://b.example/y"]


def test_wildcard_collection_listing_401_is_skipped():
    """If the `/collections/` discovery call is rejected, the whole server is skipped (logged),
    not crashed — same error-to-skip contract as a bad object fetch."""
    logs = []
    handler = lambda r: httpx.Response(401, text="no")
    assert TaxiiConnector(_cfg(collection="*"), _mock_client(handler), log=logs.append).search(TARGET) == []
    assert any("rejected" in m for m in logs)
