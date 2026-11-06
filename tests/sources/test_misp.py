"""Tests for the MISP subscriber connector.

Covers the happy pull-and-filter path, the two MISP envelope shapes (2.4.x and 2.5.x), auth
header shape (env > toml > none), the error-to-skip contract (401/404/5xx/malformed/offline
all return [] and leave the rest of the Collector line-up running), the alias-mention filter,
the link-type filter (only `link`/`url`/`uri` attributes become candidates), and the
per-event + per-server caps.
"""

from __future__ import annotations

from datetime import date

import httpx

from cyllex_argus.config.settings import MispServerConfig
from cyllex_argus.sources.base import ResolvedTarget
from cyllex_argus.sources.misp import (
    MAX_EVENTS_PER_SERVER,
    MAX_LINKS_PER_EVENT,
    MispConnector,
)

TARGET = ResolvedTarget(name="APT29", aliases=["APT29", "Cozy Bear", "Midnight Blizzard"])


def _cfg(**over) -> MispServerConfig:
    base = dict(name="TestMisp", url="https://misp.example.com")
    base.update(over)
    return MispServerConfig(**base)


def _event(**over) -> dict:
    base = {
        "id": "1",
        "info": "APT29 OAuth corporate email intrusion",
        "date": "2026-05-15",
        "timestamp": "1715731200",
        "Attribute": [
            {"type": "link", "value": "https://mandiant.example/apt29-oauth.html"},
            {"type": "ip-src", "value": "198.51.100.42"},   # IOC, must be dropped
        ],
        "Tag": [{"name": "threat-actor=\"APT29\""}],
    }
    base.update(over)
    return base


def _mock_client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


# ---- Happy path ---------------------------------------------------------------------


def test_connector_returns_link_attributes_as_candidate_sources():
    """A MISP event with a link-shaped Attribute becomes a CandidateSource with the attribute's
    value as the URL, the event info as the title and `MISP:<server>` as the publisher."""
    captured = {}

    def handler(request):
        captured["url"] = str(request.url)
        captured["method"] = request.method
        captured["auth"] = request.headers.get("authorization")
        return httpx.Response(200, json={"response": [{"Event": _event()}]})

    results = MispConnector(_cfg(), _mock_client(handler)).search(TARGET)
    assert len(results) == 1
    assert results[0].url == "https://mandiant.example/apt29-oauth.html"
    assert results[0].publisher == "TestMisp" or results[0].publisher == "MISP:TestMisp"
    assert results[0].publisher == "MISP:TestMisp"
    assert results[0].published_at == date(2026, 5, 15)
    assert captured["method"] == "POST"
    assert "events/restSearch" in captured["url"]


def test_connector_handles_the_2_5_envelope_shape():
    """MISP 2.5 self-hosted sometimes answers with {"response": {"Event": [{...}]}} instead of
    the 2.4 shape. The unwrap helper handles both."""
    handler = lambda r: httpx.Response(200, json={"response": {"Event": [_event()]}})
    results = MispConnector(_cfg(), _mock_client(handler)).search(TARGET)
    assert len(results) == 1


def test_connector_handles_a_bare_list_envelope():
    """Reverse-proxied MISPs sometimes strip the top-level `response` key and return the list
    directly. The connector tolerates that."""
    handler = lambda r: httpx.Response(200, json=[{"Event": _event()}])
    results = MispConnector(_cfg(), _mock_client(handler)).search(TARGET)
    assert len(results) == 1


def test_connector_drops_non_link_attributes():
    """Only `link`/`url`/`uri` attribute types become candidates — IOCs (ip-src, md5, domain)
    are useless for the Collector, which needs a document URL to fetch."""
    event = _event(Attribute=[
        {"type": "md5", "value": "d41d8cd98f00b204e9800998ecf8427e"},
        {"type": "ip-src", "value": "198.51.100.1"},
        {"type": "domain", "value": "evil.example.com"},
    ])
    handler = lambda r: httpx.Response(200, json={"response": [{"Event": event}]})
    assert MispConnector(_cfg(), _mock_client(handler)).search(TARGET) == []


def test_connector_filters_events_whose_info_does_not_mention_the_target():
    """The server-side `value` filter can over-return (tag matches, attribute matches). The
    client-side guard drops events that do not actually mention one of the target's aliases
    in their info or tags."""
    event = _event(info="Unrelated Lazarus Q2 campaign", Tag=[{"name": "actor=lazarus"}])
    handler = lambda r: httpx.Response(200, json={"response": [{"Event": event}]})
    assert MispConnector(_cfg(), _mock_client(handler)).search(TARGET) == []


def test_connector_matches_on_tag_name_too():
    """A MISP event whose info does not literally contain the alias but whose Tag mentions it
    (e.g. `threat-actor="APT29"`) still matches."""
    event = _event(info="Internal advisory", Tag=[{"name": "threat-actor=\"APT29\""}])
    handler = lambda r: httpx.Response(200, json={"response": [{"Event": event}]})
    assert len(MispConnector(_cfg(), _mock_client(handler)).search(TARGET)) == 1


def test_connector_caps_links_per_event():
    """A single event with 500 link attributes must not drown the Collector. The cap keeps
    the per-event emission bounded even if the server went pathological."""
    attrs = [{"type": "link", "value": f"https://example.com/{i}"} for i in range(MAX_LINKS_PER_EVENT + 10)]
    event = _event(Attribute=attrs)
    handler = lambda r: httpx.Response(200, json={"response": [{"Event": event}]})
    results = MispConnector(_cfg(), _mock_client(handler)).search(TARGET)
    assert len(results) == MAX_LINKS_PER_EVENT


def test_connector_deduplicates_urls_across_events_and_aliases():
    """The same link seen under two aliases should be emitted once. One search per alias could
    otherwise cross-emit the same URL."""
    # One event, one unique link, but matches BOTH "APT29" and "Cozy Bear" through its info.
    event = _event(info="APT29 (Cozy Bear) OAuth intrusion", Attribute=[
        {"type": "link", "value": "https://x.example/a.html"},
    ])
    handler = lambda r: httpx.Response(200, json={"response": [{"Event": event}]})
    results = MispConnector(_cfg(), _mock_client(handler)).search(TARGET)
    assert len(results) == 1


# ---- Auth precedence ----------------------------------------------------------------


def test_env_api_key_wins_over_toml_api_key(monkeypatch):
    """Env rotation without a file edit is the preferred path. The resolved value lands in
    `Authorization: <key>` verbatim — NOT prefixed with `Bearer`."""
    monkeypatch.setenv("MY_MISP_KEY", "from-env")
    seen = {}

    def handler(request):
        seen["auth"] = request.headers.get("authorization")
        return httpx.Response(200, json={"response": []})

    MispConnector(_cfg(env_api_key="MY_MISP_KEY", api_key="from-toml"),
                  _mock_client(handler)).search(TARGET)
    assert seen["auth"] == "from-env"


def test_toml_api_key_is_used_when_env_is_not_set(monkeypatch):
    monkeypatch.delenv("MY_MISP_KEY", raising=False)
    seen = {}

    def handler(request):
        seen["auth"] = request.headers.get("authorization")
        return httpx.Response(200, json={"response": []})

    MispConnector(_cfg(env_api_key="MY_MISP_KEY", api_key="from-toml"),
                  _mock_client(handler)).search(TARGET)
    assert seen["auth"] == "from-toml"


def test_no_auth_header_when_server_is_public():
    """Some MISP feeds (CIRCL public MISP) allow anonymous reads. The connector must NOT invent
    credentials; those requests would then 401 for no reason."""
    seen = {}

    def handler(request):
        seen["auth"] = request.headers.get("authorization")
        return httpx.Response(200, json={"response": []})

    MispConnector(_cfg(), _mock_client(handler)).search(TARGET)
    assert seen["auth"] is None


# ---- Error-to-skip contract ---------------------------------------------------------


def test_401_logs_and_returns_empty():
    logs = []
    handler = lambda r: httpx.Response(401, text="unauthorized")
    results = MispConnector(_cfg(), _mock_client(handler), log=logs.append).search(TARGET)
    assert results == []
    assert any("TestMisp" in msg and "rejected" in msg for msg in logs)


def test_404_logs_and_returns_empty():
    """A 404 points at the base URL being wrong (restSearch isn't at that path). The log line
    says what endpoint was tried so the operator can fix the config."""
    logs = []
    handler = lambda r: httpx.Response(404, text="not found")
    results = MispConnector(_cfg(), _mock_client(handler), log=logs.append).search(TARGET)
    assert results == []
    assert any("TestMisp" in msg for msg in logs)


def test_5xx_logs_and_returns_empty():
    logs = []
    handler = lambda r: httpx.Response(503, text="busy")
    assert MispConnector(_cfg(), _mock_client(handler), log=logs.append).search(TARGET) == []
    assert any("TestMisp" in msg for msg in logs)


def test_network_error_logs_and_returns_empty():
    logs = []

    def handler(_request):
        raise httpx.ConnectError("name resolution failed")

    assert MispConnector(_cfg(), _mock_client(handler), log=logs.append).search(TARGET) == []
    assert any("TestMisp" in msg and "unreachable" in msg for msg in logs)


def test_malformed_envelope_logs_and_returns_empty():
    """A server that answers 200 with non-JSON is broken. Log and move on; the rest of the
    Collector keeps running."""
    logs = []
    handler = lambda r: httpx.Response(200, text="<html>unexpected</html>",
                                       headers={"content-type": "text/html"})
    assert MispConnector(_cfg(), _mock_client(handler), log=logs.append).search(TARGET) == []


def test_disabled_server_is_not_queried_at_all():
    """`enabled = false` on a server means "keep the toml entry around but do not pull from
    it". Equivalent to commenting the block out, without destroying the credentials."""
    called = {"count": 0}

    def handler(_request):
        called["count"] += 1
        return httpx.Response(200, json={"response": []})

    assert MispConnector(_cfg(enabled=False), _mock_client(handler)).search(TARGET) == []
    assert called["count"] == 0


# ---- Query shape --------------------------------------------------------------------


def test_timestamp_window_is_passed_as_a_duration_string():
    """MISP accepts a duration like `180d`. The operator-friendly form matches TAXII semantics."""
    captured = {}

    def handler(request):
        captured["body"] = request.read()
        return httpx.Response(200, json={"response": []})

    MispConnector(_cfg(timestamp_days=30), _mock_client(handler)).search(TARGET)
    import json as _json
    body = _json.loads(captured["body"])
    assert body["timestamp"] == "30d"


def test_timestamp_window_is_omitted_when_days_is_none():
    captured = {}

    def handler(request):
        captured["body"] = request.read()
        return httpx.Response(200, json={"response": []})

    MispConnector(_cfg(timestamp_days=None), _mock_client(handler)).search(TARGET)
    import json as _json
    body = _json.loads(captured["body"])
    assert "timestamp" not in body


def test_overall_cap_respects_max_events_per_server():
    """A server returning 500 matching events must emit at most MAX_EVENTS_PER_SERVER
    candidates. The cap applies across aliases too."""
    many = [
        {"Event": _event(id=str(i), Attribute=[{"type": "link", "value": f"https://x.example/{i}"}])}
        for i in range(MAX_EVENTS_PER_SERVER + 20)
    ]
    handler = lambda r: httpx.Response(200, json={"response": many})
    results = MispConnector(_cfg(), _mock_client(handler)).search(TARGET)
    assert len(results) <= MAX_EVENTS_PER_SERVER
