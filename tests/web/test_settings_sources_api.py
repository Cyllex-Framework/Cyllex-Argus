"""HTTP CRUD for the three list-shaped config sections: MISP, TAXII, webhooks.

Covers the round-trip (PUT ↔ GET), the mask-preserve-stored-value contract (echo "••••••••"
on PUT ⇒ keep the stored secret), the empty-string-clears contract, the test endpoints
(signed webhook probe + MISP / TAXII HTTP probes), and the validation surface (duplicate
names, unknown on_states).
"""

from __future__ import annotations

import tomllib

import httpx

from tests.web.conftest import make_client as _make_client


def make_client(world, **kwargs):
    client = _make_client(world, **kwargs)
    client.headers["X-Argus-CSRF"] = "1"
    return client


# ---- MISP ----


def test_misp_list_is_empty_on_a_fresh_install(world):
    client = make_client(world)
    response = client.get("/api/settings/misp")
    assert response.status_code == 200
    assert response.json() == {"servers": []}


def test_misp_put_persists_and_round_trips_masked(world):
    client = make_client(world)
    response = client.put("/api/settings/misp", json={"servers": [
        {"name": "CIRCL", "url": "https://misppriv.circl.lu", "api_key": "s3cret",
         "env_api_key": "", "timestamp_days": 180, "enabled": True},
    ]})
    assert response.status_code == 200
    [server] = response.json()["servers"]
    assert server["api_key"] == "••••••••"
    # Config file has the plaintext.
    config = tomllib.loads(world.paths.config_file.read_text(encoding="utf-8"))
    assert config["misp"][0]["api_key"] == "s3cret"
    # Round-trip: GET returns the masked value.
    assert client.get("/api/settings/misp").json()["servers"][0]["api_key"] == "••••••••"


def test_misp_mask_preserves_stored_key_on_subsequent_put(world):
    client = make_client(world)
    client.put("/api/settings/misp", json={"servers": [
        {"name": "CIRCL", "url": "https://misppriv.circl.lu", "api_key": "s3cret"},
    ]})
    # Flip enabled while echoing the mask back — must NOT clear the stored key.
    client.put("/api/settings/misp", json={"servers": [
        {"name": "CIRCL", "url": "https://misppriv.circl.lu", "api_key": "••••••••", "enabled": False},
    ]})
    config = tomllib.loads(world.paths.config_file.read_text(encoding="utf-8"))
    assert config["misp"][0]["api_key"] == "s3cret"
    assert config["misp"][0]["enabled"] is False


def test_misp_empty_string_clears_the_stored_key(world):
    client = make_client(world)
    client.put("/api/settings/misp", json={"servers": [
        {"name": "CIRCL", "url": "https://misppriv.circl.lu", "api_key": "s3cret"},
    ]})
    client.put("/api/settings/misp", json={"servers": [
        {"name": "CIRCL", "url": "https://misppriv.circl.lu", "api_key": ""},
    ]})
    config = tomllib.loads(world.paths.config_file.read_text(encoding="utf-8"))
    assert config["misp"][0]["api_key"] == ""


def test_misp_rejects_duplicate_names(world):
    client = make_client(world)
    response = client.put("/api/settings/misp", json={"servers": [
        {"name": "same", "url": "https://a.example"},
        {"name": "same", "url": "https://b.example"},
    ]})
    assert response.status_code == 400
    assert "duplicate" in response.json()["error"].lower()


def test_misp_rejects_empty_name_or_url(world):
    client = make_client(world)
    response = client.put("/api/settings/misp", json={"servers": [{"name": "", "url": "https://x"}]})
    assert response.status_code == 400
    response = client.put("/api/settings/misp", json={"servers": [{"name": "x", "url": ""}]})
    assert response.status_code == 400


# ---- TAXII ----


def test_taxii_list_is_empty_on_a_fresh_install(world):
    client = make_client(world)
    assert client.get("/api/settings/taxii").json() == {"servers": []}


def test_taxii_put_masks_both_api_key_and_password(world):
    client = make_client(world)
    response = client.put("/api/settings/taxii", json={"servers": [
        {"name": "Vendor", "url": "https://taxii.example/taxii2/api1",
         "collection": "apt-reports", "api_key": "s3cret",
         "username": "argus-reader", "password": "p4ssword",
         "added_after_days": 180, "enabled": True},
    ]})
    assert response.status_code == 200
    [server] = response.json()["servers"]
    assert server["api_key"] == "••••••••"
    assert server["password"] == "••••••••"
    assert server["username"] == "argus-reader"   # not a secret, round-trips plaintext


def test_taxii_mask_preserves_both_api_key_and_password(world):
    client = make_client(world)
    client.put("/api/settings/taxii", json={"servers": [
        {"name": "Vendor", "url": "https://taxii.example/taxii2/api1",
         "collection": "apt-reports", "api_key": "k1", "password": "p1"},
    ]})
    client.put("/api/settings/taxii", json={"servers": [
        {"name": "Vendor", "url": "https://taxii.example/taxii2/api1",
         "collection": "apt-reports", "api_key": "••••••••", "password": "••••••••",
         "enabled": False},
    ]})
    config = tomllib.loads(world.paths.config_file.read_text(encoding="utf-8"))
    assert config["taxii"][0]["api_key"] == "k1"
    assert config["taxii"][0]["password"] == "p1"
    assert config["taxii"][0]["enabled"] is False


def test_taxii_rejects_missing_collection(world):
    client = make_client(world)
    response = client.put("/api/settings/taxii", json={"servers": [
        {"name": "x", "url": "https://x.example/taxii", "collection": ""},
    ]})
    assert response.status_code == 400


# ---- Webhooks ----


def test_webhooks_list_is_empty_on_a_fresh_install(world):
    client = make_client(world)
    assert client.get("/api/settings/webhooks").json() == {"webhooks": []}


def test_webhooks_put_masks_the_secret(world):
    client = make_client(world)
    response = client.put("/api/settings/webhooks", json={"webhooks": [
        {"url": "https://hooks.slack.com/x", "secret": "s3cret",
         "on_states": ["finished"], "enabled": True},
    ]})
    assert response.status_code == 200
    [hook] = response.json()["webhooks"]
    assert hook["secret"] == "••••••••"
    assert hook["url"] == "https://hooks.slack.com/x"


def test_webhooks_mask_preserves_stored_secret(world):
    client = make_client(world)
    client.put("/api/settings/webhooks", json={"webhooks": [
        {"url": "https://hooks.slack.com/x", "secret": "s3cret"},
    ]})
    client.put("/api/settings/webhooks", json={"webhooks": [
        {"url": "https://hooks.slack.com/x", "secret": "••••••••", "enabled": False},
    ]})
    config = tomllib.loads(world.paths.config_file.read_text(encoding="utf-8"))
    assert config["webhooks"][0]["secret"] == "s3cret"
    assert config["webhooks"][0]["enabled"] is False


def test_webhooks_rejects_unknown_on_state(world):
    client = make_client(world)
    response = client.put("/api/settings/webhooks", json={"webhooks": [
        {"url": "https://x.example/hook", "on_states": ["running"]},   # not a terminal state
    ]})
    assert response.status_code == 400
    assert "running" in response.json()["error"].lower() or "state" in response.json()["error"].lower()


def test_webhooks_rejects_duplicate_urls(world):
    client = make_client(world)
    response = client.put("/api/settings/webhooks", json={"webhooks": [
        {"url": "https://same.example/hook"},
        {"url": "https://same.example/hook"},
    ]})
    assert response.status_code == 400
    assert "duplicate" in response.json()["error"].lower()


# ---- Isolation across sections (shared argus.toml write) ----


def test_saving_misp_does_not_wipe_taxii_or_webhooks(world):
    """The three sections live in the same file. A PUT to one must preserve the other two."""
    client = make_client(world)
    client.put("/api/settings/taxii", json={"servers": [
        {"name": "T1", "url": "https://t.example/taxii", "collection": "c1"},
    ]})
    client.put("/api/settings/webhooks", json={"webhooks": [
        {"url": "https://w.example/hook"},
    ]})
    client.put("/api/settings/misp", json={"servers": [
        {"name": "M1", "url": "https://m.example"},
    ]})
    config = tomllib.loads(world.paths.config_file.read_text(encoding="utf-8"))
    assert len(config.get("misp", [])) == 1
    assert len(config.get("taxii", [])) == 1
    assert len(config.get("webhooks", [])) == 1


# ---- Test endpoints (configuration probes) ----


def test_misp_test_endpoint_calls_restSearch(world):
    """The /test endpoint issues one `/events/restSearch` POST; a 200 counts as reachable."""
    seen = {}

    def handler(request):
        seen["path"] = request.url.path
        seen["method"] = request.method
        return httpx.Response(200, json={"response": []})

    client = make_client(world, http_transport=httpx.MockTransport(handler))
    response = client.post("/api/settings/misp/test", json={
        "name": "Probe", "url": "https://m.example", "api_key": "k",
    })
    assert response.status_code == 200
    assert response.json()["ok"] is True
    assert seen["path"].endswith("/events/restSearch")
    assert seen["method"] == "POST"


def test_misp_test_surfaces_auth_errors(world):
    def handler(_request):
        return httpx.Response(401, text="unauthorized")

    client = make_client(world, http_transport=httpx.MockTransport(handler))
    response = client.post("/api/settings/misp/test", json={
        "name": "Probe", "url": "https://m.example",
    })
    assert response.status_code == 200   # /test always 200s — the body carries ok/error
    body = response.json()
    assert body["ok"] is False
    assert "401" in body["error"] or "rejected" in body["error"].lower()


def test_taxii_test_endpoint_calls_objects(world):
    """The /test endpoint issues one `/collections/<id>/objects/` GET with match[type]=report."""
    seen = {}

    def handler(request):
        seen["path"] = request.url.path
        seen["query"] = str(request.url.query)
        return httpx.Response(200, json={"objects": [], "more": False})

    client = make_client(world, http_transport=httpx.MockTransport(handler))
    response = client.post("/api/settings/taxii/test", json={
        "name": "Probe", "url": "https://taxii.example/taxii2/api1",
        "collection": "c", "api_key": "k",
    })
    assert response.status_code == 200
    assert response.json()["ok"] is True
    assert "collections/c/objects" in seen["path"]
    assert "match%5Btype%5D=report" in seen["query"] or "match[type]=report" in seen["query"]


def test_webhook_test_endpoint_fires_a_signed_payload(world):
    """The /test endpoint fires one synthetic FINISHED payload. A 2xx is `ok=true`; the
    signature header is present when a secret is configured."""
    seen = {}

    def handler(request):
        seen["body"] = request.read()
        seen["sig"] = request.headers.get("x-argus-signature")
        seen["ts"] = request.headers.get("x-argus-timestamp")
        return httpx.Response(202, text="accepted")

    client = make_client(world, http_transport=httpx.MockTransport(handler))
    response = client.post("/api/settings/webhooks/test", json={
        "url": "https://ok.example/hook", "secret": "s3cret", "on_states": ["finished"],
    })
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    assert body["status"] == "sent"
    assert seen["sig"] is not None
    assert seen["sig"].startswith("sha256=")
    assert seen["ts"] is not None


def test_webhook_test_endpoint_surfaces_failures(world):
    """A 5xx on the probe surfaces as ok=false with the detail."""
    def handler(_request):
        return httpx.Response(500, text="broken")

    client = make_client(world, http_transport=httpx.MockTransport(handler))
    response = client.post("/api/settings/webhooks/test", json={
        "url": "https://broken.example/hook",
    })
    body = response.json()
    assert body["ok"] is False
    assert "500" in (body.get("detail") or "") or body["status"] == "failed"
