"""HTTP API for the enrichment framework: list the catalog, toggle, invoke."""

from __future__ import annotations

import tomllib

from tests.web.conftest import make_client as _make_client


def make_client(world, **kwargs):
    client = _make_client(world, **kwargs)
    client.headers["X-Argus-CSRF"] = "1"
    return client


def test_list_enrichers_returns_catalog_with_outbound_statements(world):
    client = make_client(world)
    response = client.get("/api/enrichers")
    assert response.status_code == 200
    names = {e["name"] for e in response.json()["enrichers"]}
    assert {"crt.sh", "nvd", "urlhaus", "cisa-kev"} <= names
    for enricher in response.json()["enrichers"]:
        assert "outbound" in enricher
        assert enricher["enabled"] is False   # fresh fixture: every enricher is OFF
        assert enricher["supported_types"]    # non-empty


def test_toggle_persists_the_change_to_argus_toml(world):
    client = make_client(world)
    response = client.put("/api/enrichers/crt.sh", json={"enabled": True})
    assert response.status_code == 200
    body = response.json()
    # The PUT returns the full enricher view (name/description/outbound/enabled/requires_api_key…).
    # crt.sh is NOT key-gated, so the key fields stay empty.
    assert body["name"] == "crt.sh"
    assert body["enabled"] is True
    assert body["requires_api_key"] is False
    assert body["api_key_configured"] is False
    # Round-trip: the catalog view reflects the new state.
    listing = client.get("/api/enrichers").json()["enrichers"]
    [crtsh] = [e for e in listing if e["name"] == "crt.sh"]
    assert crtsh["enabled"] is True
    # And the config file has the stanza.
    config = tomllib.loads(world.paths.config_file.read_text(encoding="utf-8"))
    assert config["enrichment"]["enrichers"]["crt.sh"]["enabled"] is True


def test_toggle_virustotal_persists_api_key_and_masks_it_on_read(world):
    """VirusTotal is a key-gated enricher: the PUT persists `api_key` and `env_api_key`, the
    subsequent GET returns the key as the mask ("••••••••") so plaintext never crosses the API."""
    client = make_client(world)
    response = client.put(
        "/api/enrichers/virustotal",
        json={"enabled": True, "api_key": "s3cret-vt", "env_api_key": "VIRUSTOTAL_API_KEY"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["requires_api_key"] is True
    assert body["api_key_configured"] is True
    assert body["api_key"] == "••••••••"   # masked, not plaintext
    assert body["env_api_key"] == "VIRUSTOTAL_API_KEY"
    # Round-trip: catalog shows it masked.
    listing = client.get("/api/enrichers").json()["enrichers"]
    [vt] = [e for e in listing if e["name"] == "virustotal"]
    assert vt["api_key"] == "••••••••"
    assert vt["enabled"] is True
    # Config file has the plaintext (file is on local disk; the API never surfaces it).
    config = tomllib.loads(world.paths.config_file.read_text(encoding="utf-8"))
    assert config["enrichment"]["enrichers"]["virustotal"]["api_key"] == "s3cret-vt"


def test_toggle_virustotal_mask_preserves_stored_key(world):
    """Toggling `enabled` on a key-gated enricher while sending the mask back must NOT clear
    the stored key — the operator doesn't have to re-paste it to flip the switch."""
    client = make_client(world)
    # First save a real key.
    client.put("/api/enrichers/virustotal", json={"enabled": True, "api_key": "s3cret-vt"})
    # Then flip the toggle while echoing the mask back.
    response = client.put(
        "/api/enrichers/virustotal",
        json={"enabled": False, "api_key": "••••••••"},
    )
    assert response.status_code == 200
    config = tomllib.loads(world.paths.config_file.read_text(encoding="utf-8"))
    assert config["enrichment"]["enrichers"]["virustotal"]["api_key"] == "s3cret-vt"
    assert config["enrichment"]["enrichers"]["virustotal"]["enabled"] is False


def test_toggle_rejects_unknown_enricher(world):
    client = make_client(world)
    response = client.put("/api/enrichers/not-a-real-one", json={"enabled": True})
    assert response.status_code == 404
    assert "unknown" in response.json()["error"].lower()


def test_invoke_refuses_a_disabled_enricher_with_409(world):
    """A UI that tries to invoke before toggling must see the OPSEC trade-off reason."""
    client = make_client(world)
    response = client.post(
        "/api/enrichers/crt.sh/invoke",
        json={"indicator": "example.com", "indicator_type": "domain-name"},
    )
    assert response.status_code == 409
    assert "disabled" in response.json()["error"].lower()


def test_invoke_rejects_a_bad_indicator_type_with_400(world):
    client = make_client(world)
    response = client.post(
        "/api/enrichers/crt.sh/invoke",
        json={"indicator": "example.com", "indicator_type": "not-a-stix-type"},
    )
    assert response.status_code == 400
    assert "indicator_type" in response.json()["error"]


def test_invoke_dispatches_through_the_runner_when_enabled(world, monkeypatch):
    """Once enabled, the invoke endpoint returns the enricher's findings."""
    from cyllex_argus.enrichment import EnrichmentFinding, EnrichmentResult
    from cyllex_argus.enrichment.crtsh import CrtShEnricher

    def fake_enrich(self, request):
        return EnrichmentResult(
            request=request,
            findings=[EnrichmentFinding(source="crt.sh", key="common-name", value="a.example.com")],
            duration_ms=12,
        )
    monkeypatch.setattr(CrtShEnricher, "enrich", fake_enrich)

    client = make_client(world)
    client.put("/api/enrichers/crt.sh", json={"enabled": True})
    response = client.post(
        "/api/enrichers/crt.sh/invoke",
        json={"indicator": "example.com", "indicator_type": "domain-name"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["name"] == "crt.sh"
    assert body["error"] is None
    assert [f["value"] for f in body["findings"]] == ["a.example.com"]
