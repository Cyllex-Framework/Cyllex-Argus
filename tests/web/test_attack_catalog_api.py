import json

from tests.web.conftest import make_client

BUNDLE = {"type": "bundle", "objects": [
    {"type": "attack-pattern", "id": "attack-pattern--a", "name": "Active Scanning",
     "external_references": [{"source_name": "mitre-attack", "external_id": "T1595"}],
     "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "reconnaissance"}]},
    {"type": "attack-pattern", "id": "attack-pattern--b", "name": "Scanning IP Blocks",
     "external_references": [{"source_name": "mitre-attack", "external_id": "T1595.001"}],
     "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "reconnaissance"}]},
    {"type": "attack-pattern", "id": "attack-pattern--c", "name": "Valid Accounts",
     "external_references": [{"source_name": "mitre-attack", "external_id": "T1078"}],
     "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "initial-access"},
                           {"kill_chain_name": "mitre-attack", "phase_name": "persistence"}]},
    {"type": "attack-pattern", "id": "attack-pattern--d", "name": "Gone", "x_mitre_deprecated": True,
     "external_references": [{"source_name": "mitre-attack", "external_id": "T0001"}],
     "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "impact"}]},
]}


def test_catalog_lists_14_tactics_in_kill_chain_order_with_techniques(world):
    world.paths.attack_file.write_text(json.dumps(BUNDLE), encoding="utf-8")
    response = make_client(world).get("/api/attack/catalog")
    assert response.status_code == 200
    tactics = response.json()["tactics"]
    assert [t["id"] for t in tactics][:5] == ["reconnaissance", "resource-development", "initial-access", "execution", "persistence"]
    assert len(tactics) == 14 and tactics[0]["name"] == "Reconnaissance"
    by_id = {t["id"]: t for t in tactics}
    assert [t["external_id"] for t in by_id["reconnaissance"]["techniques"]] == ["T1595", "T1595.001"]
    assert by_id["reconnaissance"]["techniques"][0] == {
        "id": "attack-pattern--a", "external_id": "T1595", "name": "Active Scanning", "tactics": ["reconnaissance"]}
    assert by_id["impact"]["techniques"] == []  # deprecated techniques are left out


def test_multi_tactic_technique_appears_under_each(world):
    world.paths.attack_file.write_text(json.dumps(BUNDLE), encoding="utf-8")
    by_id = {t["id"]: t for t in make_client(world).get("/api/attack/catalog").json()["tactics"]}
    for tactic in ("initial-access", "persistence"):
        assert [t["external_id"] for t in by_id[tactic]["techniques"]] == ["T1078"]


def test_catalog_is_cacheable_for_ten_minutes(world):
    response = make_client(world).get("/api/attack/catalog")
    assert response.headers["cache-control"] == "public, max-age=600"


def test_missing_catalog_is_404_and_not_cached(world):
    world.paths.attack_file.unlink()
    response = make_client(world).get("/api/attack/catalog")
    assert response.status_code == 404
    assert response.json() == {"error": "ATT&CK data not loaded"}
    assert response.headers["cache-control"] == "no-store"
