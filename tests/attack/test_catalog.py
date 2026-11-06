import json
from pathlib import Path

import httpx
import pytest

from cyllex_argus.attack.catalog import AttackCatalog, download_attack, load_catalog_into_store, normalize_technique_id

T1566 = "attack-pattern--00000000-0000-4000-8000-000000001566"
SPIDER = "intrusion-set--00000000-0000-4000-8000-000000001015"
FIXTURES = Path(__file__).parent.parent / "fixtures"


def test_normalize_technique_id():
    assert normalize_technique_id(" t1566.004 ") == "T1566.004"
    assert normalize_technique_id("T1566/004") == "T1566.004"
    assert normalize_technique_id("phishing") is None
    assert normalize_technique_id("T15") is None


def test_resolve_active_technique(attack_catalog):
    tech = attack_catalog.resolve_technique("t1566.004")
    assert tech.technique_id == "T1566.004"
    assert tech.name == "Spearphishing Voice"


def test_revoked_technique_follows_revoked_by(attack_catalog):
    assert attack_catalog.resolve_technique("T9999").stix_id == T1566


def test_deprecated_and_unknown_techniques_do_not_resolve(attack_catalog):
    assert attack_catalog.resolve_technique("T8888") is None
    assert attack_catalog.resolve_technique("T0000") is None
    assert attack_catalog.resolve_technique("not an id") is None


def test_groups_and_software(attack_catalog):
    [group] = attack_catalog.groups
    assert group.name == "Scattered Spider" and "UNC3944" in group.aliases
    assert {s.name for s in attack_catalog.software} == {"BlackCat", "Rclone"}
    assert {t.technique_id for t in attack_catalog.active_techniques()} == {"T1566", "T1566.004"}


def test_groups_capture_mitre_external_id(attack_catalog):
    """0.15 fix: groups/software now capture the external_references MITRE id at parse
    time. 0.14 and earlier left it as None, which meant the Threat Profile header could
    not render the G/S badge next to the actor's name."""
    [group] = attack_catalog.groups
    assert group.external_id == "G1015"
    software_ids = {s.name: s.external_id for s in attack_catalog.software}
    assert software_ids == {"BlackCat": "S1068", "Rclone": "S1040"}


def test_campaigns_are_loaded_from_the_bundle_and_revoked_ones_are_dropped(attack_catalog):
    """ATT&CK Enterprise includes campaign SDOs (C0027 Scattered Spider among them). The loader must
    expose them alongside groups and software — ignoring them leaves the operator asking why a well-
    known campaign is nowhere in the store."""
    assert {c.name for c in attack_catalog.campaigns} == {"C0027"}
    [c0027] = attack_catalog.campaigns
    assert "Scattered Spider CRM Campaign" in c0027.aliases


def test_load_into_store_is_idempotent(store, attack_catalog):
    # Entities loaded: 1 intrusion-set + 2 software (BlackCat, Rclone) + 1 campaign (C0027)
    # + 2 active techniques (T1566, T1566.004) = 6
    assert load_catalog_into_store(attack_catalog, store) == 6
    assert load_catalog_into_store(attack_catalog, store) == 0
    assert store.find_by_alias("Octo Tempest").id == SPIDER
    assert store.find_by_alias("ALPHV").stix_type == "malware"
    assert store.find_by_external_id("T1566").id == T1566
    # The campaign resolves by its MITRE external id and by its canonical name/alias.
    c0027 = store.find_by_external_id("C0027")
    assert c0027 is not None and c0027.stix_type == "campaign"
    assert store.find_by_alias("Scattered Spider CRM Campaign").id == c0027.id


def test_groups_and_software_persist_mitre_id(store, attack_catalog):
    """0.15 fix: groups/software get their MITRE id written to entities.external_id so
    find_by_external_id resolves them, matching the pre-existing behaviour for techniques
    and campaigns."""
    load_catalog_into_store(attack_catalog, store)
    actor = store.find_by_external_id("G1015")
    assert actor is not None and actor.canonical_name == "Scattered Spider"
    blackcat = store.find_by_external_id("S1068")
    assert blackcat is not None and blackcat.canonical_name == "BlackCat"


def test_load_backfills_external_id_on_existing_rows(store, attack_catalog):
    """Legacy stores with 0.14-era rows have external_id = NULL on groups/software. Re-running
    attack update must backfill the id so the badge appears without a full rebuild."""
    # Simulate a 0.14-era store: entity exists but with external_id = NULL.
    [group] = attack_catalog.groups
    store.connection.execute(
        "INSERT INTO entities (id, stix_type, canonical_name, external_id) "
        "VALUES (?, ?, ?, NULL)",
        (group.stix_id, group.stix_type, group.name),
    )
    store.connection.commit()
    load_catalog_into_store(attack_catalog, store)
    patched = store.get_entity(group.stix_id)
    assert patched.external_id == "G1015"


def test_download_attack_writes_validated_json(tmp_path):
    payload = {"type": "bundle", "objects": [{"type": "attack-pattern", "id": T1566, "name": "Phishing"}]}
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json=payload))
    dest = tmp_path / "attack" / "enterprise-attack.json"
    with httpx.Client(transport=transport) as client:
        result = download_attack(dest, client)
    assert result == dest
    assert json.loads(dest.read_text(encoding="utf-8")) == payload


@pytest.mark.parametrize("payload", [
    {"message": "rate limited"},
    [{"type": "attack-pattern"}],
    {"type": "bundle", "objects": "nope"},
    {"type": "bundle", "objects": []},
    {"type": "bundle", "objects": [{"type": "malware", "name": "BlackCat"}]},
])
def test_download_attack_keeps_the_good_bundle_when_the_answer_is_not_attack(tmp_path, payload):
    dest = tmp_path / "attack" / "enterprise-attack.json"
    dest.parent.mkdir()
    good = (FIXTURES / "attack_mini.json").read_text(encoding="utf-8")
    dest.write_text(good, encoding="utf-8")
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json=payload))
    with httpx.Client(transport=transport) as client, pytest.raises(ValueError, match="not an ATT&CK bundle"):
        download_attack(dest, client)
    assert dest.read_text(encoding="utf-8") == good
    assert list(dest.parent.iterdir()) == [dest]


def test_technique_carries_its_mitre_tactics_in_order():
    bundle = {"objects": [
        {"type": "attack-pattern", "id": "attack-pattern--1", "name": "Spearphishing Voice",
         "external_references": [{"source_name": "mitre-attack", "external_id": "T1566.004"}],
         "kill_chain_phases": [
             {"kill_chain_name": "mitre-attack", "phase_name": "initial-access"},
             {"kill_chain_name": "mitre-attack", "phase_name": "reconnaissance"},
             {"kill_chain_name": "other", "phase_name": "ignored"},
         ]},
        {"type": "attack-pattern", "id": "attack-pattern--2", "name": "Silent",
         "external_references": [{"source_name": "mitre-attack", "external_id": "T9999"}]},
    ]}
    catalog = AttackCatalog(bundle)
    spider = catalog.resolve_technique("T1566.004")
    silent = catalog.resolve_technique("T9999")
    assert spider.tactics == ["initial-access", "reconnaissance"]
    assert silent.tactics == []
