import json
import sqlite3

import pytest

from cyllex_argus.attack.catalog import AttackCatalog
from cyllex_argus.knowledge.attack_matrix import TACTICS, build_campaign_matrix, build_matrix
from cyllex_argus.knowledge.models import AliasOrigin, Assessment, AssessmentStatus
from cyllex_argus.knowledge.sqlite_store import SQLiteStore
from tests.support import SPIDER

VOICE = "attack-pattern--00000000-0000-4000-8000-000015660004"
PHISHING = "attack-pattern--00000000-0000-4000-8000-000000001566"
BLACKCAT = "malware--00000000-0000-4000-8000-000000001068"


@pytest.fixture
def tactic_catalog():
    """The mini bundle with two tactics on Spearphishing Voice and none on Phishing."""
    from tests.conftest import FIXTURES

    bundle = json.loads((FIXTURES / "attack_mini.json").read_text(encoding="utf-8"))
    for obj in bundle["objects"]:
        if obj["id"] == VOICE:
            obj["kill_chain_phases"] = [
                {"kill_chain_name": "mitre-attack", "phase_name": "initial-access"},
                {"kill_chain_name": "mitre-attack", "phase_name": "reconnaissance"},
            ]
    return AttackCatalog(bundle)


def matrix_for(world, catalog, entity_id):
    conn = sqlite3.connect(str(world.paths.db_file))
    conn.row_factory = sqlite3.Row
    try:
        return build_matrix(conn, catalog, entity_id)
    finally:
        conn.close()


def add_assessment(world, subject, obj, **overrides):
    with SQLiteStore(world.paths.db_file) as store:
        store.upsert_assessment(Assessment(**{
            "subject_entity_id": subject, "predicate": "uses", "object_entity_id": obj,
            "status": AssessmentStatus.SINGLE_SOURCE, "confidence": 40, "admiralty": "C3", **overrides}))


def test_matrix_always_has_the_14_mitre_tactics_in_canonical_order(world, tactic_catalog):
    with SQLiteStore(world.paths.db_file):
        pass  # creates the empty database
    matrix = matrix_for(world, tactic_catalog, "intrusion-set--nope")
    assert [t["id"] for t in matrix] == [tid for tid, _ in TACTICS]
    assert len(matrix) == 14
    assert all(t["techniques"] == [] for t in matrix)


def test_matrix_places_a_technique_under_each_of_its_tactics(seeded_world, tactic_catalog):
    matrix = matrix_for(seeded_world, tactic_catalog, SPIDER)
    initial = next(t for t in matrix if t["id"] == "initial-access")
    reco = next(t for t in matrix if t["id"] == "reconnaissance")
    assert [tech["external_id"] for tech in initial["techniques"]] == ["T1566.004"]
    assert [tech["external_id"] for tech in reco["techniques"]] == ["T1566.004"]
    assert initial["name"] == "Initial Access"


def test_matrix_only_counts_uses_assessments_of_attack_patterns(seeded_world, tactic_catalog):
    add_assessment(seeded_world, SPIDER, BLACKCAT)  # malware, not a technique
    add_assessment(seeded_world, SPIDER, PHISHING)  # a technique without tactics
    matrix = matrix_for(seeded_world, tactic_catalog, SPIDER)
    all_ids = [tech["external_id"] for tactic in matrix for tech in tactic["techniques"]]
    assert "T1566.004" in all_ids
    assert "T1566" not in all_ids
    assert len(all_ids) == 2  # Spearphishing Voice under its two tactics only


def test_matrix_carries_status_confidence_admiralty_and_source_count(seeded_world, tactic_catalog):
    matrix = matrix_for(seeded_world, tactic_catalog, SPIDER)
    [tech] = next(t["techniques"] for t in matrix if t["id"] == "initial-access")
    assert tech["id"] == VOICE and tech["name"] == "Spearphishing Voice"
    assert tech["status"] == "corroborated"
    # 2 undated F-grade supporters → confidence 28 (post-undated-factor fix). The seed data has
    # no publication date on the fixture pages, so the harsher undated_factor=0.5 applies.
    # Previously 40 under the old scoring that treated undated the same as ancient-dated.
    assert tech["confidence"] == 28
    assert tech["admiralty"] == "F2"
    assert tech["sources"] == 2


def test_matrix_keeps_the_assessed_entity_id_even_when_the_technique_was_revoked(seeded_world):
    from tests.conftest import FIXTURES

    replacement = "attack-pattern--00000000-0000-4000-8000-000000007777"
    bundle = json.loads((FIXTURES / "attack_mini.json").read_text(encoding="utf-8"))
    for obj in bundle["objects"]:
        if obj["id"] == VOICE:
            obj["revoked"] = True
    bundle["objects"] += [
        {"type": "attack-pattern", "id": replacement, "name": "Replacement Voice",
         "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}],
         "external_references": [{"source_name": "mitre-attack", "external_id": "T1566.099"}]},
        {"type": "relationship", "id": "relationship--00000000-0000-4000-8000-000000000077",
         "relationship_type": "revoked-by", "source_ref": VOICE, "target_ref": replacement},
    ]
    matrix = matrix_for(seeded_world, AttackCatalog(bundle), SPIDER)
    [tech] = next(t["techniques"] for t in matrix if t["id"] == "initial-access")
    assert tech["id"] == VOICE != replacement
    assert tech["external_id"] == "T1566.099" and tech["name"] == "Replacement Voice"


def test_matrix_can_be_scoped_to_the_techniques_one_investigation_supports(seeded_world, tactic_catalog):
    from tests.scope_support import add_scoped_claim, add_second_investigation

    second = add_second_investigation(seeded_world)

    def scoped(investigation_id):
        conn = sqlite3.connect(str(seeded_world.paths.db_file))
        conn.row_factory = sqlite3.Row
        try:
            matrix = build_matrix(conn, tactic_catalog, SPIDER, investigation_id)
        finally:
            conn.close()
        return {tech["id"] for tactic in matrix for tech in tactic["techniques"]}

    assert scoped(1) == {VOICE} and scoped(second) == set()
    add_scoped_claim(seeded_world, second, VOICE, object_name="Spearphishing Voice", object_type="attack-pattern")
    assert scoped(second) == {VOICE}


def test_campaign_matrix_includes_techniques_reachable_through_the_attributed_actor(seeded_world, tactic_catalog):
    """The seeded world has SPIDER→uses→VOICE but no direct campaign→uses edge; the matrix should
    still surface VOICE under the campaign because the campaign is attributed-to SPIDER.
    """
    with SQLiteStore(seeded_world.paths.db_file) as store:
        camp = store.create_entity("campaign", "Operation Reach", AliasOrigin.DOCUMENT)
        store.upsert_assessment(Assessment(
            subject_entity_id=camp.id, predicate="attributed-to", object_entity_id=SPIDER,
            status=AssessmentStatus.SINGLE_SOURCE, confidence=40, admiralty="C3"))
    conn = sqlite3.connect(str(seeded_world.paths.db_file))
    conn.row_factory = sqlite3.Row
    try:
        matrix = build_campaign_matrix(conn, tactic_catalog, camp.id)
    finally:
        conn.close()
    initial = next(t for t in matrix if t["id"] == "initial-access")
    assert any(t["id"] == VOICE for t in initial["techniques"])


def test_campaign_matrix_is_empty_without_any_use_edge(world, tactic_catalog):
    with SQLiteStore(world.paths.db_file) as store:
        camp = store.create_entity("campaign", "Lonely Op", AliasOrigin.DOCUMENT)
    conn = sqlite3.connect(str(world.paths.db_file))
    conn.row_factory = sqlite3.Row
    try:
        matrix = build_campaign_matrix(conn, tactic_catalog, camp.id)
    finally:
        conn.close()
    assert all(t["techniques"] == [] for t in matrix)
