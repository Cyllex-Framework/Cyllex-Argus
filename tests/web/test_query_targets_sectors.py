"""/api/query/targets merges actors.sectors[] (direct) with identity-targeting (indirect)."""

from __future__ import annotations

from cyllex_argus.knowledge.models import (
    AliasOrigin,
    Assessment,
    AssessmentStatus,
)
from tests.web.conftest import make_client as _make_client


def make_client(world, **kwargs):
    return _make_client(world, **kwargs)


def test_direct_sector_attribute_shows_without_an_identity_entity(world):
    """0.13 flow: the actor has sectors=["healthcare"] on its attributes directly. No identity
    entity need exist for the actor to show up in /api/query/targets?sector=healthcare."""
    svc = world.services()
    try:
        actor = svc.store.create_entity("intrusion-set", "SectorActor", AliasOrigin.ATTACK)
        svc.store.append_entity_sector(actor.id, "healthcare")
    finally:
        svc.close()
    body = make_client(world).get("/api/query/targets?sector=healthcare").json()
    assert body["matched_by_sectors_attribute"] == 1
    [row] = body["actors"]
    assert row["canonical_name"] == "SectorActor"
    assert row["source"] == "sectors"
    assert row["assessment_count"] == 0


def test_identity_targeting_path_still_works_without_sectors(world):
    """0.11-era flow: actor has `targets` claim against an identity whose `sector` attribute
    matches. Still returned, now with `source: "targets-identity"`."""
    svc = world.services()
    try:
        actor = svc.store.create_entity("intrusion-set", "LegacyActor", AliasOrigin.ATTACK)
        identity = svc.store.create_entity("identity", "ACME Health", AliasOrigin.DOCUMENT)
        svc.store.set_entity_attributes(identity.id, sector="healthcare")
        svc.store.upsert_assessment(Assessment(
            subject_entity_id=actor.id, predicate="targets", object_entity_id=identity.id,
            status=AssessmentStatus.CORROBORATED, confidence=70, admiralty="B2",
        ))
    finally:
        svc.close()
    body = make_client(world).get("/api/query/targets?sector=healthcare").json()
    assert body["matched_identities"] == 1
    [row] = body["actors"]
    assert row["canonical_name"] == "LegacyActor"
    assert row["source"] == "targets-identity"
    assert row["assessment_count"] == 1


def test_an_actor_on_both_paths_is_deduped_with_direct_source_winning(world):
    """An actor can have both: own sectors[] AND targets claims against identities. The dedupe
    keeps the direct source label but preserves the assessment count so the operator sees
    the full picture."""
    svc = world.services()
    try:
        actor = svc.store.create_entity("intrusion-set", "DualActor", AliasOrigin.ATTACK)
        svc.store.append_entity_sector(actor.id, "healthcare")
        identity = svc.store.create_entity("identity", "ACME Health", AliasOrigin.DOCUMENT)
        svc.store.set_entity_attributes(identity.id, sector="healthcare")
        svc.store.upsert_assessment(Assessment(
            subject_entity_id=actor.id, predicate="targets", object_entity_id=identity.id,
            status=AssessmentStatus.CORROBORATED, confidence=70, admiralty="B2",
        ))
    finally:
        svc.close()
    body = make_client(world).get("/api/query/targets?sector=healthcare").json()
    assert len(body["actors"]) == 1
    [row] = body["actors"]
    assert row["source"] == "sectors"   # direct wins
    assert row["assessment_count"] == 1  # count preserved


def test_direct_actors_sort_above_indirect(world):
    """Ranking: direct attribution first, then by assessment count desc. The operator sees
    the authoritative hits (actors we're sure about) at the top of the list."""
    svc = world.services()
    try:
        direct_actor = svc.store.create_entity("intrusion-set", "AlphaDirect", AliasOrigin.ATTACK)
        svc.store.append_entity_sector(direct_actor.id, "healthcare")
        indirect_actor = svc.store.create_entity("intrusion-set", "BetaIndirect", AliasOrigin.ATTACK)
        identity = svc.store.create_entity("identity", "ACME", AliasOrigin.DOCUMENT)
        svc.store.set_entity_attributes(identity.id, sector="healthcare")
        for _ in range(5):
            # Many assessments on the indirect actor; still ranked below the direct one.
            svc.store.upsert_assessment(Assessment(
                subject_entity_id=indirect_actor.id, predicate="targets", object_entity_id=identity.id,
                status=AssessmentStatus.CORROBORATED, confidence=80, admiralty="A1",
            ))
    finally:
        svc.close()
    body = make_client(world).get("/api/query/targets?sector=healthcare").json()
    names = [a["canonical_name"] for a in body["actors"]]
    assert names == ["AlphaDirect", "BetaIndirect"]


def test_country_filter_still_identity_only(world):
    """`?country=` has no actor-side path (actors do not carry a country attribute). The
    direct-sector count stays 0 and only identity-based matches surface."""
    svc = world.services()
    try:
        actor = svc.store.create_entity("intrusion-set", "USActor", AliasOrigin.ATTACK)
        identity = svc.store.create_entity("identity", "ACME", AliasOrigin.DOCUMENT)
        svc.store.set_entity_attributes(identity.id, country="US")
        svc.store.upsert_assessment(Assessment(
            subject_entity_id=actor.id, predicate="targets", object_entity_id=identity.id,
            status=AssessmentStatus.CORROBORATED, confidence=70, admiralty="B2",
        ))
    finally:
        svc.close()
    body = make_client(world).get("/api/query/targets?country=US").json()
    assert body["matched_by_sectors_attribute"] == 0
    assert body["matched_identities"] == 1
    [row] = body["actors"]
    assert row["source"] == "targets-identity"


def test_actors_by_sector_attribute_rejects_name_substring_false_positives(world):
    """The LIKE pre-filter can false-positive on names that contain the sector string
    (e.g. actor named "Healthcare Hunters"). The second-pass JSON parse must reject them
    so the operator does not see noise."""
    svc = world.services()
    try:
        # Actor whose CANONICAL NAME contains "healthcare" but no sectors attribute set.
        svc.store.create_entity("intrusion-set", "Healthcare Hunters", AliasOrigin.ATTACK)
        # Actor with the real attribute.
        legit = svc.store.create_entity("intrusion-set", "LegitActor", AliasOrigin.ATTACK)
        svc.store.append_entity_sector(legit.id, "healthcare")
    finally:
        svc.close()
    body = make_client(world).get("/api/query/targets?sector=healthcare").json()
    assert [a["canonical_name"] for a in body["actors"]] == ["LegitActor"]
