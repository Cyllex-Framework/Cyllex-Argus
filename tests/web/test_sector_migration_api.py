"""POST /api/entities/{id}/migrate-to-sector-tag — sector-identity → actor.sectors[]."""

from __future__ import annotations

from cyllex_argus.knowledge.models import (
    AliasOrigin,
    Assessment,
    AssessmentStatus,
)
from tests.web.conftest import make_client as _make_client


def make_client(world, **kwargs):
    client = _make_client(world, **kwargs)
    client.headers["X-Argus-CSRF"] = "1"
    return client


def _seed_sector_targeting(world) -> tuple[str, str, str]:
    """One sector identity, two actors each with a `targets` assessment against it."""
    svc = world.services()
    try:
        actor_a = svc.store.create_entity("intrusion-set", "ZetaActor", AliasOrigin.ATTACK)
        actor_b = svc.store.create_entity("campaign", "Zeta Campaign", AliasOrigin.ATTACK)
        sector = svc.store.create_entity("identity", "healthcare", AliasOrigin.DOCUMENT)
        for actor_id in (actor_a.id, actor_b.id):
            svc.store.upsert_assessment(Assessment(
                subject_entity_id=actor_id, predicate="targets", object_entity_id=sector.id,
                status=AssessmentStatus.CORROBORATED, confidence=70, admiralty="B2",
            ))
        return sector.id, actor_a.id, actor_b.id
    finally:
        svc.close()


def test_actors_targeting_identity_endpoint(world):
    sector_id, actor_a, actor_b = _seed_sector_targeting(world)
    body = make_client(world).get(f"/api/entities/{sector_id}/actors-targeting").json()
    actor_ids = {a["id"] for a in body["actors"]}
    assert actor_ids == {actor_a, actor_b}


def test_actors_targeting_404_on_unknown_entity(world):
    r = make_client(world).get("/api/entities/identity--nope/actors-targeting")
    assert r.status_code == 404


def test_migrate_sector_tag_defaults_to_every_targeting_actor(world):
    sector_id, actor_a, actor_b = _seed_sector_targeting(world)
    r = make_client(world).post(
        f"/api/entities/{sector_id}/migrate-to-sector-tag",
        json={"actor_ids": [], "delete": True},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["identity_canonical_name"] == "healthcare"
    assert body["deleted"] is True
    tagged_ids = {a["id"] for a in body["tagged_actors"]}
    assert tagged_ids == {actor_a, actor_b}
    # Each actor now has sectors == ["healthcare"].
    for actor in body["tagged_actors"]:
        assert actor["sectors"] == ["healthcare"]


def test_migrate_sector_tag_removes_identity_and_its_claims(world):
    sector_id, actor_a, actor_b = _seed_sector_targeting(world)
    make_client(world).post(
        f"/api/entities/{sector_id}/migrate-to-sector-tag",
        json={"actor_ids": [], "delete": True},
    )
    svc = world.services()
    try:
        assert svc.store.get_entity(sector_id) is None
        # Actors survive; healthcare appears in their sectors.
        actor = svc.store.get_entity(actor_a)
        assert actor.attributes.get("sectors") == ["healthcare"]
    finally:
        svc.close()


def test_migrate_sector_tag_with_explicit_actor_subset(world):
    sector_id, actor_a, actor_b = _seed_sector_targeting(world)
    r = make_client(world).post(
        f"/api/entities/{sector_id}/migrate-to-sector-tag",
        json={"actor_ids": [actor_a], "delete": False},
    )
    body = r.json()
    assert len(body["tagged_actors"]) == 1
    assert body["tagged_actors"][0]["id"] == actor_a
    assert body["deleted"] is False
    # The identity SURVIVES because delete=false.
    svc = world.services()
    try:
        assert svc.store.get_entity(sector_id) is not None
        # actor_b was not in the list, so its sectors stay empty.
        actor_b_entity = svc.store.get_entity(actor_b)
        assert "sectors" not in actor_b_entity.attributes or actor_b_entity.attributes["sectors"] == []
    finally:
        svc.close()


def test_migrate_sector_tag_404_on_unknown_identity(world):
    r = make_client(world).post(
        "/api/entities/identity--does-not-exist/migrate-to-sector-tag",
        json={"actor_ids": []},
    )
    assert r.status_code == 404


def test_migrate_sector_tag_requires_csrf(world):
    sector_id, *_ = _seed_sector_targeting(world)
    client = _make_client(world)
    r = client.post(f"/api/entities/{sector_id}/migrate-to-sector-tag", json={"actor_ids": []})
    assert r.status_code == 403
