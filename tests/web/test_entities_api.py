"""HTTP API for identity attributes, targets query and admin entity-merge."""

from __future__ import annotations

from cyllex_argus.knowledge.models import AliasOrigin
from tests.web.conftest import make_client as _make_client


def make_client(world, **kwargs):
    client = _make_client(world, **kwargs)
    client.headers["X-Argus-CSRF"] = "1"
    return client


def _in_services(world, fn):
    svc = world.services()
    try:
        return fn(svc)
    finally:
        svc.close()


def test_update_attributes_sets_sector_and_country(world):
    identity = _in_services(world, lambda s: s.store.create_entity(
        "identity", "Caesars Entertainment", AliasOrigin.DOCUMENT,
    ))
    client = make_client(world)
    response = client.put(
        f"/api/entities/{identity.id}/attributes",
        json={"sector": "gaming", "country": "US"},
    )
    assert response.status_code == 200
    assert response.json()["attributes"] == {"sector": "gaming", "country": "US"}


def test_update_attributes_404_on_unknown(world):
    client = make_client(world)
    assert client.put(
        "/api/entities/identity--does-not-exist/attributes",
        json={"sector": "x"},
    ).status_code == 404


def test_query_targets_lists_actors_ranked(world):
    from cyllex_argus.knowledge.models import Assessment, AssessmentStatus

    def seed(svc):
        actor_a = svc.store.create_entity("intrusion-set", "Alpha", AliasOrigin.ATTACK)
        actor_b = svc.store.create_entity("intrusion-set", "Beta", AliasOrigin.ATTACK)
        bank1 = svc.store.create_entity("identity", "Bank One", AliasOrigin.DOCUMENT)
        bank2 = svc.store.create_entity("identity", "Bank Two", AliasOrigin.DOCUMENT)
        for ident in (bank1, bank2):
            svc.store.set_entity_attributes(ident.id, sector="financial", country="US")
        for subj, obj in ((actor_a.id, bank1.id), (actor_a.id, bank2.id), (actor_b.id, bank1.id)):
            svc.store.upsert_assessment(Assessment(
                subject_entity_id=subj, predicate="targets", object_entity_id=obj,
                status=AssessmentStatus.CORROBORATED, confidence=80, admiralty="A2",
            ))

    _in_services(world, seed)
    response = make_client(world).get("/api/query/targets?sector=financial")
    assert response.status_code == 200
    data = response.json()
    assert data["matched_identities"] == 2
    names = [a["canonical_name"] for a in data["actors"]]
    assert names == ["Alpha", "Beta"]   # Alpha has 2 assessments, Beta has 1


def test_query_targets_requires_at_least_one_filter(world):
    response = make_client(world).get("/api/query/targets")
    assert response.status_code == 400
    assert "sector" in response.json()["error"]


def test_merge_endpoint_fuses_two_entities(world):
    def seed(svc):
        dup = svc.store.create_entity("campaign", "DUP", AliasOrigin.DOCUMENT)
        off = svc.store.create_entity(
            "campaign", "OFF", AliasOrigin.ATTACK,
            external_id="X-API-0001", entity_id="campaign--off",
        )
        return dup, off
    dup, off = _in_services(world, seed)
    response = make_client(world).post(
        "/api/entities/merge",
        json={"source": dup.id, "target": off.id},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["source"] == dup.id and body["target"] == off.id
    def check(svc):
        assert svc.store.get_entity(dup.id) is None
        assert svc.store.find_by_external_id("X-API-0001").id == off.id
    _in_services(world, check)


def test_merge_refuses_cross_stix_type(world):
    def seed(svc):
        a = svc.store.create_entity("intrusion-set", "A", AliasOrigin.DOCUMENT)
        b = svc.store.create_entity("campaign", "B", AliasOrigin.DOCUMENT)
        return a, b
    a, b = _in_services(world, seed)
    assert make_client(world).post(
        "/api/entities/merge",
        json={"source": a.id, "target": b.id},
    ).status_code == 400


def test_merge_404_on_unknown(world):
    assert make_client(world).post(
        "/api/entities/merge",
        json={"source": "nope", "target": "nope2"},
    ).status_code == 404
