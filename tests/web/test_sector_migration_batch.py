"""POST /api/entities/migrate-sectors-batch — bulk variant."""

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


def _seed(world, actor_name: str, *sectors: str) -> tuple[str, list[str]]:
    """One actor with `targets` claims against each sector identity."""
    svc = world.services()
    try:
        actor = svc.store.create_entity("intrusion-set", actor_name, AliasOrigin.ATTACK)
        ids: list[str] = []
        for s in sectors:
            sector = svc.store.create_entity("identity", s, AliasOrigin.DOCUMENT)
            svc.store.upsert_assessment(Assessment(
                subject_entity_id=actor.id, predicate="targets", object_entity_id=sector.id,
                status=AssessmentStatus.CORROBORATED, confidence=70, admiralty="B2",
            ))
            ids.append(sector.id)
        return actor.id, ids
    finally:
        svc.close()


def test_batch_all_succeed_tags_each_actor(world):
    actor_id, sector_ids = _seed(world, "ZetaActor", "healthcare", "retail", "insurance")
    r = make_client(world).post(
        "/api/entities/migrate-sectors-batch",
        json={"identity_ids": sector_ids},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 3
    assert len(body["ok"]) == 3
    assert body["failed"] == []
    # The actor accumulated all three sector tags.
    svc = world.services()
    try:
        actor = svc.store.get_entity(actor_id)
        assert sorted(actor.attributes.get("sectors", [])) == ["healthcare", "insurance", "retail"]
    finally:
        svc.close()


def test_batch_mixes_success_and_unknown_identity(world):
    actor_id, [healthcare_id] = _seed(world, "ZetaActor", "healthcare")
    r = make_client(world).post(
        "/api/entities/migrate-sectors-batch",
        json={"identity_ids": [healthcare_id, "identity--does-not-exist"]},
    )
    body = r.json()
    assert body["total"] == 2
    assert len(body["ok"]) == 1
    assert len(body["failed"]) == 1
    assert body["failed"][0]["identity_id"] == "identity--does-not-exist"


def test_batch_rejects_empty_list(world):
    r = make_client(world).post("/api/entities/migrate-sectors-batch", json={"identity_ids": []})
    assert r.status_code in (400, 422)


def test_batch_rejects_too_many_items(world):
    """Cap is tighter than retype (50 vs 100) because the operation does more SQL per item —
    a bigger clean-up should run as two batches so each stage is auditable."""
    r = make_client(world).post(
        "/api/entities/migrate-sectors-batch",
        json={"identity_ids": [f"identity--{i:032d}" for i in range(51)]},
    )
    assert r.status_code in (400, 422)


def test_batch_requires_csrf(world):
    _, [sector_id] = _seed(world, "ZetaActor", "healthcare")
    client = _make_client(world)
    r = client.post("/api/entities/migrate-sectors-batch", json={"identity_ids": [sector_id]})
    assert r.status_code == 403
