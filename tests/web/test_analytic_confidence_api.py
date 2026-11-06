"""ICD 203 override endpoint + preservation across recomputes."""

from __future__ import annotations

from cyllex_argus.knowledge.models import (
    AliasOrigin,
    AnalyticConfidence,
    Assessment,
    AssessmentStatus,
)
from tests.web.conftest import make_client as _make_client


def make_client(world, **kwargs):
    client = _make_client(world, **kwargs)
    client.headers["X-Argus-CSRF"] = "1"
    return client


def _seed(world):
    svc = world.services()
    try:
        actor = svc.store.create_entity("intrusion-set", "ICDActor", AliasOrigin.ATTACK)
        malware = svc.store.create_entity("malware", "ICDBot", AliasOrigin.ATTACK)
        a = svc.store.upsert_assessment(Assessment(
            subject_entity_id=actor.id, predicate="uses", object_entity_id=malware.id,
            status=AssessmentStatus.CORROBORATED, confidence=80, admiralty="A2",
        ))
        return a.id
    finally:
        svc.close()


def test_put_sets_level_and_rationale(world):
    aid = _seed(world)
    client = make_client(world)
    r = client.put(
        f"/api/assessments/{aid}/analytic-confidence",
        json={"level": "low", "rationale": "evidence predates 2015 vendor rename"},
    )
    assert r.status_code == 200
    assert r.json()["analytic_confidence"] == "low"
    assert "vendor rename" in r.json()["confidence_rationale"]


def test_put_null_level_clears_override(world):
    aid = _seed(world)
    client = make_client(world)
    client.put(f"/api/assessments/{aid}/analytic-confidence", json={"level": "high", "rationale": "x"})
    r = client.put(f"/api/assessments/{aid}/analytic-confidence", json={"level": None, "rationale": None})
    assert r.status_code == 200
    assert r.json()["analytic_confidence"] is None
    assert r.json()["confidence_rationale"] is None


def test_404_on_unknown_assessment(world):
    r = make_client(world).put(
        "/api/assessments/99999/analytic-confidence", json={"level": "high"},
    )
    assert r.status_code == 404


def test_recompute_preserves_manual_override(world):
    """Core correctness: once a human says LOW with a rationale, a later recompute of the same
    triple (same subject/predicate/object) must not overwrite it with the derived value.
    This is what the COALESCE in upsert_assessment guards."""
    aid = _seed(world)
    svc = world.services()
    try:
        before = svc.store.set_analytic_confidence(
            aid, AnalyticConfidence.LOW, "my judgement",
        )
        assert before.analytic_confidence is AnalyticConfidence.LOW
        # Simulate a recompute: upsert the same triple with None (meaning "derive").
        a = svc.store.assessments_involving(before.subject_entity_id)
        existing = next(x for x in a if x.id == aid)
        svc.store.upsert_assessment(Assessment(
            subject_entity_id=existing.subject_entity_id,
            predicate=existing.predicate,
            object_entity_id=existing.object_entity_id,
            status=existing.status,
            confidence=existing.confidence,
            admiralty=existing.admiralty,
            analytic_confidence=None,
            confidence_rationale=None,
        ))
        # Fetch the fresh row.
        after = next(
            x for x in svc.store.assessments_involving(existing.subject_entity_id) if x.id == aid
        )
        assert after.analytic_confidence is AnalyticConfidence.LOW
        assert after.confidence_rationale == "my judgement"
    finally:
        svc.close()


def test_threat_profile_exposes_analytic_confidence(world):
    """The /api/threats/{id} endpoint must surface analytic_confidence on each fact so the UI
    can render the badge without a second round-trip."""
    svc = world.services()
    try:
        actor = svc.store.create_entity("intrusion-set", "UIActor", AliasOrigin.ATTACK)
        malware = svc.store.create_entity("malware", "UIBot", AliasOrigin.ATTACK)
        svc.store.upsert_assessment(Assessment(
            subject_entity_id=actor.id, predicate="uses", object_entity_id=malware.id,
            status=AssessmentStatus.CORROBORATED, confidence=80, admiralty="A2",
            analytic_confidence=AnalyticConfidence.HIGH,
        ))
        actor_id = actor.id
    finally:
        svc.close()
    body = make_client(world).get(f"/api/threats/{actor_id}").json()
    assert body["facts"]
    fact = body["facts"][0]
    assert fact["analytic_confidence"] == "high"
    assert "assessment_id" in fact
