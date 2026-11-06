"""Cached executive summary: read, write, staleness and provider failure."""

from __future__ import annotations

from cyllex_argus.knowledge.models import AliasOrigin, Assessment, AssessmentStatus
from cyllex_argus.llm.base import LLMRequest, RateLimited
from cyllex_argus.llm.fake import FakeLLMProvider
from tests.web.conftest import make_client

CSRF = {"X-Argus-CSRF": "1"}


def _seed(world, *, facts: int = 1) -> str:
    svc = world.services()
    try:
        actor = svc.store.create_entity("intrusion-set", "SummaryActor", AliasOrigin.ATTACK)
        for n in range(facts):
            technique = svc.store.create_entity("attack-pattern", f"Technique {n}", AliasOrigin.ATTACK)
            svc.store.upsert_assessment(Assessment(
                subject_entity_id=actor.id, predicate="uses", object_entity_id=technique.id,
                status=AssessmentStatus.CORROBORATED, confidence=80, admiralty="A2",
            ))
        return actor.id
    finally:
        svc.close()


def test_get_returns_empty_shape_before_anything_is_written(world):
    actor_id = _seed(world)
    body = make_client(world).get(f"/api/threats/{actor_id}/summary").json()
    assert body["summary"] is None
    assert body["generated_at"] is None
    assert body["stale"] is False
    assert body["fact_count"] == 1
    assert body["can_generate"] is True


def test_get_never_calls_the_llm(world):
    """A page load must not bill the operator — reading is pure cache."""
    actor_id = _seed(world)
    before = world.llm.calls if hasattr(world.llm, "calls") else None
    make_client(world).get(f"/api/threats/{actor_id}/summary")
    if before is not None:
        assert world.llm.calls == before


def test_post_writes_the_summary_and_get_reads_it_back(world):
    actor_id = _seed(world)
    client = make_client(world)
    written = client.post(f"/api/threats/{actor_id}/summary", headers=CSRF).json()
    assert "financially motivated" in written["summary"]
    assert written["stale"] is False
    assert written["written_from_fact_count"] == 1
    assert written["prompt_version"] == "summary-v5"

    read_back = client.get(f"/api/threats/{actor_id}/summary").json()
    assert read_back["summary"] == written["summary"]
    assert read_back["generated_at"] == written["generated_at"]


def test_summary_goes_stale_when_a_new_fact_lands(world):
    actor_id = _seed(world)
    client = make_client(world)
    client.post(f"/api/threats/{actor_id}/summary", headers=CSRF)
    assert client.get(f"/api/threats/{actor_id}/summary").json()["stale"] is False

    svc = world.services()
    try:
        extra = svc.store.create_entity("malware", "NewMalware", AliasOrigin.DOCUMENT)
        svc.store.upsert_assessment(Assessment(
            subject_entity_id=actor_id, predicate="uses", object_entity_id=extra.id,
            status=AssessmentStatus.SINGLE_SOURCE, confidence=40, admiralty="C3",
        ))
    finally:
        svc.close()

    body = client.get(f"/api/threats/{actor_id}/summary").json()
    assert body["stale"] is True
    assert body["summary"] is not None, "a stale summary stays readable"
    assert body["written_from_fact_count"] == 1
    assert body["fact_count"] == 2


def test_rewriting_clears_staleness(world):
    actor_id = _seed(world, facts=2)
    client = make_client(world)
    client.post(f"/api/threats/{actor_id}/summary", headers=CSRF)
    svc = world.services()
    try:
        extra = svc.store.create_entity("tool", "NewTool", AliasOrigin.DOCUMENT)
        svc.store.upsert_assessment(Assessment(
            subject_entity_id=actor_id, predicate="uses", object_entity_id=extra.id,
            status=AssessmentStatus.SINGLE_SOURCE, confidence=40, admiralty="C3",
        ))
    finally:
        svc.close()
    assert client.get(f"/api/threats/{actor_id}/summary").json()["stale"] is True
    rewritten = client.post(f"/api/threats/{actor_id}/summary", headers=CSRF).json()
    assert rewritten["stale"] is False
    assert rewritten["written_from_fact_count"] == 3


def test_post_409_when_the_threat_has_no_facts(world):
    svc = world.services()
    try:
        bare = svc.store.create_entity("intrusion-set", "BareActor", AliasOrigin.ATTACK).id
    finally:
        svc.close()
    response = make_client(world).post(f"/api/threats/{bare}/summary", headers=CSRF)
    assert response.status_code == 409
    assert "investigate" in response.json()["error"].lower()


def test_post_503_when_the_provider_fails(world):
    actor_id = _seed(world)

    def rate_limited(_request: LLMRequest):
        return RateLimited("usage limit reached")

    world.llm = FakeLLMProvider(rate_limited)
    response = make_client(world).post(f"/api/threats/{actor_id}/summary", headers=CSRF)
    assert response.status_code == 503
    assert "usage limit" in response.json()["error"]


def test_404_on_unknown_threat(world):
    client = make_client(world)
    assert client.get("/api/threats/intrusion-set--nope/summary").status_code == 404
    assert client.post("/api/threats/intrusion-set--nope/summary", headers=CSRF).status_code == 404
