import pytest

from cyllex_argus.config.settings import ArgusConfig, LoggingConfig
from cyllex_argus.knowledge.trace import PipelineEvent
from cyllex_argus.llm.base import LLMUsage
from tests.support import World
from tests.web.conftest import TOKEN, make_client

CSRF = {"X-Argus-CSRF": "1"}


def _record(world, **kwargs):
    services = world.services()
    try:
        services.trace_recorder().record(PipelineEvent(**kwargs))
    finally:
        services.close()


def _usage(inp=1000, out=500):
    return LLMUsage(input_tokens=inp, output_tokens=out, model="claude-sonnet-5-5", duration_ms=1200)


@pytest.fixture
def raw_world(tmp_path):
    world = World(tmp_path / "home")
    world.config = ArgusConfig(feeds=[], logging=LoggingConfig(retain_raw_llm="full"))
    world.investigate()
    return world


def test_trace_shape_and_ordering(seeded_world):
    data = make_client(seeded_world).get("/api/investigations/1/trace").json()
    assert set(data) == {"cost", "documents", "events"} and data["events"]
    ids = [e["id"] for e in data["events"]]
    assert ids == sorted(ids)
    assert set(data["events"][0]) == {
        "id", "document_id", "stage", "decision", "reason", "created_at", "duration_ms", "usage", "has_raw"}
    assert {"collector", "analyst", "validator"} <= {e["stage"] for e in data["events"]}
    doc_ids = {e["document_id"] for e in data["events"] if e["document_id"] is not None}
    assert doc_ids and {d["id"] for d in data["documents"]} == doc_ids
    assert all(isinstance(d["title"], str) and d["title"] for d in data["documents"])


def test_trace_of_an_unknown_investigation_is_404(seeded_world):
    assert make_client(seeded_world).get("/api/investigations/999/trace").status_code == 404


def test_cost_is_null_without_llm_events(world):
    world.investigate()
    client = make_client(world)
    client.delete("/api/investigations/1/trace", headers=CSRF)
    _record(world, investigation_id=1, stage="collector", decision="collected")
    payload = client.get("/api/investigations/1/trace").json()
    assert payload["cost"] is None and len(payload["events"]) == 1


def test_cost_sums_only_events_with_usage(world):
    world.investigate()
    client = make_client(world)
    client.delete("/api/investigations/1/trace", headers=CSRF)
    _record(world, investigation_id=1, stage="collector", decision="collected", duration_ms=5000)
    _record(world, investigation_id=1, stage="analyst", decision="analysed", usage=_usage(1000, 500))
    _record(world, investigation_id=1, stage="triage", decision="relevant", usage=_usage(2000, 100))
    cost = client.get("/api/investigations/1/trace").json()["cost"]
    assert cost["input_tokens"] == 3000 and cost["output_tokens"] == 600
    assert cost["duration_ms"] == 2400  # the collector's own duration is not LLM time
    # claude-sonnet-5-5 at $2/$10 per MTok: analyst (1000*2 + 500*10) + triage (2000*2 + 100*10)
    assert cost["usd"] == pytest.approx(0.0070 + 0.0050)


def test_has_raw_and_raw_endpoint(raw_world):
    client = make_client(raw_world)
    _record(raw_world, investigation_id=1, stage="analyst", decision="analysed", usage=_usage(),
            raw_prompt="P", raw_response="R")
    events = client.get("/api/investigations/1/trace").json()["events"]
    with_raw = [e for e in events if e["has_raw"]]
    assert with_raw
    response = client.get(f"/api/investigations/1/trace/{with_raw[-1]['id']}/raw")
    assert response.status_code == 200 and response.json() == {"prompt": "P", "response": "R"}
    no_raw = next(e for e in events if not e["has_raw"])
    assert client.get(f"/api/investigations/1/trace/{no_raw['id']}/raw").status_code == 404
    assert client.get(f"/api/investigations/2/trace/{with_raw[-1]['id']}/raw").status_code == 404


def test_raw_is_404_when_the_flag_is_off_even_if_data_exists(raw_world):
    client = make_client(raw_world)
    event = next(e for e in client.get("/api/investigations/1/trace").json()["events"] if e["has_raw"])
    raw_world.config = ArgusConfig(feeds=[], logging=LoggingConfig(retain_raw_llm="off"))
    assert client.get(f"/api/investigations/1/trace/{event['id']}/raw").status_code == 404
    events = client.get("/api/investigations/1/trace").json()["events"]
    assert not any(e["has_raw"] for e in events)


def test_delete_returns_the_count_and_is_idempotent(seeded_world):
    client = make_client(seeded_world)
    count = len(client.get("/api/investigations/1/trace").json()["events"])
    assert client.delete("/api/investigations/1/trace", headers=CSRF).json() == {"deleted": count}
    assert client.delete("/api/investigations/1/trace", headers=CSRF).json() == {"deleted": 0}
    assert client.get("/api/investigations/1/trace").json() == {"cost": None, "documents": [], "events": []}


def test_delete_404s_for_an_unknown_investigation(seeded_world):
    # Symmetric with GET; a DELETE that says "0 deleted" on an id that never existed hides typos.
    assert make_client(seeded_world).delete("/api/investigations/9999/trace", headers=CSRF).status_code == 404


@pytest.mark.parametrize("method,path", [
    ("get", "/api/investigations/1/trace"),
    ("get", "/api/investigations/1/trace/1/raw"),
    ("delete", "/api/investigations/1/trace"),
])
def test_trace_routes_need_the_token(seeded_world, method, path):
    client = make_client(seeded_world, authenticated=False)
    assert getattr(client, method)(path, headers=CSRF).status_code == 401
    assert getattr(client, method)(path, headers={**CSRF, "X-Argus-Token": TOKEN + "x"}).status_code == 401


def test_delete_needs_the_csrf_header(seeded_world):
    assert make_client(seeded_world).delete("/api/investigations/1/trace").status_code == 403
