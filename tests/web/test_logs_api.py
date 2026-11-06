from datetime import UTC, datetime, timedelta

import pytest

from cyllex_argus.knowledge.browse import BrowseQueries
from cyllex_argus.web.jobs import JobManager
from tests.web.conftest import TOKEN, make_client

EVENT_KEYS = {
    "id", "investigation_id", "investigation_target", "document_id", "document_title", "stage", "decision", "reason",
    "created_at", "duration_ms", "input_tokens", "output_tokens", "cost_usd",
}
JOB_KEYS = {"id", "kind", "state", "started_at", "finished_at", "message", "duration_ms", "events_count"}


def _ok(params, log):
    log("working")
    return {"state": "finished", "message": "done"}


def _boom(params, log):
    raise RuntimeError("boom")


def _jobs():
    manager = JobManager({"ingest": _ok, "attack_update": _ok, "recompute": _boom}, inline=True)
    manager.submit("ingest", {})
    manager.submit("attack_update", {})
    manager.submit("recompute", {})
    return manager


def _client(world, jobs=None):
    return make_client(world, jobs=jobs or _jobs())


def test_logs_shape(seeded_world):
    data = _client(seeded_world).get("/api/logs").json()
    assert set(data) == {"jobs", "events"}
    assert [j["kind"] for j in data["jobs"]] == ["recompute", "attack_update", "ingest"]  # newest first
    assert all(set(j) == JOB_KEYS for j in data["jobs"])
    assert data["jobs"][0]["state"] == "failed" and data["jobs"][0]["message"] == "RuntimeError: boom"
    assert data["jobs"][2]["events_count"] == 1 and isinstance(data["jobs"][2]["duration_ms"], int)
    events = data["events"]
    assert events and all(set(e) == EVENT_KEYS for e in events)
    stamps = [e["created_at"] for e in events]
    assert stamps == sorted(stamps, reverse=True)
    assert all(e["investigation_target"] == "Scattered Spider" for e in events)
    assert any(e["document_title"] for e in events)


def test_filter_jobs_by_kind(seeded_world):
    data = _client(seeded_world).get("/api/logs", params={"kind": "ingest"}).json()
    assert [j["kind"] for j in data["jobs"]] == ["ingest"]
    assert data["events"]  # the kind filter narrows jobs only


def test_filter_jobs_by_state(seeded_world):
    data = _client(seeded_world).get("/api/logs", params={"state": "failed"}).json()
    assert [j["kind"] for j in data["jobs"]] == ["recompute"]


@pytest.mark.parametrize("params", [{"kind": "nope"}, {"state": "nope"}, {"since": "yesterday"}, {"limit": 0}])
def test_invalid_filters_are_400(seeded_world, params):
    assert _client(seeded_world).get("/api/logs", params=params).status_code == 400


def test_since_filters_jobs_and_events(seeded_world):
    client = _client(seeded_world)
    future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
    assert client.get("/api/logs", params={"since": future}).json() == {"jobs": [], "events": []}
    past = (datetime.now(UTC) - timedelta(hours=1)).date().isoformat()  # a bare date is accepted
    data = client.get("/api/logs", params={"since": past}).json()
    assert len(data["jobs"]) == 3 and data["events"]


def test_limit_caps_each_list(seeded_world):
    data = _client(seeded_world).get("/api/logs", params={"limit": 2}).json()
    assert len(data["jobs"]) == 2 and len(data["events"]) == 2
    assert len(_client(seeded_world).get("/api/logs", params={"limit": 100000}).json()["events"]) <= 500


def test_recent_events_filters_by_stage(seeded_world):
    with BrowseQueries(seeded_world.paths.db_file) as browse:
        everything = browse.recent_events(500)
        analyst = browse.recent_events(500, kind_filter="analyst")
    assert analyst and {e["stage"] for e in analyst} == {"analyst"} and len(analyst) < len(everything)


def test_logs_need_the_token(seeded_world):
    client = make_client(seeded_world, authenticated=False)
    assert client.get("/api/logs").status_code == 401
    assert client.get("/api/logs", headers={"X-Argus-Token": TOKEN + "x"}).status_code == 401
