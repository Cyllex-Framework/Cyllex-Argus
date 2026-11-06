import sqlite3

import pytest

from cyllex_argus.web.jobs import JobManager
from tests.support import SPIDER
from tests.web.conftest import make_client


def _set(world, **columns):
    conn = sqlite3.connect(str(world.paths.db_file))
    try:
        sets = ", ".join(f"{name} = ?" for name in columns)
        conn.execute(f"UPDATE investigations SET {sets} WHERE id = 1", tuple(columns.values()))
        conn.commit()
    finally:
        conn.close()


def _tactic_ids(data):
    return [t["id"] for t in data["attack_matrix"]["tactics"]]


def test_dashboard_of_an_unknown_investigation_is_404(seeded_world):
    response = make_client(seeded_world).get("/api/investigations/999/dashboard")
    assert response.status_code == 404 and response.json() == {"error": "unknown investigation"}


def test_dashboard_of_an_unresolved_investigation(seeded_world):
    _set(seeded_world, resolved_entity_id=None)
    data = make_client(seeded_world).get("/api/investigations/1/dashboard").json()
    assert data["entity"] is None
    assert len(_tactic_ids(data)) == 14
    assert all(t["techniques"] == [] for t in data["attack_matrix"]["tactics"])


def test_dashboard_of_a_resolved_investigation(seeded_world):
    data = make_client(seeded_world).get("/api/investigations/1/dashboard").json()
    assert data["investigation"]["state"] == "finished"
    assert data["investigation"]["counts"] == {"failed": 1, "irrelevant": 1, "validated": 2}
    assert data["entity"]["id"] == SPIDER and data["entity"]["name"] == "Scattered Spider"
    assert {"alias": "UNC3944", "origin": "attack"} in data["entity"]["aliases"]
    assert len(_tactic_ids(data)) == 14 and _tactic_ids(data)[0] == "reconnaissance"


def test_dashboard_without_attack_data_still_has_the_shape(seeded_world):
    seeded_world.paths.attack_file.unlink()
    data = make_client(seeded_world).get("/api/investigations/1/dashboard").json()
    assert data["entity"]["id"] == SPIDER and len(_tactic_ids(data)) == 14


def test_dashboard_of_a_failed_job_carries_the_reason(seeded_world):
    _set(seeded_world, state="running", finished_at=None)

    def boom(params, log):
        raise RuntimeError("usage limit reached")

    jobs = JobManager({"resume": boom}, inline=True)
    jobs.submit("resume", {"investigation_id": 1})
    header = make_client(seeded_world, jobs=jobs).get("/api/investigations/1/dashboard").json()["investigation"]
    assert header["state"] == "failed" and "usage limit reached" in header["failure_reason"]


class _ListedJobs(JobManager):
    """A job manager whose list() returns canned summaries, newest first."""

    def __init__(self, summaries):
        super().__init__({}, inline=True)
        self._summaries = summaries

    def list(self):
        return self._summaries


def _job(kind, state, target, *, result=None, message=None, **params):
    return {"id": "x", "kind": kind, "params": {"target": target, **params}, "state": state,
            "message": message, "result": result}


def test_dashboard_prefers_failed_investigate_job_matched_by_investigation_id(seeded_world):
    _set(seeded_world, state="running", finished_at=None)
    target = "Scattered Spider"
    jobs = _ListedJobs([
        _job("investigate", "running", target, result={"investigation_id": 2}),
        _job("investigate", "failed", target, result={"investigation_id": 1}, message="quota exhausted"),
    ])
    header = make_client(seeded_world, jobs=jobs).get("/api/investigations/1/dashboard").json()["investigation"]
    assert header["state"] == "failed" and header["failure_reason"] == "quota exhausted"


def test_dashboard_falls_back_to_target_when_no_job_has_the_investigation_id(seeded_world):
    _set(seeded_world, state="running", finished_at=None)
    jobs = _ListedJobs([_job("investigate", "failed", "scattered spider", message="network down")])
    header = make_client(seeded_world, jobs=jobs).get("/api/investigations/1/dashboard").json()["investigation"]
    assert header["state"] == "failed" and header["failure_reason"] == "network down"


def test_dashboard_needs_a_session(seeded_world):
    assert make_client(seeded_world, authenticated=False).get("/api/investigations/1/dashboard").status_code == 401


@pytest.mark.parametrize("bad", ["999999999999999999999", "abc"])
def test_dashboard_rejects_bad_ids(seeded_world, bad):
    assert make_client(seeded_world).get(f"/api/investigations/{bad}/dashboard").status_code == 400


def _give_voice_a_tactic(world):
    """The mini ATT&CK bundle has no tactics; without one no technique reaches the matrix."""
    import json

    bundle = json.loads(world.paths.attack_file.read_text(encoding="utf-8"))
    for obj in bundle["objects"]:
        if obj["id"] == "attack-pattern--00000000-0000-4000-8000-000015660004":
            obj["kill_chain_phases"] = [{"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}]
    world.paths.attack_file.write_text(json.dumps(bundle), encoding="utf-8")


def _dashboard_ids(data):
    return {t["id"] for tactic in data["attack_matrix"]["tactics"] for t in tactic["techniques"]}


def test_dashboard_scope_absent_echoes_everything(seeded_world):
    assert make_client(seeded_world).get("/api/investigations/1/dashboard").json()["scope"] == "everything"


def test_dashboard_scope_filters_the_matrix_and_echoes_it(seeded_world):
    from tests.scope_support import VOICE, add_scoped_claim, add_second_investigation

    _give_voice_a_tactic(seeded_world)
    second = add_second_investigation(seeded_world)
    client = make_client(seeded_world)
    assert _dashboard_ids(client.get("/api/investigations/1/dashboard").json()) == {VOICE}
    mine = client.get("/api/investigations/1/dashboard", params={"scope": "investigation:1"}).json()
    assert mine["scope"] == "investigation:1" and _dashboard_ids(mine) == {VOICE}
    other = client.get("/api/investigations/1/dashboard", params={"scope": f"investigation:{second}"}).json()
    assert other["scope"] == f"investigation:{second}" and _dashboard_ids(other) == set()
    assert other["investigation"]["id"] == 1  # the header never changes with the scope
    add_scoped_claim(seeded_world, second, VOICE, object_name="Spearphishing Voice", object_type="attack-pattern")
    again = client.get("/api/investigations/1/dashboard", params={"scope": f"investigation:{second}"}).json()
    assert _dashboard_ids(again) == {VOICE}


@pytest.mark.parametrize("bad", ["", "everything", "investigation:", "investigation:abc", "investigation:-1",
                                 "investigation:1x", "Investigation:1", "investigation:1;", "investigation: 1"])
def test_dashboard_rejects_an_invalid_scope(seeded_world, bad):
    response = make_client(seeded_world).get("/api/investigations/1/dashboard", params={"scope": bad})
    assert response.status_code == 400 and "scope" in response.json()["error"]


def test_dashboard_scope_of_an_unknown_investigation_is_404(seeded_world):
    client = make_client(seeded_world)
    response = client.get("/api/investigations/1/dashboard", params={"scope": "investigation:999"})
    assert response.status_code == 404 and response.json() == {"error": "unknown investigation"}
    huge = client.get("/api/investigations/1/dashboard", params={"scope": "investigation:" + "9" * 30})
    assert huge.status_code == 400


CSRF = {"X-Argus-CSRF": "1"}


def test_delete_investigation_removes_the_row_and_returns_204(seeded_world):
    client = make_client(seeded_world)
    detail = client.get("/api/investigations/1").json()
    assert detail is not None
    assert client.delete("/api/investigations/1", headers=CSRF).status_code == 204
    assert client.get("/api/investigations/1").status_code == 404


def test_delete_unknown_investigation_returns_404(seeded_world):
    assert make_client(seeded_world).delete("/api/investigations/9999", headers=CSRF).status_code == 404


def test_delete_investigation_needs_the_csrf_header(seeded_world):
    assert make_client(seeded_world).delete("/api/investigations/1").status_code == 403


def test_cancel_endpoint_flags_the_pipeline_to_stop(seeded_world):
    """POST /cancel marks `cancel_requested = 1` on the row so the running pipeline sees
    the stop at its next between-docs check. Returns 202 (accepted — the stop is cooperative,
    not instant)."""
    import sqlite3
    client = make_client(seeded_world)
    r = client.post("/api/investigations/1/cancel", headers=CSRF)
    assert r.status_code == 202
    assert r.json()["status"] == "stop_requested"
    # Row directly: the flag landed.
    conn = sqlite3.connect(str(seeded_world.paths.db_file))
    try:
        [(flag,)] = conn.execute("SELECT cancel_requested FROM investigations WHERE id = 1").fetchall()
        assert flag == 1
    finally:
        conn.close()


def test_cancel_unknown_investigation_returns_404(seeded_world):
    assert make_client(seeded_world).post("/api/investigations/9999/cancel", headers=CSRF).status_code == 404


def test_cancel_endpoint_needs_csrf(seeded_world):
    assert make_client(seeded_world).post("/api/investigations/1/cancel").status_code == 403
