"""The /api/watchers surface: roles, ownership, and per-user unseen."""

from datetime import UTC, datetime, timedelta

from cyllex_argus.knowledge.models import ChangeKind, Role, WatcherChange
from cyllex_argus.web import auth_core
from tests.web.conftest import make_client


def _client(world, role=Role.ADMIN):
    client = make_client(world, role=role)
    client.headers["X-Argus-CSRF"] = "1"  # writes require the CSRF header
    return client


def _client_for(world, username, role):
    """A client authenticated as a specific named user (for distinct-owner tests)."""
    services = world.services()
    try:
        store = services.store
        user = store.get_user_by_username(username) or store.create_user(
            username, auth_core.hash_password("x"), role)
        token, hashed = auth_core.new_session_token()
        store.create_session(user.id, hashed, datetime.now(UTC) + timedelta(days=1))
    finally:
        services.close()
    client = make_client(world, authenticated=False)
    client.headers["X-Argus-Token"] = token
    client.headers["X-Argus-CSRF"] = "1"
    return client


def _create(client, target="APT29"):
    return client.post("/api/watchers", json={"target": target})


def test_reader_can_list_but_not_create(world):
    reader = _client(world, Role.READER)
    assert reader.get("/api/watchers").status_code == 200
    assert _create(reader).status_code == 403  # role, not CSRF


def test_operator_can_create_and_list(world):
    op = _client(world, Role.OPERATOR)
    created = _create(op)
    assert created.status_code == 201
    assert created.json()["target"] == "APT29"
    assert [w["target"] for w in op.get("/api/watchers").json()] == ["APT29"]


def test_non_owner_operator_refused_admin_allowed(world):
    owner = _client_for(world, "alice", Role.OPERATOR)
    wid = _create(owner).json()["id"]
    other = _client_for(world, "bob", Role.OPERATOR)  # a different operator, not the owner
    assert other.put(f"/api/watchers/{wid}/enabled", json={"enabled": False}).status_code == 403
    assert other.delete(f"/api/watchers/{wid}").status_code == 403
    admin = _client(world, Role.ADMIN)
    assert admin.put(f"/api/watchers/{wid}/enabled", json={"enabled": False}).status_code == 200
    assert admin.delete(f"/api/watchers/{wid}").status_code == 204


def test_changes_feed_is_reader_visible(world):
    reader = _client(world, Role.READER)
    assert reader.get("/api/watchers/changes").status_code == 200
    assert reader.get("/api/watchers/changes").json() == []


def test_unseen_count_is_per_user_and_seen_reduces_it(world):
    op = _client(world, Role.OPERATOR)
    wid = _create(op).json()["id"]
    services = world.services()
    try:
        ids = services.store.add_changes(wid, [
            WatcherChange(id=0, watcher_id=0, kind=ChangeKind.NEW, ref_key="a",
                          detected_at=datetime(2026, 10, 31, 10, 0)),
            WatcherChange(id=0, watcher_id=0, kind=ChangeKind.NEW, ref_key="b",
                          detected_at=datetime(2026, 10, 31, 10, 1)),
        ])
    finally:
        services.close()

    mine = next(w for w in op.get("/api/watchers").json() if w["id"] == wid)
    assert mine["unseen_count"] == 2
    assert op.post(f"/api/watchers/{wid}/seen", json={"last_change_id": ids[-1]}).status_code == 204
    mine = next(w for w in op.get("/api/watchers").json() if w["id"] == wid)
    assert mine["unseen_count"] == 0
    admin = _client(world, Role.ADMIN)
    his = next(w for w in admin.get("/api/watchers").json() if w["id"] == wid)
    assert his["unseen_count"] == 2  # unaffected by the operator marking seen


# -- run params (max docs / concurrency) and run-now ---------------------------------------------


class _RecordingJobs:
    """Captures submit() so a test can assert what an endpoint queued without running it."""
    def __init__(self):
        self.calls = []

    def submit(self, kind, params, dedupe_key=None):
        self.calls.append((kind, params, dedupe_key))
        return {"id": "job-1"}

    def shutdown(self):
        pass


def _admin_recording(world, jobs):
    client = make_client(world, role=Role.ADMIN, jobs=jobs)
    client.headers["X-Argus-CSRF"] = "1"
    return client


def test_create_accepts_run_params(world):
    op = _client(world, Role.OPERATOR)
    created = op.post("/api/watchers", json={"target": "LockBit", "max_docs": 25, "concurrency": 4})
    assert created.status_code == 201
    assert created.json()["max_docs"] == 25
    assert created.json()["concurrency"] == 4
    [w] = [w for w in op.get("/api/watchers").json() if w["target"] == "LockBit"]
    assert w["max_docs"] == 25 and w["concurrency"] == 4


def test_create_rejects_out_of_range_concurrency(world):
    op = _client(world, Role.OPERATOR)
    # The app maps request-validation failures to 400 with a readable message (not FastAPI's 422).
    r = op.post("/api/watchers", json={"target": "X", "concurrency": 99})
    assert r.status_code == 400
    assert "concurrency" in r.json()["error"]


def test_run_now_fires_investigation_tagged_with_the_watcher(world):
    jobs = _RecordingJobs()
    client = _admin_recording(world, jobs)
    wid = client.post("/api/watchers", json={"target": "APT29", "max_docs": 10, "concurrency": 3}).json()["id"]
    assert client.post(f"/api/watchers/{wid}/run-now").status_code == 200
    [(kind, params, _dedupe)] = jobs.calls
    assert kind == "investigate"
    assert params["target"] == "APT29"
    assert params["watcher_id"] == wid
    assert params["concurrency"] == 3
    assert params["max_docs"] == 10


def test_run_now_unknown_is_404(world):
    client = _admin_recording(world, _RecordingJobs())
    assert client.post("/api/watchers/999/run-now").status_code == 404


def test_run_now_forbidden_for_non_owner_operator(world):
    owner = _client_for(world, "alice", Role.OPERATOR)
    wid = _create(owner).json()["id"]
    other = _client_for(world, "bob", Role.OPERATOR)
    assert other.post(f"/api/watchers/{wid}/run-now").status_code == 403
