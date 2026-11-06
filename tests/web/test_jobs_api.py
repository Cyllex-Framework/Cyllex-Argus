import asyncio
import json
import pathlib
import socket
import threading
from contextlib import contextmanager

import httpx
import pytest
import uvicorn

from cyllex_argus.web.api import jobs as jobs_api
from cyllex_argus.web.api.jobs import safe_upload_name
from cyllex_argus.web.app import create_app
from cyllex_argus.web.job_handlers import build_handlers
from cyllex_argus.web.jobs import JobManager
from tests.support import QUOTE, SPIDER, ScriptedLLM
from tests.web.conftest import TOKEN, make_client, session_token

CSRF = {"X-Argus-CSRF": "1"}


def _client(world, **kwargs):
    return make_client(world, jobs=JobManager(build_handlers(world.services), inline=True), **kwargs)


def test_investigate_job_runs_and_streams_events(world):
    client = _client(world)
    response = client.post("/api/jobs", json={"kind": "investigate", "target": "Scattered Spider"}, headers=CSRF)
    assert response.status_code == 202
    job = response.json()
    assert job["state"] == "finished" and job["result"]["stage_counts"]["validated"] == 2
    assert client.get(f"/api/jobs/{job['id']}").json()["id"] == job["id"]
    assert client.get("/api/jobs").json()[0]["id"] == job["id"]
    with client.stream("GET", f"/api/jobs/{job['id']}/events") as stream:
        assert stream.headers["content-type"].startswith("text/event-stream")
        body = "".join(stream.iter_text())
    assert "data: " in body and "Collected" in body
    assert body.rstrip().splitlines()[-2] == "event: end"
    with client.stream("GET", f"/api/jobs/{job['id']}/events", params={"after": 999}) as stream:
        tail = "".join(stream.iter_text())
    assert tail.startswith("event: end")


@pytest.mark.parametrize("body, status", [
    ({"kind": "investigate"}, 400),
    ({"kind": "investigate", "target": "   "}, 400),
    ({"kind": "investigate", "target": "x", "max_docs": 0}, 400),
    ({"kind": "nope"}, 400),
    ({"kind": "resume"}, 400),
    ({"kind": "resume", "investigation_id": 999}, 404),
])
def test_job_validation(world, body, status):
    assert _client(world).post("/api/jobs", json=body, headers=CSRF).status_code == status


def test_jobs_need_attack_data_and_claude(world):
    world.paths.attack_file.unlink()
    response = _client(world).post("/api/jobs", json={"kind": "investigate", "target": "X"}, headers=CSRF)
    assert response.status_code == 409 and "ATT&CK" in response.json()["error"]
    assert "Settings → Update ATT&CK" in response.json()["error"]  # the refusal names the fix


def test_jobs_need_claude(world):
    response = _client(world, claude=False).post(
        "/api/jobs", json={"kind": "investigate", "target": "X"}, headers=CSRF)
    assert response.status_code == 503
    assert "restart argus serve" in response.json()["error"]


def test_ingest_needs_attack_data_and_claude(world):
    upload = [("files", ("a.txt", b"report", "text/plain"))]
    no_claude = _client(world, claude=False).post("/api/ingest", headers=CSRF, files=upload)
    assert no_claude.status_code == 503 and "restart argus serve" in no_claude.json()["error"]
    world.paths.attack_file.unlink()
    no_attack = _client(world).post("/api/ingest", headers=CSRF, files=upload)
    assert no_attack.status_code == 409 and "Settings → Update ATT&CK" in no_attack.json()["error"]


def test_attack_update_job_works_without_claude(world):
    job = _client(world, claude=False).post("/api/jobs", json={"kind": "attack_update"}, headers=CSRF).json()
    assert job["state"] == "finished" and job["message"].startswith("ATT&CK loaded")


def test_resume_job(world):
    world.llm = ScriptedLLM(analyst_error_on_call=1)
    paused = world.investigate()
    world.llm = ScriptedLLM()
    job = _client(world).post(
        "/api/jobs", json={"kind": "resume", "investigation_id": paused.investigation_id}, headers=CSRF).json()
    assert job["state"] == "finished"


def test_an_identical_job_is_refused_while_one_is_queued_or_running(world):
    world.llm = ScriptedLLM(analyst_error_on_call=1)
    investigation_id = world.investigate().investigation_id
    gate = threading.Event()

    def held(params, log):
        gate.wait(10)
        return {"state": "finished"}

    jobs = JobManager({kind: held for kind in ("investigate", "resume", "attack_update")})
    client = make_client(world, jobs=jobs)

    def post(body):
        return client.post("/api/jobs", json=body, headers=CSRF)

    accepted = []
    try:
        for body in (
            {"kind": "investigate", "target": "Scattered Spider"},
            {"kind": "investigate", "target": "APT29"},
            {"kind": "investigate", "target": "Scattered Spider", "max_docs": 3},  # other params, another job
            {"kind": "resume", "investigation_id": investigation_id},
            {"kind": "attack_update"},
        ):
            response = post(body)
            assert response.status_code == 202, (body, response.text)
            accepted.append(response.json()["id"])
        for body in (
            {"kind": "investigate", "target": "Scattered Spider"},
            {"kind": "investigate", "target": "  scattered SPIDER "},  # the target compares case-insensitively
            {"kind": "investigate", "target": "Scattered Spider", "max_docs": 3},
            {"kind": "resume", "investigation_id": investigation_id},
            {"kind": "attack_update"},
        ):
            response = post(body)
            assert response.status_code == 409, body
            assert response.json() == {"error": "an identical job is already queued or running"}
        assert len(client.get("/api/jobs").json()) == 5
        gate.set()
        for job_id in accepted:
            assert jobs.wait_until_finished(job_id, timeout=10)["state"] == "finished"
        assert post({"kind": "investigate", "target": "scattered spider"}).status_code == 202  # nothing active now
    finally:
        gate.set()
        jobs.shutdown()


def test_unknown_job(world):
    client = _client(world)
    assert client.get("/api/jobs/missing").status_code == 404
    assert client.get("/api/jobs/missing/events").status_code == 404


@pytest.mark.parametrize("bad_id", [2**63, -(2**63) - 1])
def test_out_of_range_ids_are_rejected_not_crashed(world, bad_id):
    client = _client(world)
    resume = client.post("/api/jobs", json={"kind": "resume", "investigation_id": bad_id}, headers=CSRF)
    assert resume.status_code == 400
    assert client.put(f"/api/sources/{bad_id}", json={"reliability": "A"}, headers=CSRF).status_code == 400


def test_largest_and_smallest_ids_are_unknown_not_invalid(world):
    client = _client(world)
    for edge in (2**63 - 1, -(2**63)):
        resume = client.post("/api/jobs", json={"kind": "resume", "investigation_id": edge}, headers=CSRF)
        assert resume.status_code == 404
        assert client.put(f"/api/sources/{edge}", json={"reliability": "A"}, headers=CSRF).status_code == 404


def test_ingest_upload_sanitizes_names(world):
    client = _client(world)
    content = f"Memo\n\nScattered Spider {QUOTE}.".encode()
    response = client.post(
        "/api/ingest", headers=CSRF, data={"target": "Scattered Spider"},
        files=[("files", ("../../evil memo.txt", content, "text/plain"))],
    )
    assert response.status_code == 202, response.text
    job = response.json()
    assert job["state"] == "finished" and job["result"]["stage_counts"] == {"validated": 1}
    [saved] = list((world.paths.home / "uploads").iterdir())
    assert saved.name.endswith("-evil_memo.txt") and saved.parent == world.paths.home / "uploads"


def test_ingest_rejects_oversize_and_too_many(world):
    world.config.limits.max_download_bytes = 10
    client = _client(world)
    too_big = client.post("/api/ingest", headers=CSRF, files=[("files", ("a.txt", b"x" * 11, "text/plain"))])
    assert too_big.status_code == 400 and "size limit" in too_big.json()["error"]
    uploads = world.paths.home / "uploads"
    assert not uploads.exists() or list(uploads.iterdir()) == []
    many = [("files", (f"{i}.txt", b"x", "text/plain")) for i in range(21)]
    assert client.post("/api/ingest", headers=CSRF, files=many).status_code == 400
    assert client.post("/api/ingest", headers=CSRF, data={"target": "x"}).status_code == 400


def _uploaded_files(world):
    uploads = world.paths.home / "uploads"
    return list(uploads.iterdir()) if uploads.exists() else []


def test_ingest_removes_every_saved_file_when_the_job_cannot_be_submitted(world, monkeypatch):
    jobs = JobManager(build_handlers(world.services), inline=True)

    saved_at_submit = []

    def refuse(kind, params):
        saved_at_submit.extend(pathlib.Path(f).exists() for f in params["files"])
        raise RuntimeError("the job manager is shut down")

    monkeypatch.setattr(jobs, "submit", refuse)
    response = make_client(world, jobs=jobs).post(
        "/api/ingest", headers=CSRF,
        files=[("files", ("a.txt", b"first", "text/plain")), ("files", ("b.txt", b"second", "text/plain"))])
    assert saved_at_submit == [True, True]  # both files were on disk when the submit failed
    assert response.status_code == 500 and response.json() == {"error": "internal error"}
    assert _uploaded_files(world) == []


def test_ingest_removes_the_files_already_saved_when_a_later_write_fails(world, monkeypatch):
    real_open = pathlib.Path.open
    opened = []

    def failing_second_open(self, *args, **kwargs):
        if self.parent.name == "uploads":
            opened.append(self)
            if len(opened) == 2:
                raise OSError("disk full")
        return real_open(self, *args, **kwargs)

    monkeypatch.setattr(pathlib.Path, "open", failing_second_open)
    response = make_client(world).post(
        "/api/ingest", headers=CSRF,
        files=[("files", ("a.txt", b"first", "text/plain")), ("files", ("b.txt", b"second", "text/plain"))])
    assert response.status_code == 500 and response.json() == {"error": "internal error"}
    assert len(opened) == 2 and _uploaded_files(world) == []


def test_ingest_saves_and_submits_off_the_event_loop(world):
    on_the_loop = []

    def handler(params, log):
        try:
            asyncio.get_running_loop()
            on_the_loop.append(True)
        except RuntimeError:  # no running loop: this is a worker thread
            on_the_loop.append(False)
        return {"state": "finished", "message": "ok"}

    client = make_client(world, jobs=JobManager({"ingest": handler}, inline=True))
    response = client.post("/api/ingest", headers=CSRF, files=[("files", ("a.txt", b"x" * 100, "text/plain"))])
    assert response.status_code == 202, response.text
    assert on_the_loop == [False]  # a slow upload must not stall SSE streams and other requests


def test_safe_upload_name():
    assert safe_upload_name("../../evil.pdf") == "evil.pdf"
    assert safe_upload_name("C:\\Users\\x\\report (final).pdf") == "report__final_.pdf"
    assert safe_upload_name("con:.txt") == "con_.txt"
    assert safe_upload_name("") == "upload"
    assert safe_upload_name(None) == "upload"
    assert safe_upload_name("..") == "upload"
    assert len(safe_upload_name("a" * 300 + ".pdf")) == 100


def test_update_source_reliability_saves_it_and_recomputes_in_a_job(seeded_world):
    client = _client(seeded_world)
    before = client.get(f"/api/threats/{SPIDER}").json()["facts"][0]["confidence"]
    mandiant = next(s for s in client.get("/api/sources").json() if s["name"] == "Mandiant")
    response = client.put(f"/api/sources/{mandiant['id']}", json={"reliability": "A"}, headers=CSRF)
    assert response.status_code == 200
    body = response.json()
    assert body["reliability"] == "A" and body["name"] == "Mandiant" and "recomputed" not in body
    job = body["job"]
    assert job["kind"] == "recompute" and job["state"] == "finished" and job["result"]["recomputed"] is True
    assert client.get("/api/jobs").json()[0]["id"] == job["id"]
    after = client.get(f"/api/threats/{SPIDER}").json()["facts"][0]["confidence"]
    assert after > before
    assert client.put(f"/api/sources/{mandiant['id']}", json={"reliability": "Z"}, headers=CSRF).status_code == 400
    assert client.put("/api/sources/99999", json={"reliability": "A"}, headers=CSRF).status_code == 404
    assert len(client.get("/api/jobs").json()) == 1  # a refused change queues nothing


def test_update_source_without_attack_data_saves_it_and_the_job_says_nothing_was_recomputed(seeded_world):
    seeded_world.paths.attack_file.unlink()
    client = _client(seeded_world)
    mandiant = next(s for s in client.get("/api/sources").json() if s["name"] == "Mandiant")
    body = client.put(f"/api/sources/{mandiant['id']}", json={"reliability": "B"}, headers=CSRF).json()
    assert body["reliability"] == "B"
    assert body["job"]["state"] == "finished" and body["job"]["result"]["recomputed"] is False
    assert "ATT&CK data is missing" in body["job"]["message"]


def test_update_source_never_recomputes_on_the_request_and_queues_one_recompute_after_a_running_one(seeded_world):
    started, gate = threading.Event(), threading.Event()
    seen = []

    def recompute(params, log):
        services = seeded_world.services()
        try:
            seen.append(services.store.get_publisher(mandiant["id"]).reliability)
        finally:
            services.close()
        started.set()
        gate.wait(10)
        return {"state": "finished", "recomputed": True}

    jobs = JobManager({"recompute": recompute})
    client = make_client(seeded_world, jobs=jobs)
    mandiant = next(s for s in client.get("/api/sources").json() if s["name"] == "Mandiant")
    try:
        first = client.put(f"/api/sources/{mandiant['id']}", json={"reliability": "A"}, headers=CSRF)
        assert first.status_code == 200 and first.json()["job"]["state"] == "queued"
        assert started.wait(5)
        # The running recompute already read "A"; the next change must get a recompute of its own, after it.
        second = client.put(f"/api/sources/{mandiant['id']}", json={"reliability": "C"}, headers=CSRF).json()
        assert second["reliability"] == "C" and second["job"]["id"] != first.json()["job"]["id"]
        # The UI shows the new value at once, while the recompute is still running.
        assert next(s for s in client.get("/api/sources").json() if s["name"] == "Mandiant")["reliability"] == "C"
        # A change while a recompute is still queued joins it: that one has not read anything yet.
        third = client.put(f"/api/sources/{mandiant['id']}", json={"reliability": "D"}, headers=CSRF).json()
        assert third["job"]["id"] == second["job"]["id"]
        gate.set()
        assert jobs.wait_until_finished(second["job"]["id"], timeout=10)["state"] == "finished"
        assert seen == ["A", "D"]
        assert len(jobs.list()) == 2
    finally:
        gate.set()
        jobs.shutdown()


@contextmanager
def live_server(world, jobs):
    """The app on a real loopback socket: Starlette's TestClient buffers a whole response, so it cannot show a live stream."""
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen()  # connections queue up until uvicorn accepts them, so there is nothing to poll for
    port = sock.getsockname()[1]
    app = create_app(world.services, token=TOKEN, port=port, jobs=jobs, claude_available=lambda: True)
    server = uvicorn.Server(uvicorn.Config(app, log_level="warning"))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    try:
        with httpx.Client(base_url=f"http://127.0.0.1:{port}", timeout=5, headers={"X-Argus-Token": session_token(world)}) as client:
            yield client
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        sock.close()


def test_live_event_stream_delivers_events_and_keepalives_while_a_job_runs(world, monkeypatch):
    monkeypatch.setattr(jobs_api, "_KEEPALIVE_SECONDS", 0.2)
    gate = threading.Event()

    def gated(params, log):
        log("step 1")
        gate.wait(10)
        log("step 2")
        return {"state": "finished", "message": "done"}

    jobs = JobManager({"gated": gated})
    try:
        with live_server(world, jobs) as client:
            job = jobs.submit("gated", {})
            with client.stream("GET", f"/api/jobs/{job['id']}/events") as stream:
                assert stream.status_code == 200
                assert stream.headers["content-type"].startswith("text/event-stream")
                chunks = stream.iter_text()
                received = ""
                while "step 1" not in received:
                    received += next(chunks)
                assert not gate.is_set() and "step 2" not in received  # the first event arrived while the job was blocked
                while ": keepalive" not in received:
                    received += next(chunks)
                assert not gate.is_set()  # and so did a keepalive
                gate.set()
                received += "".join(chunks)  # step 2, the end event, then the stream closes
    finally:
        gate.set()
        jobs.shutdown()
    frames = [frame for frame in received.split("\n\n") if frame]
    assert all(frame.startswith(("id: ", ": keepalive", "event: end")) for frame in frames)
    assert frames[0].startswith("id: 1\n") and frames[-1].startswith("event: end\n")
    assert ": keepalive" in frames
    events = [json.loads(frame.split("data: ", 1)[1]) for frame in frames if frame.startswith("id: ")]
    assert [(e["seq"], e["message"]) for e in events] == [(1, "step 1"), (2, "step 2")]  # none duplicated
    end = json.loads(frames[-1].split("data: ", 1)[1])
    assert end["id"] == job["id"] and end["state"] == "finished" and end["message"] == "done"


def test_default_job_manager_is_threaded(world):
    client = make_client(world)
    jobs = client.app.state.jobs
    assert isinstance(jobs, JobManager)
    job = client.post("/api/jobs", json={"kind": "attack_update"}, headers=CSRF).json()
    assert jobs.wait_until_finished(job["id"], timeout=10)["state"] == "finished"
    jobs.shutdown()
