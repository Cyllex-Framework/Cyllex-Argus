import threading
import time

import pytest

from cyllex_argus.web.jobs import DuplicateJobError, JobManager


def _echo(params, log):
    for i in range(params.get("n", 2)):
        log(f"step {i + 1}")
    return {"state": params.get("state", "finished"), "message": params.get("message")}


def _boom(params, log):
    log("about to fail")
    raise RuntimeError("boom")


def test_inline_job_records_events_and_finishes():
    jobs = JobManager({"echo": _echo}, inline=True)
    job = jobs.submit("echo", {"n": 3})
    assert job["state"] == "finished" and job["events"] == 3
    events, state = jobs.events_after(job["id"], 0)
    assert [e["seq"] for e in events] == [1, 2, 3] and state == "finished"
    assert jobs.events_after(job["id"], 2)[0][0]["message"] == "step 3"


def test_paused_and_failed_jobs_do_not_stop_the_manager():
    jobs = JobManager({"echo": _echo, "boom": _boom}, inline=True)
    paused = jobs.submit("echo", {"state": "paused", "message": "limit"})
    failed = jobs.submit("boom", {})
    after = jobs.submit("echo", {})
    assert paused["state"] == "paused" and paused["message"] == "limit"
    assert failed["state"] == "failed" and failed["message"] == "RuntimeError: boom"
    assert after["state"] == "finished"


def test_unknown_kind_and_unknown_job():
    jobs = JobManager({"echo": _echo}, inline=True)
    with pytest.raises(ValueError):
        jobs.submit("nope", {})
    assert jobs.get("missing") is None
    assert jobs.events_after("missing", 0) == ([], None)


def test_list_is_newest_first_and_pruned():
    jobs = JobManager({"echo": _echo}, inline=True, max_jobs=3)
    ids = [jobs.submit("echo", {"n": 0})["id"] for _ in range(5)]
    assert [j["id"] for j in jobs.list()] == list(reversed(ids[-3:]))


def test_threaded_jobs_run_one_at_a_time_in_order():
    running = []
    order = []
    lock = threading.Lock()
    concurrent = {"max": 0}

    def slow(params, log):
        with lock:
            running.append(params["i"])
            concurrent["max"] = max(concurrent["max"], len(running))
        time.sleep(0.05)
        with lock:
            running.remove(params["i"])
            order.append(params["i"])
        return {"state": "finished"}

    jobs = JobManager({"slow": slow})
    ids = [jobs.submit("slow", {"i": i})["id"] for i in range(4)]
    for job_id in ids:
        assert jobs.wait_until_finished(job_id, timeout=5)["state"] == "finished"
    jobs.shutdown()
    assert order == [0, 1, 2, 3]
    assert concurrent["max"] == 1


def test_wait_returns_when_new_events_arrive():
    gate = threading.Event()

    def gated(params, log):
        log("first")
        gate.wait(5)
        log("second")
        return {"state": "finished"}

    jobs = JobManager({"gated": gated})
    job_id = jobs.submit("gated", {})["id"]
    jobs.wait(job_id, after_seq=0, timeout=5)
    events, _ = jobs.events_after(job_id, 0)
    assert events[0]["message"] == "first"
    gate.set()
    assert jobs.wait_until_finished(job_id, timeout=5)["events"] == 2
    jobs.shutdown()


def _workers():
    """The live job worker threads, so a test can compare against a baseline taken before it started its own."""
    return {t for t in threading.enumerate() if t.name == "argus-jobs" and t.is_alive()}


def test_submit_returns_the_queued_job_and_shutdown_stops_the_worker():
    gate = threading.Event()

    def gated(params, log):
        gate.wait(5)
        return {"state": "finished"}

    baseline = _workers()
    jobs = JobManager({"gated": gated})
    first = jobs.submit("gated", {})
    assert first["state"] == "queued" and first["events"] == 0
    gate.set()
    assert jobs.wait_until_finished(first["id"], timeout=5)["state"] == "finished"
    assert len(_workers() - baseline) == 1
    jobs.shutdown()
    jobs.shutdown()  # idempotent
    assert _workers() - baseline == set()
    with pytest.raises(RuntimeError):
        jobs.submit("gated", {})


def test_shutdown_cancels_jobs_that_have_not_started():
    gate = threading.Event()

    def gated(params, log):
        log("started")
        gate.wait(5)
        return {"state": "finished"}

    baseline = _workers()
    jobs = JobManager({"gated": gated})
    running = jobs.submit("gated", {})["id"]
    jobs.wait(running, after_seq=0, timeout=5)  # the worker is inside the first job
    waiting = jobs.submit("gated", {})["id"]
    closer = threading.Thread(target=jobs.shutdown)
    closer.start()
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:  # a submit is refused once shutdown has begun
        try:
            jobs.submit("gated", {})
        except RuntimeError:
            break
    gate.set()
    closer.join(timeout=10)
    assert not closer.is_alive() and _workers() - baseline == set()
    assert jobs.get(running)["state"] == "finished"
    cancelled = jobs.get(waiting)
    assert cancelled["state"] == "failed" and cancelled["message"].startswith("Cancelled")


def test_concurrent_submits_share_one_worker():
    baseline = _workers()
    jobs = JobManager({"echo": _echo})
    barrier = threading.Barrier(8)
    ids = []

    def submit():
        barrier.wait(5)
        ids.append(jobs.submit("echo", {"n": 0})["id"])

    threads = [threading.Thread(target=submit) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)
    assert len(ids) == 8
    assert len(_workers() - baseline) == 1
    for job_id in ids:
        assert jobs.wait_until_finished(job_id, timeout=5)["state"] == "finished"
    jobs.shutdown()
    assert _workers() - baseline == set()


def test_a_dedupe_key_refuses_an_identical_active_job_but_not_a_finished_one():
    gate = threading.Event()

    def held(params, log):
        gate.wait(10)
        return {"state": "finished"}

    jobs = JobManager({"held": held, "echo": _echo})
    try:
        first = jobs.submit("held", {}, dedupe_key=("a",))
        with pytest.raises(DuplicateJobError):
            jobs.submit("held", {"other": "params"}, dedupe_key=("a",))  # queued or running, the key decides
        jobs.submit("held", {}, dedupe_key=("b",))
        jobs.submit("echo", {}, dedupe_key=("a",))  # another kind
        jobs.submit("held", {})
        jobs.submit("held", {})  # no key: never refused
        assert len(jobs.list()) == 5
        gate.set()
        assert jobs.wait_until_finished(first["id"], timeout=10)["state"] == "finished"
        assert jobs.submit("held", {}, dedupe_key=("a",))["kind"] == "held"  # the earlier one is done
    finally:
        gate.set()
        jobs.shutdown()


def test_coalesce_joins_a_queued_job_but_never_a_running_one():
    started = threading.Event()
    gate = threading.Event()

    def held(params, log):
        started.set()
        gate.wait(10)
        return {"state": "finished"}

    jobs = JobManager({"held": held, "echo": _echo})
    try:
        running = jobs.submit("held", {}, dedupe_key=(), coalesce=True)
        assert started.wait(5)
        # The running job may have read its inputs already, so a new submit must queue another run after it.
        queued = jobs.submit("held", {}, dedupe_key=(), coalesce=True)
        assert queued["id"] != running["id"] and queued["state"] == "queued"
        # A job that has not started yet sees whatever changed before it runs: later submits join it.
        assert jobs.submit("held", {}, dedupe_key=(), coalesce=True)["id"] == queued["id"]
        assert jobs.submit("held", {}, dedupe_key=("other",), coalesce=True)["id"] != queued["id"]
        assert jobs.submit("echo", {}, dedupe_key=(), coalesce=True)["kind"] == "echo"
        assert len(jobs.list()) == 4
        gate.set()
        assert jobs.wait_until_finished(queued["id"], timeout=10)["state"] == "finished"
    finally:
        gate.set()
        jobs.shutdown()


def test_concurrent_coalesced_submits_queue_exactly_one_job():
    gate = threading.Event()
    jobs = JobManager({"held": lambda params, log: gate.wait(10) and {}, "block": lambda params, log: gate.wait(10) and {}})
    blocker = jobs.submit("block", {})  # keeps the worker busy, so the coalesced jobs stay queued
    barrier = threading.Barrier(8)
    ids = []

    def submit():
        barrier.wait(5)
        ids.append(jobs.submit("held", {}, dedupe_key=(), coalesce=True)["id"])

    threads = [threading.Thread(target=submit) for _ in range(8)]
    try:
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)
        assert len(ids) == 8 and len(set(ids)) == 1
        assert [job["id"] for job in jobs.list()] == [ids[0], blocker["id"]]
    finally:
        gate.set()
        jobs.shutdown()


def test_concurrent_identical_submits_admit_exactly_one():
    gate = threading.Event()
    jobs = JobManager({"held": lambda params, log: gate.wait(10) and {}})
    barrier = threading.Barrier(8)
    outcomes = []

    def submit():
        barrier.wait(5)
        try:
            jobs.submit("held", {}, dedupe_key=("same",))
            outcomes.append("accepted")
        except DuplicateJobError:
            outcomes.append("refused")

    threads = [threading.Thread(target=submit) for _ in range(8)]
    try:
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)
        assert sorted(outcomes) == ["accepted"] + ["refused"] * 7
    finally:
        gate.set()
        jobs.shutdown()


def _exit(params, log):
    log("about to exit")
    raise SystemExit(*params.get("args", (3,)))


def test_inline_interrupt_ends_the_job_failed_and_still_propagates():
    jobs = JobManager({"exit": _exit}, inline=True)
    with pytest.raises(SystemExit):
        jobs.submit("exit", {})
    [job] = jobs.list()
    assert job["state"] == "failed" and job["message"] == "Interrupted: SystemExit: 3"
    assert job["finished_at"] is not None and job["events"] == 1


def test_interrupted_job_does_not_strand_the_queue():
    baseline = _workers()
    jobs = JobManager({"exit": _exit, "echo": _echo})
    interrupted = jobs.submit("exit", {})["id"]
    after = jobs.submit("echo", {})["id"]
    assert jobs.wait_until_finished(interrupted, timeout=5)["state"] == "failed"
    assert jobs.get(interrupted)["message"] == "Interrupted: SystemExit: 3"
    assert jobs.wait_until_finished(after, timeout=5)["state"] == "finished"
    jobs.shutdown()
    assert _workers() - baseline == set()


def test_interrupt_without_detail_names_only_the_type():
    jobs = JobManager({"exit": _exit}, inline=True)
    with pytest.raises(SystemExit):
        jobs.submit("exit", {"args": ()})
    assert jobs.list()[0]["message"] == "Interrupted: SystemExit"
