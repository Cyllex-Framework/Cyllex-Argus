import threading

import pytest

from cyllex_argus.web.job_handlers import build_handlers
from cyllex_argus.web.jobs import JobManager
from tests.support import QUOTE, SPIDER, ScriptedLLM


def test_investigate_handler_reports_and_logs(world):
    logs = []
    result = build_handlers(world.services)["investigate"]({"target": "Scattered Spider", "max_docs": 2}, logs.append)
    assert result["state"] == "finished" and result["target"] == "Scattered Spider"
    assert sum(result["stage_counts"].values()) == 2
    assert any("Collected" in line for line in logs)


def test_investigate_requires_a_target(world):
    with pytest.raises(ValueError):
        build_handlers(world.services)["investigate"]({"target": "  "}, lambda m: None)


def test_resume_handler(world):
    world.llm = ScriptedLLM(analyst_error_on_call=1)
    paused = world.investigate()
    world.llm = ScriptedLLM()
    result = build_handlers(world.services)["resume"]({"investigation_id": paused.investigation_id}, lambda m: None)
    assert result["state"] == "finished"


def test_ingest_handler(world, tmp_path):
    memo = tmp_path / "memo.txt"
    memo.write_text(f"Memo\n\nScattered Spider {QUOTE}.", encoding="utf-8")
    result = build_handlers(world.services)["ingest"]({"files": [str(memo)], "target": None}, lambda m: None)
    assert result["state"] == "finished" and result["stage_counts"] == {"validated": 1}
    with pytest.raises(ValueError):
        build_handlers(world.services)["ingest"]({"files": []}, lambda m: None)


def test_attack_update_handler(world):
    logs = []
    result = build_handlers(world.services)["attack_update"]({}, logs.append)
    assert result["state"] == "finished"
    assert result["message"].startswith("ATT&CK loaded: 2 techniques, 1 groups, 2 software")
    assert logs[0] == "Downloading MITRE ATT&CK Enterprise"


def _confidences(world):
    services = world.services()
    try:
        return {(a.predicate, a.object_entity_id): a.confidence for a in services.store.assessments_involving(SPIDER)}
    finally:
        services.close()


def test_recompute_handler_rescores_every_assessment(seeded_world):
    before = _confidences(seeded_world)
    services = seeded_world.services()
    try:
        services.store.set_publisher_reliability("Mandiant", "A")
        total = len(services.store.assessment_keys())
    finally:
        services.close()
    logs = []
    result = build_handlers(seeded_world.services)["recompute"]({}, logs.append)
    assert result["state"] == "finished" and result["recomputed"] is True
    assert result["message"] == f"Recomputed {total} assessment(s)."
    assert logs == [f"Recomputing {total} assessment(s)", result["message"]]
    after = _confidences(seeded_world)
    assert before and after.keys() == before.keys() and any(after[key] > before[key] for key in before)


def test_recompute_handler_skips_cleanly_without_attack_data(world):
    world.paths.attack_file.unlink()
    logs = []
    result = build_handlers(world.services)["recompute"]({}, logs.append)
    assert result["state"] == "finished" and result["recomputed"] is False
    assert result["message"].startswith("Confidences were not recomputed: ATT&CK data is missing")
    assert logs == [result["message"]]


def test_handlers_open_and_close_their_services_on_the_worker_thread(world):
    opened = []

    def factory():
        services = world.services()
        close = services.close
        record = {"thread": threading.current_thread().name, "closed": False}

        def closing():
            record["closed"] = True
            close()

        services.close = closing
        opened.append(record)
        return services

    jobs = JobManager(build_handlers(factory))
    try:
        update = jobs.submit("attack_update", {})["id"]
        investigate = jobs.submit("investigate", {"target": "Scattered Spider", "max_docs": 2})["id"]
        missing = jobs.submit("resume", {"investigation_id": 999})["id"]
        states = {i: jobs.wait_until_finished(i, timeout=30) for i in (update, investigate, missing)}
    finally:
        jobs.shutdown()
    # a SQLite connection used off its own thread would fail these jobs with a ProgrammingError
    assert states[update]["state"] == "finished", states[update]["message"]
    assert states[investigate]["state"] == "finished", states[investigate]["message"]
    assert states[missing]["state"] == "failed" and states[missing]["message"] == "KeyError: 999"
    assert [r["thread"] for r in opened] == ["argus-jobs"] * 3
    assert all(r["closed"] for r in opened)


def test_a_rate_limit_during_a_resume_job_pauses_it_and_a_later_resume_finishes(world):
    world.llm = ScriptedLLM(analyst_error_on_call=1)
    paused = world.investigate()
    assert paused.state.value == "paused"
    jobs = JobManager(build_handlers(world.services), inline=True)
    params = {"investigation_id": paused.investigation_id}
    world.llm = ScriptedLLM(analyst_error_on_call=1)
    again = jobs.submit("resume", params)
    assert again["state"] == "paused" and again["result"]["state"] == "paused"
    assert again["message"].startswith("Paused: ")
    # the pipeline's CLI hint ("Re-run the same command") makes no sense in the web UI, which has a Resume button
    assert again["message"].endswith(". Use Resume to continue.") and "Re-run" not in again["message"]
    assert again["result"]["message"] == again["message"]
    world.llm = ScriptedLLM()
    done = jobs.submit("resume", params)
    assert done["state"] == "finished" and done["result"]["investigation_id"] == paused.investigation_id




