from cyllex_argus.config.settings import ArgusConfig, LoggingConfig
from tests.support import World


def _trace_after_investigation(tmp_path, retain: bool):
    world = World(tmp_path / "home")
    world.config = ArgusConfig(feeds=[], logging=LoggingConfig(retain_raw_llm=retain))
    services = world.services()
    try:
        report = services.pipeline().investigate("Scattered Spider")
        recorder = services.trace_recorder()
        events = recorder.list_events(report.investigation_id)
        return events, [recorder.raw(e.id) for e in events if e.stage == "analyst"]
    finally:
        services.close()


def test_services_pipeline_records_a_trace(tmp_path):
    events, _ = _trace_after_investigation(tmp_path, retain=False)
    assert {"collector", "analyst", "validator"} <= {e.stage for e in events}


def test_retain_raw_llm_flag_is_honoured(tmp_path):
    _, dropped = _trace_after_investigation(tmp_path / "off", retain=False)
    assert dropped and all(raw is None for raw in dropped)
    _, kept = _trace_after_investigation(tmp_path / "on", retain=True)
    assert kept and all(raw is not None for raw in kept)
