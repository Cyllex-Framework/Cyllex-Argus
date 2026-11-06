"""Behaviour of EnrichmentRunner: default-off, trace recording, type-safety."""

from __future__ import annotations

import sqlite3

import pytest

from cyllex_argus.config.settings import EnricherConfig, EnrichmentConfig
from cyllex_argus.enrichment import (
    EnrichmentDisabledError,
    EnrichmentFinding,
    EnrichmentRequest,
    EnrichmentResult,
    EnrichmentRunner,
    EnrichmentUnavailable,
)
from cyllex_argus.knowledge.schema import MIGRATIONS
from cyllex_argus.knowledge.trace import SQLiteTraceRecorder


class StubEnricher:
    name = "stub"
    description = "Returns a fixed finding; makes no network call."
    outbound = "Nothing leaves the machine."
    supported_types = ("domain-name",)

    def __init__(self) -> None:
        self.calls = 0

    def enrich(self, request: EnrichmentRequest) -> EnrichmentResult:
        self.calls += 1
        return EnrichmentResult(
            request=request,
            findings=[EnrichmentFinding(source=self.name, key="k", value=request.indicator)],
            duration_ms=1,
        )


def _runner(enabled: bool, enricher: StubEnricher | None = None) -> tuple[EnrichmentRunner, StubEnricher]:
    stub = enricher or StubEnricher()
    cfg = EnrichmentConfig(enrichers={"stub": EnricherConfig(enabled=enabled)})
    return EnrichmentRunner(cfg, {"stub": stub}), stub


def test_disabled_by_default_refuses_without_touching_the_enricher():
    runner, stub = _runner(enabled=False)
    with pytest.raises(EnrichmentDisabledError, match="disabled"):
        runner.enrich(EnrichmentRequest("example.com", "domain-name"), "stub")
    assert stub.calls == 0


def test_enabled_runner_dispatches_and_returns_findings():
    runner, stub = _runner(enabled=True)
    result = runner.enrich(EnrichmentRequest("example.com", "domain-name"), "stub")
    assert stub.calls == 1
    assert [f.value for f in result.findings] == ["example.com"]
    assert result.error is None


def test_unknown_enricher_is_refused_up_front():
    runner, _ = _runner(enabled=True)
    with pytest.raises(EnrichmentUnavailable, match="unknown"):
        runner.enrich(EnrichmentRequest("example.com", "domain-name"), "not-registered")


def test_unsupported_type_is_refused_before_the_enricher_runs():
    runner, stub = _runner(enabled=True)
    with pytest.raises(EnrichmentUnavailable, match="ipv4-addr"):
        runner.enrich(EnrichmentRequest("1.1.1.1", "ipv4-addr"), "stub")
    assert stub.calls == 0


def test_enabled_names_lists_only_opted_in_enrichers():
    cfg = EnrichmentConfig(enrichers={
        "a": EnricherConfig(enabled=True),
        "b": EnricherConfig(enabled=False),
    })
    runner = EnrichmentRunner(cfg, {"a": StubEnricher(), "b": StubEnricher()})
    assert runner.enabled_names() == ["a"]


def test_outbound_message_is_included_in_the_disabled_error():
    """Error message must tell the operator exactly what would leave if they opt in."""
    runner, _ = _runner(enabled=False)
    with pytest.raises(EnrichmentDisabledError) as info:
        runner.enrich(EnrichmentRequest("example.com", "domain-name"), "stub")
    assert "Nothing leaves the machine." in str(info.value)


def test_trace_records_a_pipeline_event_when_wired(tmp_path):
    """When investigation_id and trace are both provided, enrichment writes a trace event."""
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    db.execute("CREATE TABLE schema_version (version INTEGER)")
    for sql in MIGRATIONS:
        db.executescript(sql)
    db.execute("INSERT INTO investigations (target, target_key, started_at, state) VALUES (?, ?, ?, ?)",
               ("x", "x", "2026-01-01T00:00:00Z", "finished"))
    db.commit()
    inv_id = db.execute("SELECT id FROM investigations").fetchone()[0]

    cfg = EnrichmentConfig(enrichers={"stub": EnricherConfig(enabled=True)})
    recorder = SQLiteTraceRecorder(db, retain_raw=False)
    runner = EnrichmentRunner(cfg, {"stub": StubEnricher()}, trace=recorder, investigation_id=inv_id)
    runner.enrich(EnrichmentRequest("example.com", "domain-name"), "stub")

    rows = db.execute("SELECT stage, decision, reason FROM pipeline_events").fetchall()
    assert len(rows) == 1
    assert rows[0]["stage"] == "enrichment"
    assert rows[0]["decision"] == "enriched"
    assert "stub" in rows[0]["reason"] and "example.com" in rows[0]["reason"]


def test_error_result_is_traced_as_failed(tmp_path):
    class FailingEnricher(StubEnricher):
        def enrich(self, request):
            return EnrichmentResult(request=request, error="network down")

    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    db.execute("CREATE TABLE schema_version (version INTEGER)")
    for sql in MIGRATIONS:
        db.executescript(sql)
    db.execute("INSERT INTO investigations (target, target_key, started_at, state) VALUES (?, ?, ?, ?)",
               ("x", "x", "2026-01-01T00:00:00Z", "finished"))
    db.commit()
    inv_id = db.execute("SELECT id FROM investigations").fetchone()[0]

    cfg = EnrichmentConfig(enrichers={"stub": EnricherConfig(enabled=True)})
    runner = EnrichmentRunner(
        cfg, {"stub": FailingEnricher()},
        trace=SQLiteTraceRecorder(db, retain_raw=False),
        investigation_id=inv_id,
    )
    runner.enrich(EnrichmentRequest("x.example", "domain-name"), "stub")

    row = db.execute("SELECT decision, reason FROM pipeline_events").fetchone()
    assert row["decision"] == "failed"
    assert "network down" in row["reason"]
