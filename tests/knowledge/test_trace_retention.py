"""SQLiteTraceRecorder retention modes: off / errors / full + bool backward compat."""

from __future__ import annotations

import sqlite3

from cyllex_argus.knowledge.schema import MIGRATIONS
from cyllex_argus.knowledge.trace import PipelineEvent, SQLiteTraceRecorder


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    for stmt in MIGRATIONS:
        conn.executescript(stmt)
    return conn


def _event(decision: str) -> PipelineEvent:
    return PipelineEvent(
        investigation_id=1, stage="analyst", decision=decision,
        raw_prompt="PROMPT", raw_response="RESPONSE",
    )


def _raw_count(conn: sqlite3.Connection) -> int:
    return conn.execute(
        "SELECT COUNT(*) FROM pipeline_events "
        "WHERE raw_prompt IS NOT NULL OR raw_response IS NOT NULL"
    ).fetchone()[0]


def test_off_never_stores_raw():
    conn = _conn()
    rec = SQLiteTraceRecorder(conn, retain_raw="off")
    rec.record(_event("validated"))
    rec.record(_event("rejected"))
    assert _raw_count(conn) == 0


def test_full_always_stores_raw():
    conn = _conn()
    rec = SQLiteTraceRecorder(conn, retain_raw="full")
    rec.record(_event("validated"))
    rec.record(_event("rejected"))
    assert _raw_count(conn) == 2


def test_errors_stores_only_on_failure_decisions():
    conn = _conn()
    rec = SQLiteTraceRecorder(conn, retain_raw="errors")
    rec.record(_event("validated"))      # kept counts, no raw
    rec.record(_event("triaged-in"))     # kept counts, no raw
    rec.record(_event("rejected"))       # raw kept
    rec.record(_event("failed"))         # raw kept
    rec.record(_event("parse-error"))    # raw kept
    assert _raw_count(conn) == 3


def test_backward_compat_true_maps_to_full():
    conn = _conn()
    rec = SQLiteTraceRecorder(conn, retain_raw=True)   # legacy bool shape
    rec.record(_event("validated"))
    assert _raw_count(conn) == 1
    assert rec.retain_mode == "full"


def test_backward_compat_false_maps_to_off():
    conn = _conn()
    rec = SQLiteTraceRecorder(conn, retain_raw=False)
    rec.record(_event("rejected"))
    assert _raw_count(conn) == 0
    assert rec.retain_mode == "off"


def test_set_retain_mode_flips_live_without_reconstruction():
    conn = _conn()
    rec = SQLiteTraceRecorder(conn, retain_raw="off")
    rec.record(_event("rejected"))       # stored under 'off' → no raw
    rec.set_retain_mode("errors")
    rec.record(_event("rejected"))       # now kept
    rec.record(_event("validated"))      # still skipped under errors
    assert _raw_count(conn) == 1


def test_purge_raw_only_keeps_events(world):  # noqa: ARG001 — world fixture reused for isolation
    conn = _conn()
    rec = SQLiteTraceRecorder(conn, retain_raw="full")
    for _ in range(4):
        rec.record(_event("rejected"))
    assert conn.execute("SELECT COUNT(*) FROM pipeline_events").fetchone()[0] == 4
    assert _raw_count(conn) == 4
    nulled = rec.purge_raw_only()
    assert nulled == 4
    assert conn.execute("SELECT COUNT(*) FROM pipeline_events").fetchone()[0] == 4  # rows survive
    assert _raw_count(conn) == 0
