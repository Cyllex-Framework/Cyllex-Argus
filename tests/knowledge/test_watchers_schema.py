"""Schema migrations that back the Watchers feature (Delivery 1)."""

import sqlite3

from cyllex_argus.knowledge.sqlite_store import SQLiteStore


def _columns(con: sqlite3.Connection, table: str) -> set[str]:
    return {row[1] for row in con.execute(f"PRAGMA table_info({table})")}


def _tables(con: sqlite3.Connection) -> set[str]:
    return {row[0] for row in con.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}


def _open(tmp_path) -> sqlite3.Connection:
    db = tmp_path / "argus.db"
    SQLiteStore(db)  # constructor applies all migrations
    return sqlite3.connect(db)


def test_scheduled_investigations_has_created_by(tmp_path):
    con = _open(tmp_path)
    assert "created_by" in _columns(con, "scheduled_investigations")


def test_investigations_has_watcher_id(tmp_path):
    con = _open(tmp_path)
    assert "watcher_id" in _columns(con, "investigations")


def test_watcher_tables_exist(tmp_path):
    con = _open(tmp_path)
    assert {"watcher_changes", "watcher_snapshots", "watcher_seen"} <= _tables(con)


def test_watcher_changes_columns(tmp_path):
    con = _open(tmp_path)
    expected = {
        "id", "watcher_id", "entity_id", "kind", "ref_key", "subject", "predicate",
        "object", "from_status", "to_status", "citation_json", "detected_at",
        "run_job_id", "delivered_at", "delivered_channels",
    }
    assert expected <= _columns(con, "watcher_changes")


def test_watcher_snapshots_columns(tmp_path):
    con = _open(tmp_path)
    assert {"watcher_id", "ref_key", "status", "updated_at"} <= _columns(con, "watcher_snapshots")


def test_watcher_seen_columns(tmp_path):
    con = _open(tmp_path)
    assert {"user_id", "watcher_id", "last_seen_change_id"} <= _columns(con, "watcher_seen")
