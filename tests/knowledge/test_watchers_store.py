"""Store CRUD for watchers (atop the scheduled_investigations table)."""

from datetime import datetime

from cyllex_argus.knowledge.models import Role


def _user(store, name):
    return store.create_user(name, "hash", Role.OPERATOR).id


def _mk(store, target="APT29", created_by=None):
    return store.create_watcher(
        target=target, cron_expr="0 8 * * *", created_by=created_by,
        next_run_at=datetime(2026, 11, 1, 8, 0),
    )


def test_create_then_get_roundtrip(store):
    uid = _user(store, "alice")
    w = _mk(store, created_by=uid)
    got = store.get_watcher(w.id)
    assert got is not None
    assert got.target == "APT29"
    assert got.cron_expr == "0 8 * * *"
    assert got.created_by == uid
    assert got.enabled is True


def test_create_is_idempotent_per_target(store):
    a, b = _user(store, "alice"), _user(store, "bob")
    first = _mk(store, created_by=a)
    second = _mk(store, created_by=b)  # same target, different caller
    assert second.id == first.id
    assert len(store.list_watchers()) == 1
    assert store.watcher_owner(first.id) == a  # original owner kept


def test_disable_then_get(store):
    w = _mk(store, created_by=_user(store, "alice"))
    store.set_watcher_enabled(w.id, False)
    assert store.get_watcher(w.id).enabled is False


def test_list_watchers_spans_owners(store):
    a, b = _user(store, "alice"), _user(store, "bob")
    _mk(store, target="APT29", created_by=a)
    _mk(store, target="LockBit", created_by=b)
    owners = {w.target: w.created_by for w in store.list_watchers()}
    assert owners == {"APT29": a, "LockBit": b}


def test_delete_removes_watcher_and_its_rows_only(store):
    w = _mk(store, created_by=_user(store, "alice"))
    # A child row in each dependent table, plus an unrelated entity that must survive.
    store._conn.execute(
        "INSERT INTO watcher_changes (watcher_id, kind, ref_key, detected_at) VALUES (?,?,?,?)",
        (w.id, "new", "k", "2026-10-31T10:00:00"),
    )
    store._conn.execute(
        "INSERT INTO watcher_snapshots (watcher_id, ref_key, status, updated_at) VALUES (?,?,?,?)",
        (w.id, "k", "corroborated", "2026-10-31T10:00:00"),
    )
    store._conn.execute(
        "INSERT INTO entities (id, stix_type, canonical_name) VALUES (?,?,?)",
        ("intrusion-set--x", "intrusion-set", "APT29"),
    )
    store._conn.commit()

    assert store.delete_watcher(w.id) is True
    assert store.get_watcher(w.id) is None
    assert store._conn.execute("SELECT COUNT(*) FROM watcher_changes").fetchone()[0] == 0
    assert store._conn.execute("SELECT COUNT(*) FROM watcher_snapshots").fetchone()[0] == 0
    # Knowledge is untouched.
    assert store._conn.execute(
        "SELECT COUNT(*) FROM entities WHERE id = 'intrusion-set--x'"
    ).fetchone()[0] == 1


def test_create_watcher_persists_run_params(store):
    uid = _user(store, "carol")
    w = store.create_watcher(
        target="LockBit", cron_expr="0 8 * * 1", created_by=uid,
        next_run_at=datetime(2026, 11, 1, 8, 0), max_docs=25, concurrency=4,
    )
    got = store.get_watcher(w.id)
    assert got is not None
    assert got.max_docs == 25
    assert got.concurrency == 4


def test_schedule_rows_are_visible_as_watchers_with_their_run_params(store):
    # Watchers and schedules share the scheduled_investigations table, so a row created through
    # create_schedule must read back through the watcher accessors carrying its run params.
    store.create_schedule(
        target="Scattered Spider", cron_expr="0 8 * * *", max_docs=10, concurrency=2,
        next_run_at=datetime(2026, 11, 1, 8, 0),
    )
    [w] = [x for x in store.list_watchers() if x.target == "Scattered Spider"]
    assert w.max_docs == 10
    assert w.concurrency == 2
