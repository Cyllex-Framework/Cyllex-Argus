"""Reconcile a finished run into watcher change events."""

from datetime import datetime
from types import SimpleNamespace

from cyllex_argus.config.settings import ArgusConfig
from cyllex_argus.knowledge.models import AssessmentStatus, ChangeKind, InvestigationState, Role
from cyllex_argus.knowledge.profile import EntityRef, FactView, Profile
from cyllex_argus.watchers import runner


def _entity_row(store, entity_id="intrusion-set--apt29", name="APT29"):
    store._conn.execute(
        "INSERT INTO entities (id, stix_type, canonical_name) VALUES (?, ?, ?)",
        (entity_id, "intrusion-set", name),
    )
    store._conn.commit()
    return entity_id


def _fact(obj="WellMess", status=AssessmentStatus.CORROBORATED):
    return FactView(
        subject=EntityRef(id="intrusion-set--apt29", stix_type="intrusion-set", name="APT29"),
        predicate="uses",
        object=EntityRef(id=obj, stix_type="malware", name=obj),
        status=status, confidence=80, admiralty="B2", citations=[],
    )


def _patch_profile(monkeypatch, facts):
    profile = Profile(
        entity=EntityRef(id="intrusion-set--apt29", stix_type="intrusion-set", name="APT29"),
        aliases=[], facts=facts,
    )
    monkeypatch.setattr(runner, "build_profile", lambda store, entity: profile)


def _watcher(store, target="APT29"):
    uid = store.create_user("alice", "h", Role.OPERATOR).id
    return store.create_watcher(
        target=target, cron_expr="0 8 * * *", created_by=uid,
        next_run_at=datetime(2026, 11, 1, 8, 0),
    )


def test_no_watcher_returns_empty(store, monkeypatch):
    _entity_row(store)
    _patch_profile(monkeypatch, [_fact()])
    out = runner.reconcile_after_run(
        store, ArgusConfig(), entity_id="intrusion-set--apt29", target="APT29", run_job_id="j1",
    )
    assert out == []  # no watcher for this target


def test_persists_changes_and_advances_snapshot(store, monkeypatch):
    w = _watcher(store)
    _entity_row(store)
    _patch_profile(monkeypatch, [_fact()])
    out = runner.reconcile_after_run(
        store, ArgusConfig(), entity_id="intrusion-set--apt29", target="APT29", run_job_id="j1",
    )
    assert len(out) == 1
    assert store.list_changes(watcher_id=w.id, limit=10)  # persisted
    assert store.get_snapshot(w.id)  # snapshot advanced


def test_double_count_guard(store, monkeypatch):
    _watcher(store)
    _entity_row(store)
    _patch_profile(monkeypatch, [_fact()])
    first = runner.reconcile_after_run(
        store, ArgusConfig(), entity_id="intrusion-set--apt29", target="APT29", run_job_id="j1",
    )
    second = runner.reconcile_after_run(
        store, ArgusConfig(), entity_id="intrusion-set--apt29", target="APT29", run_job_id="j2",
    )
    assert len(first) == 1
    assert second == []  # snapshot already advanced; nothing new


def test_fact_crossing_floor_fires_new(store, monkeypatch):
    """A fact below the reliability floor is not recorded in the snapshot, so when it later
    becomes credible (crosses the floor) it is reported as NEW rather than silently swallowed."""
    w = _watcher(store)
    _entity_row(store)
    holder = {"facts": [_fact(obj="WellMess")]}
    holder["facts"][0].admiralty = "D2"  # below the C floor
    monkeypatch.setattr(runner, "build_profile", lambda store, entity: Profile(
        entity=EntityRef(id="intrusion-set--apt29", stix_type="intrusion-set", name="APT29"),
        aliases=[], facts=holder["facts"],
    ))
    first = runner.reconcile_after_run(
        store, ArgusConfig(), entity_id="intrusion-set--apt29", target="APT29", run_job_id="j1")
    assert first == []                       # below floor: no event
    assert store.get_snapshot(w.id) == {}    # and NOT recorded in the snapshot

    holder["facts"] = [_fact(obj="WellMess")]  # same triple, now B2 (credible)
    second = runner.reconcile_after_run(
        store, ArgusConfig(), entity_id="intrusion-set--apt29", target="APT29", run_job_id="j2")
    assert len(second) == 1
    assert second[0].kind is ChangeKind.NEW


def test_reconcile_finds_watcher_by_resolved_entity(store, monkeypatch):
    """A manual run whose target string differs from the watcher's (an alias / different
    spelling) but resolves to the same entity still advances that watcher — so the next
    scheduled run does not re-report the hand-run findings as new."""
    w = _watcher(store, target="APT29")
    _entity_row(store, entity_id="intrusion-set--apt29", name="APT29")
    _patch_profile(monkeypatch, [_fact()])
    out = runner.reconcile_after_run(
        store, ArgusConfig(), entity_id="intrusion-set--apt29", target="Cozy Bear", run_job_id="j1")
    assert len(out) == 1
    assert out[0].watcher_id == w.id
    assert store.get_snapshot(w.id)


def test_report_gate_skips_non_finished(store):
    report = SimpleNamespace(state=InvestigationState.PAUSED, investigation_id=1, target="APT29")
    assert runner.reconcile_report(store, ArgusConfig(), report) == []


def test_report_finished_triggers_reconcile(store, monkeypatch):
    w = _watcher(store)
    eid = _entity_row(store)
    inv = store.create_investigation("APT29", resolved_entity_id=eid)
    _patch_profile(monkeypatch, [_fact()])
    report = SimpleNamespace(
        state=InvestigationState.FINISHED, investigation_id=inv.id, target="APT29",
    )
    out = runner.reconcile_report(store, ArgusConfig(), report)
    assert len(out) == 1
    assert out[0].watcher_id == w.id
