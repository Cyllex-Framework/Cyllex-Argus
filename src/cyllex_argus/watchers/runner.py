"""Glue between a finished investigation run and the watcher diff.

`reconcile_after_run` is called after a run's committed FINISHED state (never mid-run — the diff
must read settled assessments, or the known concurrency>1 status race would surface spurious
'verified'/'weakened' events). It finds the watcher for the target, diffs the entity's current
facts against the stored snapshot, persists the change events, and advances the snapshot.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from cyllex_argus.knowledge.models import InvestigationState, WatcherChange
from cyllex_argus.knowledge.profile import build_profile
from cyllex_argus.watchers.diff import diff, floor_eligible, snapshot_of

if TYPE_CHECKING:
    from cyllex_argus.config.settings import ArgusConfig
    from cyllex_argus.knowledge.sqlite_store import SQLiteStore


def reconcile_after_run(
    store: SQLiteStore, config: ArgusConfig, *, entity_id: str | None, target: str,
    run_job_id: str | None, now: datetime | None = None,
) -> list[WatcherChange]:
    """Diff + persist change events for the watcher on `target`. Returns the new changes (empty
    when there is no watcher, no resolved entity, or nothing changed)."""
    if entity_id is None:
        return []
    # Match by target string first, then by the resolved entity — so a manual run under an alias
    # or different spelling still advances the watcher (keyed by entity, per the spec), instead of
    # the next scheduled run re-reporting those findings as new.
    watcher = store.watcher_for_target(target) or store.watcher_for_entity(entity_id)
    if watcher is None:
        return []
    entity = store.get_entity(entity_id)
    if entity is None:
        return []
    facts = build_profile(store, entity).facts
    previous = store.get_snapshot(watcher.id)
    changes = diff(
        previous, facts, min_reliability=config.watchers.min_reliability,
        baseline=not previous, now=now,
    )
    for change in changes:
        change.watcher_id = watcher.id
        change.entity_id = entity_id
        change.run_job_id = run_job_id
    if changes:
        store.add_changes(watcher.id, changes)
    # Snapshot only the floor-eligible facts: a below-floor fact must not enter the snapshot, or
    # it would never fire NEW once it becomes credible. Capped-off baseline facts stay eligible,
    # so they are recorded and do not resurface as NEW.
    store.replace_snapshot(watcher.id, snapshot_of(floor_eligible(facts, config.watchers.min_reliability)))
    return changes


def dispatch_pending(store: SQLiteStore, dispatcher) -> None:
    """Push every undelivered change event to the webhooks and mark it delivered. De-dup: a
    change already delivered is skipped; a change that failed to send stays undelivered so the
    next pass retries it."""
    for change in store.undelivered_changes():
        watcher = store.get_watcher(change.watcher_id)
        if watcher is None:
            continue
        results = dispatcher.dispatch_watcher_change(watcher, change)
        # Mark delivered only when no enabled webhook failed — a partial failure leaves the change
        # undelivered so the next pass retries it, rather than silently dropping the failed
        # channel. With no enabled webhooks (no failures, nothing sent) it is marked so it does
        # not retry forever.
        if any(r.status == "failed" for r in results):
            continue
        store.mark_delivered([change.id], [r.url for r in results if r.status == "sent"])


def reconcile_report(
    store: SQLiteStore, config: ArgusConfig, report, *,
    run_job_id: str | None = None, now: datetime | None = None,
) -> list[WatcherChange]:
    """Reconcile from an investigation report, but only once the run has FINISHED (committed).
    A paused/failed run touches nothing."""
    if report.state is not InvestigationState.FINISHED:
        return []
    investigation = store.get_investigation(report.investigation_id)
    return reconcile_after_run(
        store, config, entity_id=investigation.resolved_entity_id, target=report.target,
        run_job_id=run_job_id or str(report.investigation_id), now=now,
    )
