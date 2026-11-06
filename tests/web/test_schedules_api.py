"""The scheduler ticker and its cron helpers.

The HTTP CRUD surface for scheduled investigations was retired when Watchers became the single
recurring-monitoring UI (watchers manage the same `scheduled_investigations` rows through
`/api/watchers`). The scheduler thread that fires those rows, and the cron helpers it relies on,
are still the core mechanism and are covered here.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from cyllex_argus.pipeline.scheduler import SchedulerThread, is_valid_cron, next_fire
from tests.support import World

# -- croniter helpers --------------------------------------------------------------------------


def test_is_valid_cron_catches_junk():
    assert is_valid_cron("0 8 * * 1") is True
    assert is_valid_cron("not a cron") is False
    assert is_valid_cron("") is False


def test_next_fire_computes_strictly_after():
    anchor = datetime(2026, 1, 1, 7, 0, tzinfo=UTC)
    # "every day at 8am UTC" after 7am same day → 8am same day.
    assert next_fire("0 8 * * *", anchor) == datetime(2026, 1, 1, 8, 0, tzinfo=UTC)
    # anchor past the fire time → next day
    assert next_fire("0 8 * * *", datetime(2026, 1, 1, 9, 0, tzinfo=UTC)) == datetime(2026, 1, 2, 8, 0, tzinfo=UTC)


# -- Scheduler thread --------------------------------------------------------------------------


def test_scheduler_fires_due_schedules_and_advances_next_run(seeded_world: World, monkeypatch):
    """Build a schedule whose next_run_at is in the past; the scheduler should enqueue a job and
    advance next_run_at to the next cron slot."""
    from cyllex_argus.web.jobs import JobManager
    world = seeded_world
    services = world.services()
    try:
        past = datetime.now(UTC) - timedelta(minutes=5)
        schedule = services.store.create_schedule(
            target="Scattered Spider", cron_expr="*/5 * * * *",  # every 5 min
            max_docs=None, concurrency=1, next_run_at=past,
        )
    finally:
        services.close()
    jobs = JobManager(handlers={"investigate": lambda params, log: {"ok": True}}, inline=True)
    ticker = SchedulerThread(world.services, jobs, tick_seconds=0.1)
    # Run exactly one tick synchronously.
    ticker._tick_once()  # noqa: SLF001
    services = world.services()
    try:
        refreshed = services.store.get_schedule(schedule.id)
    finally:
        services.close()
    assert refreshed is not None
    assert refreshed.next_run_at > past, "next_run_at should have advanced past the fired slot"
    # The job manager should have at least one investigate job queued or finished.
    kinds = [j["kind"] for j in jobs.list()]
    assert "investigate" in kinds
