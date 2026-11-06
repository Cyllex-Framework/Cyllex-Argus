"""Background scheduler for recurring investigations.

A daemon thread polls the `scheduled_investigations` table every `TICK_SECONDS` and, for every
enabled row whose `next_run_at` has passed, enqueues an `investigate` job via the shared
JobManager. The row is then updated with the fired job id and the next fire time (computed via
croniter against the schedule's cron expression).

Design notes:

- One thread per process. Spawn it from `web.app.create_app` after the JobManager is wired. The
  CLI does not run the scheduler — recurrent investigations only fire while `argus serve` is up.
  That's intentional: `argus serve` IS the "always-on" surface, and running the ticker from a
  one-shot CLI invocation would mean a schedule only fires when the operator happens to type a
  command. systemd / the keep-alive install docs point at `argus serve`.

- croniter computes `next_run_at` from the LAST FIRED TIME, not from NOW, to keep the schedule
  honest when the server was down past the window (e.g. laptop closed over the weekend). This
  means Monday 8am stays Monday 8am even if the ticker next polls at 11am on Monday — exactly
  what an operator expects.

- A schedule due at `now` fires at MOST once per tick: `due_schedules()` returns it, the ticker
  recomputes `next_run_at` BEFORE submitting the job, so a second concurrent reader (if any) that
  queries in the same window would see `next_run_at` already pushed forward.

- A disabled schedule is skipped; its `next_run_at` is NOT advanced. When the operator re-enables
  it, the ticker will fire it immediately (since the stored next time is in the past) and
  recompute from there. That matches the "pause then resume" mental model.

- The thread catches every exception per schedule — a single malformed cron or a store blip
  doesn't halt the scheduler for every other row.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from croniter import croniter

if TYPE_CHECKING:
    from cyllex_argus.services import Services
    from cyllex_argus.web.jobs import JobManager

TICK_SECONDS = 30.0
log = logging.getLogger(__name__)


def next_fire(cron_expr: str, after: datetime) -> datetime:
    """Compute the next cron fire strictly after `after`."""
    return croniter(cron_expr, after).get_next(datetime)


def is_valid_cron(cron_expr: str) -> bool:
    try:
        croniter(cron_expr)
    except Exception:  # noqa: BLE001 — croniter raises a mix of types
        return False
    return True


class SchedulerThread(threading.Thread):
    """Runs forever (as a daemon) ticking every TICK_SECONDS."""

    def __init__(
        self,
        services_factory: Callable[[], Services],
        jobs: JobManager,
        tick_seconds: float = TICK_SECONDS,
    ) -> None:
        super().__init__(daemon=True, name="argus-scheduler")
        self._services_factory = services_factory
        self._jobs = jobs
        self._tick = tick_seconds
        self._stop = threading.Event()

    def run(self) -> None:
        log.info("scheduler thread starting (tick=%ss)", self._tick)
        while not self._stop.wait(self._tick):
            try:
                self._tick_once()
            except Exception:
                log.exception("scheduler tick failed")

    def stop(self) -> None:
        self._stop.set()

    def _tick_once(self) -> None:
        now = datetime.now(UTC)
        services = self._services_factory()
        try:
            due = services.store.due_schedules(now)
        finally:
            services.close()
        for schedule in due:
            try:
                self._fire(schedule, now)
            except Exception:
                log.exception("failed to fire schedule id=%s", schedule.id)

    def _fire(self, schedule, now: datetime) -> None:
        from cyllex_argus.web.jobs import DuplicateJobError

        params: dict = {"target": schedule.target, "concurrency": schedule.concurrency}
        if schedule.max_docs is not None:
            params["max_docs"] = schedule.max_docs
        # A watcher run is attributed to the watcher (its schedule id) and to the owner, so the
        # diff/alert reconcile can find the watcher and "started by" shows the owner.
        params["watcher_id"] = schedule.id
        if schedule.created_by is not None:
            params["user_id"] = schedule.created_by
        # dedupe_key keeps the ticker from double-firing a schedule when the previous run is
        # still queued or running — if the operator pointed two schedules at the same target with
        # overlapping fire times, only one lands at any instant.
        dedupe_key = (schedule.target.casefold(), schedule.max_docs)
        try:
            job = self._jobs.submit("investigate", params, dedupe_key=dedupe_key)
            job_id = job["id"]
        except DuplicateJobError:
            log.info("schedule id=%s: previous run still active, skipping this tick",
                     schedule.id)
            # Still advance next_run_at so we don't retry in a tight loop. The current job will
            # end naturally; the next scheduled fire is the next cron slot after `now`.
            job_id = None
        advanced = next_fire(schedule.cron_expr, now)
        services = self._services_factory()
        try:
            services.store.mark_schedule_fired(
                schedule.id,
                job_id=job_id or (schedule.last_job_id or ""),
                fired_at=now,
                next_run_at=advanced,
            )
        finally:
            services.close()
