"""Single-worker job queue: long operations run one at a time and publish progress events."""

from __future__ import annotations

import queue
import secrets
import threading
from collections.abc import Callable, Hashable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

Handler = Callable[[dict[str, Any], Callable[[str], None]], dict[str, Any]]


class JobState(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    FINISHED = "finished"
    PAUSED = "paused"
    FAILED = "failed"


TERMINAL_STATES = frozenset({JobState.FINISHED, JobState.PAUSED, JobState.FAILED})
_MAX_TEXT = 2000
_SHUTDOWN_JOIN_SECONDS = 5.0


class DuplicateJobError(Exception):
    """A job with the same kind and dedupe key is already queued or running."""


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


@dataclass
class JobEvent:
    seq: int
    time: str
    message: str


@dataclass
class Job:
    id: str
    kind: str
    params: dict[str, Any]
    state: JobState = JobState.QUEUED
    created_at: str = field(default_factory=_now)
    started_at: str | None = None
    finished_at: str | None = None
    message: str | None = None
    result: dict[str, Any] | None = None
    events: list[JobEvent] = field(default_factory=list)
    dedupe_key: Hashable | None = None

    def summary(self) -> dict[str, Any]:
        return {
            "id": self.id, "kind": self.kind, "params": dict(self.params), "state": self.state.value,
            "created_at": self.created_at, "started_at": self.started_at, "finished_at": self.finished_at,
            "message": self.message, "result": self.result, "events": len(self.events),
        }


class JobManager:
    """Runs jobs one at a time on a single worker thread. All job state is guarded by one condition."""

    def __init__(self, handlers: dict[str, Handler], *, inline: bool = False, max_jobs: int = 200) -> None:
        self._handlers = dict(handlers)
        self._inline = inline
        self._max_jobs = max_jobs
        self._jobs: dict[str, Job] = {}
        self._order: list[str] = []
        self._cond = threading.Condition()
        self._queue: queue.Queue[str | None] = queue.Queue()
        self._worker: threading.Thread | None = None
        self._closed = False

    # -- public API ----------------------------------------------------------------

    def submit(
        self, kind: str, params: dict[str, Any], *, dedupe_key: Hashable | None = None, coalesce: bool = False,
    ) -> dict[str, Any]:
        """Queue a job. With a `dedupe_key`, raise DuplicateJobError if a queued or running job of the same kind has it.

        With `coalesce`, a queued job of the same kind and key is returned instead, and no new job is queued. A running
        one never is: it may have read its inputs already, so the caller's change needs a run of its own after it.
        The check and the enqueue happen under one lock, so concurrent identical submits admit exactly one.
        """
        if kind not in self._handlers:
            raise ValueError(f"unknown job kind: {kind}")
        job = Job(id=secrets.token_hex(8), kind=kind, params=dict(params), dedupe_key=dedupe_key)
        with self._cond:
            if self._closed and not self._inline:
                raise RuntimeError("the job manager is shut down")
            if coalesce:
                waiting = next((
                    other for other in self._jobs.values()
                    if other.kind == kind and other.dedupe_key == dedupe_key and other.state is JobState.QUEUED
                ), None)
                if waiting is not None:
                    return waiting.summary()
            elif dedupe_key is not None and any(
                other.kind == kind and other.dedupe_key == dedupe_key and other.state not in TERMINAL_STATES
                for other in self._jobs.values()
            ):
                raise DuplicateJobError(f"an identical {kind} job is already queued or running")
            self._jobs[job.id] = job
            self._order.append(job.id)
            self._prune()
            if not self._inline:
                self._ensure_worker()
                self._queue.put(job.id)
            queued = job.summary()  # taken before the worker can pick the job up: always "queued"
        if not self._inline:
            return queued
        self._run(job)
        with self._cond:
            return job.summary()

    def get(self, job_id: str) -> dict[str, Any] | None:
        with self._cond:
            job = self._jobs.get(job_id)
            return job.summary() if job else None

    def list(self) -> list[dict[str, Any]]:
        with self._cond:
            return [self._jobs[job_id].summary() for job_id in reversed(self._order)]

    def events_after(self, job_id: str, seq: int) -> tuple[list[dict[str, Any]], str | None]:
        with self._cond:
            job = self._jobs.get(job_id)
            if job is None:
                return [], None
            return [asdict(e) for e in job.events[max(0, seq):]], job.state.value

    def wait(self, job_id: str, after_seq: int, timeout: float) -> None:
        """Block until the job has events beyond `after_seq`, ends, disappears, or `timeout` seconds pass."""
        with self._cond:
            self._cond.wait_for(lambda: self._changed(job_id, after_seq), timeout=timeout)

    def wait_until_finished(self, job_id: str, timeout: float) -> dict[str, Any] | None:
        with self._cond:
            self._cond.wait_for(
                lambda: job_id not in self._jobs or self._jobs[job_id].state in TERMINAL_STATES, timeout=timeout)
        return self.get(job_id)

    def shutdown(self) -> None:
        """Stop the worker after its current job. Jobs still queued are marked failed instead of run."""
        with self._cond:
            self._closed = True
            worker = self._worker
            if worker is not None and worker.is_alive():
                self._queue.put(None)
        if worker is not None and worker is not threading.current_thread():
            worker.join(timeout=_SHUTDOWN_JOIN_SECONDS)

    # -- internals -----------------------------------------------------------------

    def _changed(self, job_id: str, after_seq: int) -> bool:
        """Condition predicate: the caller holds the lock."""
        job = self._jobs.get(job_id)
        return job is None or len(job.events) > after_seq or job.state in TERMINAL_STATES

    def _ensure_worker(self) -> None:
        """Start the single worker if it is not running. The caller holds the lock."""
        if self._worker is None or not self._worker.is_alive():
            self._worker = threading.Thread(target=self._loop, name="argus-jobs", daemon=True)
            self._worker.start()

    def _loop(self) -> None:
        while True:
            job_id = self._queue.get()
            if job_id is None:
                return
            with self._cond:
                job = self._jobs.get(job_id)
                closed = self._closed
            if job is None:
                continue
            if closed:
                self._finish(job, JobState.FAILED, None, "Cancelled: the job manager shut down before this job started")
                continue
            try:
                self._run(job)
            except BaseException:
                # The job is already recorded as failed. A thread cannot act on SystemExit or KeyboardInterrupt
                # (threading ignores them too), so the worker keeps serving the jobs queued behind this one.
                pass

    def _run(self, job: Job) -> None:
        with self._cond:
            job.state = JobState.RUNNING
            job.started_at = _now()
            self._cond.notify_all()

        def log(message: str) -> None:
            with self._cond:
                job.events.append(JobEvent(seq=len(job.events) + 1, time=_now(), message=str(message)[:_MAX_TEXT]))
                self._cond.notify_all()

        try:
            result = self._handlers[job.kind](job.params, log) or {}
            state = JobState.PAUSED if result.get("state") == "paused" else JobState.FINISHED
            message = result.get("message")
        except Exception as exc:  # a job failure must never kill the worker
            result, state = None, JobState.FAILED
            message = f"{type(exc).__name__}: {exc}"[:_MAX_TEXT]
        except BaseException as exc:  # SystemExit, KeyboardInterrupt: never leave the job "running"
            detail = f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__
            self._finish(job, JobState.FAILED, None, f"Interrupted: {detail}"[:_MAX_TEXT])
            raise
        self._finish(job, state, result, message)

    def _finish(self, job: Job, state: JobState, result: dict[str, Any] | None, message: str | None) -> None:
        with self._cond:
            job.state = state
            job.result = result
            job.message = message
            job.finished_at = _now()
            self._cond.notify_all()

    def _prune(self) -> None:
        """Drop the oldest finished jobs beyond the cap. The caller holds the lock."""
        while len(self._order) > self._max_jobs:
            oldest = next((i for i in self._order if self._jobs[i].state in TERMINAL_STATES), None)
            if oldest is None:
                return
            self._order.remove(oldest)
            del self._jobs[oldest]
