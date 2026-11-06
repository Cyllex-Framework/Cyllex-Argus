"""A cross-investigation, cross-job log: recent jobs and recent pipeline events in one response."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Query, Request

from cyllex_argus.web.deps import open_browse

router = APIRouter()
MAX_LIMIT = 500


def _parse_instant(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)  # a bare date or datetime is UTC


def _duration_ms(job: dict) -> int | None:
    if not job["started_at"] or not job["finished_at"]:
        return None
    start, end = _parse_instant(job["started_at"]), _parse_instant(job["finished_at"])
    return None if start is None or end is None else max(0, round((end - start).total_seconds() * 1000))


@router.get("/logs")
def logs(
    request: Request,
    limit: Annotated[int, Query(ge=1)] = 100,
    kind: Literal["investigate", "resume", "ingest", "attack_update", "recompute"] | None = None,
    state: Literal["queued", "running", "finished", "paused", "failed"] | None = None,
    since: str | None = None,
    per_stage_limit: Annotated[int | None, Query(ge=1, le=500)] = None,
) -> dict:
    """Jobs (newest first, as `GET /api/jobs`) and pipeline events (newest first), each capped at `limit` (max 500).

    When `per_stage_limit` is set, events are drawn up to that many per stage so a busy stage does not crowd out
    quiet ones.
    """
    limit = min(limit, MAX_LIMIT)
    cutoff = None
    if since:
        cutoff = _parse_instant(since)
        if cutoff is None:
            raise HTTPException(status_code=400, detail="invalid since: expected an ISO date or datetime")
        cutoff = cutoff.astimezone(UTC)
    jobs = []
    for job in request.app.state.jobs.list():
        if (kind and job["kind"] != kind) or (state and job["state"] != state):
            continue
        if cutoff is not None:
            moment = _parse_instant(job["started_at"] or job["created_at"])
            if moment is None or moment < cutoff:
                continue
        jobs.append({
            "id": job["id"], "kind": job["kind"], "state": job["state"], "started_at": job["started_at"],
            "finished_at": job["finished_at"], "message": job["message"], "duration_ms": _duration_ms(job),
            "events_count": job["events"],
        })
        if len(jobs) == limit:
            break
    with open_browse(request) as browse:
        events = browse.recent_events(
            limit,
            since=cutoff.isoformat() if cutoff is not None else None,
            per_stage_limit=per_stage_limit,
        )
    return {"jobs": jobs, "events": events}
