"""Server clock.

Watcher cron expressions are evaluated by the scheduler in UTC (`SchedulerThread` uses
`datetime.now(UTC)` — see `pipeline/scheduler.py`), so the web UI shows the operator the server's
own UTC time. A skewed client clock must not mislead them, hence this endpoint rather than the
browser's `Date`. Named `clock` (not `time`) to avoid shadowing the stdlib `time` module where the
router is imported.
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter

router = APIRouter()


@router.get("/time")
def server_time() -> dict:
    """The server's current time, as ISO 8601 UTC with a trailing `Z` and no microseconds."""
    now = datetime.now(UTC)
    return {"now": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "tz": "UTC"}
