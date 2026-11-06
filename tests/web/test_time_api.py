"""`GET /api/time` — the server clock watchers are scheduled against (UTC).

Watcher cron expressions are evaluated by the scheduler in UTC (`datetime.now(UTC)`), so the UI
shows the operator the server's UTC time. The endpoint requires a session like every other read.
"""

from __future__ import annotations

from datetime import UTC, datetime

from tests.web.conftest import make_client as _make_client


def make_client(world, **kwargs):
    return _make_client(world, **kwargs)


def test_time_returns_utc_now_in_iso8601_z(world):
    body = make_client(world).get("/api/time").json()
    assert body["tz"] == "UTC"
    assert body["now"].endswith("Z"), body["now"]
    parsed = datetime.fromisoformat(body["now"].replace("Z", "+00:00"))
    assert parsed.tzinfo is not None
    # The clock is the real server clock, so it must be within a minute of now.
    assert abs((datetime.now(UTC) - parsed).total_seconds()) < 60


def test_time_requires_a_session(world):
    r = make_client(world, authenticated=False).get("/api/time")
    assert r.status_code in (401, 403), r.status_code
