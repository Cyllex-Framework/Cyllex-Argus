"""Login, logout, current-user and status for the web UI.

Argus's web UI gates every page behind a login screen. Credentials are checked against the `users`
table; a successful login opens a per-user session (a row in `sessions`) and returns its token. The
token is a random secret; only its hash is stored, and logout deletes the row, so logout is a real
server-side revocation.

The admin user is seeded on first boot from the pre-multiuser credential sources (env → argus.toml
→ built-in default); see `web/auth_seed.py`.
"""

from __future__ import annotations

import os
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, Field

from cyllex_argus.web import auth_core
from cyllex_argus.web.auth_core import DEFAULT_ADMIN_PASSWORD, DEFAULT_ADMIN_USERNAME
from cyllex_argus.web.auth_seed import admin_uses_default_password
from cyllex_argus.web.deps import current_user, open_services
from cyllex_argus.web.security import TOKEN_HEADER

router = APIRouter()

# Re-exported for callers that import them from here (CLI, tests); defined in auth_core.
__all__ = ["DEFAULT_ADMIN_PASSWORD", "DEFAULT_ADMIN_USERNAME", "is_using_default_password", "router"]


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=200)
    password: str = Field(min_length=1, max_length=1024)


class LoginThrottle:
    """Per-username fixed-window failure cap, to blunt brute force. In-memory and per server
    process, which is enough for the single-server, trusted-LAN deployment. One instance lives on
    `app.state`, so each server (and each test app) is isolated."""

    WINDOW_SECONDS = 60.0
    MAX_FAILURES = 10

    def __init__(self, now: Callable[[], float] = time.monotonic) -> None:
        self._now = now
        self._failures: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def check(self, key: str) -> None:
        with self._lock:
            recent = self._prune(key)
            if len(recent) >= self.MAX_FAILURES:
                raise HTTPException(status_code=429, detail="too many login attempts; wait a moment")

    def record_failure(self, key: str) -> None:
        with self._lock:
            self._prune(key).append(self._now())

    def record_success(self, key: str) -> None:
        with self._lock:
            self._failures.pop(key, None)

    def _prune(self, key: str) -> list[float]:
        cutoff = self._now() - self.WINDOW_SECONDS
        kept = [t for t in self._failures.get(key, []) if t > cutoff]
        self._failures[key] = kept
        return kept


@router.post("/auth/login")
def login(body: LoginRequest, request: Request) -> dict:
    throttle: LoginThrottle | None = getattr(request.app.state, "login_throttle", None)
    key = body.username.strip().casefold()
    if throttle is not None:
        throttle.check(key)
    with open_services(request) as services:
        store = services.store
        user = store.get_user_by_username(body.username)
        hashed = store.user_password_hash(user.id) if user is not None else None
        if user is None or user.disabled or hashed is None or not auth_core.verify_password(body.password, hashed):
            if throttle is not None:
                throttle.record_failure(key)
            raise HTTPException(status_code=401, detail="Invalid credentials")
        token, hashed_token = auth_core.new_session_token()
        store.create_session(user.id, hashed_token, auth_core.session_expiry(datetime.now(UTC)))
    if throttle is not None:
        throttle.record_success(key)
    return {
        "success": True,
        "data": {"token": token, "user": {"username": user.username, "role": user.role.value}},
    }


@router.post("/auth/logout", status_code=204)
def logout(request: Request) -> Response:
    """Revoke the caller's session. Idempotent: an already-gone session is a no-op."""
    presented = request.headers.get(TOKEN_HEADER)
    if presented:
        with open_services(request) as services:
            services.store.delete_session(auth_core.token_hash(presented))
    return Response(status_code=204)


@router.get("/auth/me")
def me(request: Request) -> dict:
    user = current_user(request)
    if user is None:
        raise HTTPException(status_code=401, detail="session required")
    return {"username": user.username, "role": user.role.value}


@router.get("/auth/status")
def auth_status(request: Request) -> dict:
    """Whether the admin still holds the built-in default password, for the login-screen hint.
    `login_enabled` is always true — the login screen is the only path to the dashboard."""
    with open_services(request) as services:
        default_in_use = admin_uses_default_password(services.store)
    return {"login_enabled": True, "default_password_in_use": default_in_use}


def is_using_default_password(config_auth) -> bool:
    """Config-based default-password check, retained for the `argus serve` startup warning. The
    runtime truth is the admin row's `seeded_with_default` flag (see `admin_uses_default_password`);
    this stays in sync because the seed uses the same env → toml → default precedence.
    """
    if os.environ.get("ARGUS_ADMIN_PASSWORD"):
        return False
    if config_auth is not None and config_auth.admin_password_hash:
        return False
    return True
