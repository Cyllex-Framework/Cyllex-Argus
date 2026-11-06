"""The security middleware resolves a per-user session for /api, and keeps the machine token for TAXII."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from cyllex_argus.knowledge.models import Role
from cyllex_argus.knowledge.sqlite_store import SQLiteStore
from cyllex_argus.web import auth_core
from cyllex_argus.web.deps import current_user
from cyllex_argus.web.security import SecurityMiddleware

MACHINE_TOKEN = "machine-token-xyz"


@pytest.fixture
def store():
    with SQLiteStore(":memory:") as s:
        yield s


def _app(store) -> FastAPI:
    app = FastAPI()

    @app.get("/api/session/check")
    def check(request: Request):
        user = current_user(request)
        return {"username": user.username, "role": user.role.value}

    @app.get("/api/auth/status")
    def status():
        return {"login_enabled": True}

    @app.get("/taxii2/ping")
    def taxii():
        return {"ok": True}

    def resolver(token: str):
        return store.session_user(auth_core.token_hash(token))

    app.add_middleware(
        SecurityMiddleware, token=MACHINE_TOKEN, port=8766,
        extra_hosts=["testserver"], session_resolver=resolver,
    )
    return app


def _session_for(store, role=Role.OPERATOR) -> tuple[str, int]:
    user = store.create_user("alice", "h", role)
    token, token_hash = auth_core.new_session_token()
    store.create_session(user.id, token_hash, datetime.now(UTC) + timedelta(days=1))
    return token, user.id


def test_valid_session_resolves_the_user(store):
    token, _ = _session_for(store)
    client = TestClient(_app(store))
    resp = client.get("/api/session/check", headers={"X-Argus-Token": token})
    assert resp.status_code == 200
    assert resp.json() == {"username": "alice", "role": "operator"}


def test_unknown_token_is_rejected(store):
    _session_for(store)
    client = TestClient(_app(store))
    assert client.get("/api/session/check", headers={"X-Argus-Token": "nope"}).status_code == 401
    assert client.get("/api/session/check").status_code == 401  # no token at all


def test_disabled_user_session_is_rejected(store):
    token, user_id = _session_for(store)
    store.set_user_disabled(user_id, True)
    client = TestClient(_app(store))
    assert client.get("/api/session/check", headers={"X-Argus-Token": token}).status_code == 401


def test_public_api_needs_no_token(store):
    client = TestClient(_app(store))
    assert client.get("/api/auth/status").status_code == 200


def test_taxii_takes_the_machine_token_not_a_session(store):
    token, _ = _session_for(store)
    client = TestClient(_app(store))
    # machine token works
    assert client.get("/taxii2/ping", headers={"Authorization": f"Bearer {MACHINE_TOKEN}"}).status_code == 200
    # a user session token does NOT open TAXII
    assert client.get("/taxii2/ping", headers={"X-Argus-Token": token}).status_code == 401
