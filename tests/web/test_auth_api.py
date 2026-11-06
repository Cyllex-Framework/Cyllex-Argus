"""Tests for the admin login endpoint. Covers env → toml → built-in-default precedence and the
401 wrong-credentials path.

The URL-fragment / token-bypass path has been removed: the login screen is the only way to
obtain the session token, so `login_enabled` is always true. When neither the env var nor the
toml hash is set, the server accepts the shipped default (`admin` / `Argus123`) and the auth
status endpoint flips `default_password_in_use` to true so the login screen can show a hint.
"""

from __future__ import annotations

import bcrypt
import pytest

from cyllex_argus.config.settings import AuthConfig
from cyllex_argus.web.api.auth import DEFAULT_ADMIN_PASSWORD, DEFAULT_ADMIN_USERNAME
from tests.support import World
from tests.web.conftest import make_client

CSRF = {"X-Argus-CSRF": "1"}


def _hash(pw: str) -> str:
    return bcrypt.hashpw(pw.encode("utf-8"), bcrypt.gensalt()).decode("ascii")


@pytest.fixture(autouse=True)
def _clear_admin_env(monkeypatch):
    """Clear the env override so every test starts from "no env" unless it opts back in. Keeps
    tests independent of the shell they run in — a developer with ARGUS_ADMIN_PASSWORD exported
    would otherwise get a different precedence order per test."""
    monkeypatch.delenv("ARGUS_ADMIN_PASSWORD", raising=False)
    monkeypatch.delenv("ARGUS_ADMIN_USERNAME", raising=False)


def test_login_with_default_password_when_nothing_configured(seeded_world: World):
    """The shipped default is `admin` / `Argus123`.
    Lets a first-run operator open the UI without the token-URL dance that used to be required.
    """
    client = make_client(seeded_world, authenticated=False)
    r = client.post(
        "/api/auth/login",
        json={"username": DEFAULT_ADMIN_USERNAME, "password": DEFAULT_ADMIN_PASSWORD},
        headers=CSRF,
    )
    assert r.status_code == 200
    body = r.json()
    assert body["success"] is True
    assert body["data"]["user"] == {"username": DEFAULT_ADMIN_USERNAME, "role": "admin"}


def test_auth_status_signals_default_password_in_use(seeded_world: World):
    """The login screen uses this to render the yellow "change the default" hint. `login_enabled`
    is always true; `default_password_in_use` flips to false once an operator sets the env or
    runs set/reset-admin-password."""
    client = make_client(seeded_world, authenticated=False)
    status = client.get("/api/auth/status").json()
    assert status == {"login_enabled": True, "default_password_in_use": True}


def test_auth_status_marks_default_as_disabled_when_toml_configured(seeded_world: World):
    seeded_world.config.auth = AuthConfig(admin_username="admin", admin_password_hash=_hash("s3cret"))
    client = make_client(seeded_world, authenticated=False)
    status = client.get("/api/auth/status").json()
    assert status == {"login_enabled": True, "default_password_in_use": False}


def test_auth_status_marks_default_as_disabled_when_env_configured(seeded_world: World, monkeypatch):
    monkeypatch.setenv("ARGUS_ADMIN_PASSWORD", "env-pass")
    client = make_client(seeded_world, authenticated=False)
    status = client.get("/api/auth/status").json()
    assert status == {"login_enabled": True, "default_password_in_use": False}


def test_default_password_login_fails_once_toml_hash_is_set(seeded_world: World):
    """Setting a toml hash must disable the shipped default; otherwise an operator who thinks
    they rotated the password would still be exposed to anyone trying 'Argus123'."""
    seeded_world.config.auth = AuthConfig(admin_username="admin", admin_password_hash=_hash("real-pass"))
    client = make_client(seeded_world, authenticated=False)
    r = client.post(
        "/api/auth/login",
        json={"username": DEFAULT_ADMIN_USERNAME, "password": DEFAULT_ADMIN_PASSWORD},
        headers=CSRF,
    )
    assert r.status_code == 401


def test_login_via_argus_toml_hash_round_trip(seeded_world: World):
    seeded_world.config.auth = AuthConfig(admin_username="admin", admin_password_hash=_hash("s3cret"))
    client = make_client(seeded_world, authenticated=False)
    r = client.post("/api/auth/login", json={"username": "admin", "password": "s3cret"}, headers=CSRF)
    assert r.status_code == 200
    body = r.json()
    assert body["success"] is True
    assert body["data"]["user"] == {"username": "admin", "role": "admin"}
    # A per-user session token is issued — a fresh secret, not the TAXII machine token.
    assert isinstance(body["data"]["token"], str) and body["data"]["token"]
    assert body["data"]["token"] != "test-token-0123456789"


def test_login_via_env_wins_over_config(seeded_world: World, monkeypatch):
    """ARGUS_ADMIN_PASSWORD env should be preferred — operator rotation without a file edit."""
    seeded_world.config.auth = AuthConfig(admin_username="admin", admin_password_hash=_hash("in-file"))
    monkeypatch.setenv("ARGUS_ADMIN_PASSWORD", "env-wins")
    monkeypatch.setenv("ARGUS_ADMIN_USERNAME", "root")
    client = make_client(seeded_world, authenticated=False)
    # env creds work
    ok = client.post("/api/auth/login", json={"username": "root", "password": "env-wins"}, headers=CSRF)
    assert ok.status_code == 200
    assert ok.json()["data"]["user"]["username"] == "root"
    # old file creds no longer work (env is checked first)
    stale = client.post("/api/auth/login", json={"username": "admin", "password": "in-file"}, headers=CSRF)
    assert stale.status_code == 401


def test_login_401_on_wrong_password(seeded_world: World):
    seeded_world.config.auth = AuthConfig(admin_username="admin", admin_password_hash=_hash("right"))
    client = make_client(seeded_world, authenticated=False)
    r = client.post("/api/auth/login", json={"username": "admin", "password": "wrong"}, headers=CSRF)
    assert r.status_code == 401


def test_login_401_on_wrong_username(seeded_world: World):
    seeded_world.config.auth = AuthConfig(admin_username="admin", admin_password_hash=_hash("x"))
    client = make_client(seeded_world, authenticated=False)
    r = client.post("/api/auth/login", json={"username": "root", "password": "x"}, headers=CSRF)
    assert r.status_code == 401


def test_login_bypasses_token_check_on_security_middleware(seeded_world: World, monkeypatch):
    """The point of the login endpoint is that it is reachable WITHOUT a token.
    The security middleware's exemption for /api/auth/* must not require X-Argus-Token."""
    monkeypatch.setenv("ARGUS_ADMIN_PASSWORD", "p")
    client = make_client(seeded_world, authenticated=False)
    assert "X-Argus-Token" not in client.headers
    r = client.post("/api/auth/login", json={"username": "admin", "password": "p"}, headers=CSRF)
    assert r.status_code == 200


def test_login_still_needs_csrf_header(seeded_world: World, monkeypatch):
    monkeypatch.setenv("ARGUS_ADMIN_PASSWORD", "p")
    client = make_client(seeded_world, authenticated=False)
    r = client.post("/api/auth/login", json={"username": "admin", "password": "p"})  # no CSRF header
    assert r.status_code == 403


def test_me_returns_the_current_user(seeded_world: World):
    from cyllex_argus.knowledge.models import Role
    client = make_client(seeded_world, role=Role.ADMIN)
    assert client.get("/api/auth/me").json() == {"username": "admin", "role": "admin"}


def test_logout_revokes_the_session(seeded_world: World):
    from tests.web.conftest import session_token
    token = session_token(seeded_world)
    client = make_client(seeded_world, authenticated=False)
    client.headers["X-Argus-Token"] = token
    assert client.get("/api/auth/me").status_code == 200
    assert client.post("/api/auth/logout", headers=CSRF).status_code == 204
    assert client.get("/api/auth/me").status_code == 401  # the token is dead now


def test_disabled_user_cannot_log_in(seeded_world: World):
    from cyllex_argus.knowledge.models import Role
    admin = make_client(seeded_world, role=Role.ADMIN)
    created = admin.post(
        "/api/users", json={"username": "eve", "password": "eve-pass1", "role": "reader"}, headers=CSRF).json()
    admin.put(f"/api/users/{created['id']}", json={"disabled": True}, headers=CSRF)
    login = make_client(seeded_world, authenticated=False).post(
        "/api/auth/login", json={"username": "eve", "password": "eve-pass1"}, headers=CSRF)
    assert login.status_code == 401


def test_login_throttles_after_repeated_failures(seeded_world: World):
    """Brute force is blunted: after MAX_FAILURES wrong attempts for a username, the next is 429.
    A non-existent username is used so the failures cost no bcrypt."""
    client = make_client(seeded_world, authenticated=False)
    for _ in range(10):
        assert client.post("/api/auth/login", json={"username": "ghost", "password": "x"}, headers=CSRF).status_code == 401
    assert client.post("/api/auth/login", json={"username": "ghost", "password": "x"}, headers=CSRF).status_code == 429
