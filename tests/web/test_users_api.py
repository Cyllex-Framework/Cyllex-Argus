"""User management API and role enforcement across the surface."""

from __future__ import annotations

from cyllex_argus.knowledge.models import Role
from tests.web.conftest import make_client

CSRF = {"X-Argus-CSRF": "1"}


def _login_token(world, username, password):
    resp = make_client(world, authenticated=False).post(
        "/api/auth/login", json={"username": username, "password": password}, headers=CSRF)
    assert resp.status_code == 200, resp.text
    return resp.json()["data"]["token"]


def test_admin_lists_users_including_the_seeded_admin(world):
    client = make_client(world, role=Role.ADMIN)
    resp = client.get("/api/users")
    assert resp.status_code == 200
    assert "admin" in {u["username"] for u in resp.json()["users"]}


def test_admin_creates_a_user_who_can_then_log_in_without_a_forced_change(world):
    client = make_client(world, role=Role.ADMIN)
    created = client.post(
        "/api/users", json={"username": "bob", "password": "bob-password", "role": "operator"}, headers=CSRF)
    assert created.status_code == 201 and created.json()["role"] == "operator"
    token = _login_token(world, "bob", "bob-password")
    assert token


def test_create_rejects_duplicate_username_and_short_password(world):
    client = make_client(world, role=Role.ADMIN)
    assert client.post(
        "/api/users", json={"username": "admin", "password": "longenough", "role": "reader"}, headers=CSRF
    ).status_code == 409
    assert client.post(
        "/api/users", json={"username": "x", "password": "short", "role": "reader"}, headers=CSRF
    ).status_code == 400


def test_operator_cannot_reach_user_management(world):
    client = make_client(world, role=Role.OPERATOR)
    assert client.get("/api/users").status_code == 403
    assert client.post(
        "/api/users", json={"username": "y", "password": "longenough", "role": "reader"}, headers=CSRF
    ).status_code == 403


def test_reader_may_read_but_not_write(world):
    client = make_client(world, role=Role.READER)
    assert client.get("/api/threats").status_code == 200
    assert client.post(
        "/api/jobs", json={"kind": "investigate", "target": "X"}, headers=CSRF
    ).status_code == 403


def test_admin_resets_another_users_password(world):
    admin = make_client(world, role=Role.ADMIN)
    created = admin.post(
        "/api/users", json={"username": "carol", "password": "carol-pass1", "role": "reader"}, headers=CSRF).json()
    assert admin.post(
        f"/api/users/{created['id']}/password", json={"password": "newpass123"}, headers=CSRF
    ).status_code == 204
    assert _login_token(world, "carol", "newpass123")


def test_user_changes_own_password_and_wrong_current_is_rejected(world):
    admin = make_client(world, role=Role.ADMIN)
    admin.post("/api/users", json={"username": "dave", "password": "dave-pass1", "role": "operator"}, headers=CSRF)
    token = _login_token(world, "dave", "dave-pass1")
    client = make_client(world, authenticated=False)
    client.headers["X-Argus-Token"] = token
    assert client.put(
        "/api/users/me/password", json={"current_password": "wrong", "new_password": "newpass123"}, headers=CSRF
    ).status_code == 400
    assert client.put(
        "/api/users/me/password", json={"current_password": "dave-pass1", "new_password": "newpass123"}, headers=CSRF
    ).status_code == 204


def test_last_admin_cannot_be_deleted_disabled_or_demoted(world):
    admin = make_client(world, role=Role.ADMIN)
    admin_row = next(u for u in admin.get("/api/users").json()["users"] if u["username"] == "admin")
    aid = admin_row["id"]
    assert admin.delete(f"/api/users/{aid}", headers=CSRF).status_code == 409
    assert admin.put(f"/api/users/{aid}", json={"disabled": True}, headers=CSRF).status_code == 409
    assert admin.put(f"/api/users/{aid}", json={"role": "reader"}, headers=CSRF).status_code == 409


def test_admin_reset_revokes_the_targets_sessions(world):
    admin = make_client(world, role=Role.ADMIN)
    created = admin.post(
        "/api/users", json={"username": "carl", "password": "carl-pass1", "role": "operator"}, headers=CSRF).json()
    token = _login_token(world, "carl", "carl-pass1")
    carl = make_client(world, authenticated=False)
    carl.headers["X-Argus-Token"] = token
    assert carl.get("/api/auth/me").status_code == 200
    assert admin.post(f"/api/users/{created['id']}/password", json={"password": "newpass123"}, headers=CSRF).status_code == 204
    assert carl.get("/api/auth/me").status_code == 401  # the reset revoked the old session


def test_change_own_password_keeps_current_session_but_revokes_others(world):
    admin = make_client(world, role=Role.ADMIN)
    admin.post("/api/users", json={"username": "dina", "password": "dina-pass1", "role": "operator"}, headers=CSRF)
    token1, token2 = _login_token(world, "dina", "dina-pass1"), _login_token(world, "dina", "dina-pass1")
    c1 = make_client(world, authenticated=False)
    c1.headers["X-Argus-Token"] = token1
    c2 = make_client(world, authenticated=False)
    c2.headers["X-Argus-Token"] = token2
    assert c1.put(
        "/api/users/me/password", json={"current_password": "dina-pass1", "new_password": "newpass123"}, headers=CSRF
    ).status_code == 204
    assert c1.get("/api/auth/me").status_code == 200  # the device that changed it stays signed in
    assert c2.get("/api/auth/me").status_code == 401  # every other session is revoked


def test_disabled_admin_can_be_demoted_when_another_admin_remains(world):
    admin = make_client(world, role=Role.ADMIN)
    second = admin.post(
        "/api/users", json={"username": "a2", "password": "a2-pass123", "role": "admin"}, headers=CSRF).json()
    assert admin.put(f"/api/users/{second['id']}", json={"disabled": True}, headers=CSRF).status_code == 200
    # demoting the DISABLED admin is allowed: the seeded admin still satisfies the invariant
    assert admin.put(f"/api/users/{second['id']}", json={"role": "reader"}, headers=CSRF).status_code == 200
