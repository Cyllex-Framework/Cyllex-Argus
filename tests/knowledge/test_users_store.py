"""Users, sessions and the tombstone that keeps attribution alive after a delete."""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta

import pytest

from cyllex_argus.knowledge.models import Role, User
from cyllex_argus.knowledge.sqlite_store import SQLiteStore


@pytest.fixture
def store():
    with SQLiteStore(":memory:") as s:
        yield s


def _future() -> datetime:
    return datetime.now(UTC) + timedelta(days=1)


def _past() -> datetime:
    return datetime.now(UTC) - timedelta(days=1)


def test_create_and_get_user_round_trips(store):
    user = store.create_user("Alice", "hash1", Role.OPERATOR)
    assert isinstance(user, User)
    assert user.username == "Alice" and user.role is Role.OPERATOR and not user.disabled
    assert store.get_user(user.id).username == "Alice"
    assert store.get_user_by_username("alice").id == user.id  # case-insensitive


def test_username_uniqueness_is_case_insensitive(store):
    store.create_user("Bob", "h", Role.READER)
    with pytest.raises(sqlite3.IntegrityError):
        store.create_user("BOB", "h", Role.READER)


def test_list_users_returns_every_live_user(store):
    store.create_user("a", "h", Role.ADMIN)
    store.create_user("b", "h", Role.READER)
    assert {u.username for u in store.list_users()} == {"a", "b"}


def test_role_disabled_and_password_setters(store):
    user = store.create_user("c", "h1", Role.READER)
    store.set_user_role(user.id, Role.OPERATOR)
    store.set_user_disabled(user.id, True)
    store.set_user_password(user.id, "h2")
    got = store.get_user(user.id)
    assert got.role is Role.OPERATOR and got.disabled
    assert store.user_password_hash(user.id) == "h2"


def test_delete_user_tombstones_but_keeps_attribution(store):
    user = store.create_user("ghost", "h", Role.OPERATOR)
    store.delete_user(user.id)
    assert store.get_user_by_username("ghost") is None  # cannot log in; the name is freed
    assert store.get_user(user.id).username == "ghost"  # id still resolves for attribution
    store.create_user("ghost", "h", Role.READER)  # the freed name can be reused


def test_count_enabled_admins(store):
    admin = store.create_user("admin", "h", Role.ADMIN)
    store.create_user("op", "h", Role.OPERATOR)
    assert store.count_enabled_admins() == 1
    store.set_user_disabled(admin.id, True)
    assert store.count_enabled_admins() == 0


def test_session_create_resolve_and_delete(store):
    user = store.create_user("alice", "h", Role.OPERATOR)
    store.create_session(user.id, "tokhash", _future())
    got = store.session_user("tokhash")
    assert got is not None and got.id == user.id
    store.delete_session("tokhash")
    assert store.session_user("tokhash") is None


def test_disabled_user_session_does_not_resolve(store):
    user = store.create_user("x", "h", Role.READER)
    store.create_session(user.id, "t", _future())
    store.set_user_disabled(user.id, True)
    assert store.session_user("t") is None


def test_expired_session_does_not_resolve(store):
    user = store.create_user("y", "h", Role.READER)
    store.create_session(user.id, "t", _past())
    assert store.session_user("t") is None


def test_delete_user_sessions_drops_all(store):
    user = store.create_user("z", "h", Role.READER)
    store.create_session(user.id, "t1", _future())
    store.create_session(user.id, "t2", _future())
    store.delete_user_sessions(user.id)
    assert store.session_user("t1") is None and store.session_user("t2") is None
