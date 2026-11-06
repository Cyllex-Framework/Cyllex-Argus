"""Seeding the admin user on first boot, and keeping ARGUS_ADMIN_PASSWORD authoritative."""

from __future__ import annotations

import pytest

from cyllex_argus.knowledge.models import Role
from cyllex_argus.knowledge.sqlite_store import SQLiteStore
from cyllex_argus.web import auth_core
from cyllex_argus.web.auth_seed import admin_uses_default_password, ensure_admin_seeded


class _Auth:
    def __init__(self, admin_password_hash="", admin_username="admin"):
        self.admin_password_hash = admin_password_hash
        self.admin_username = admin_username


class _Cfg:
    def __init__(self, admin_password_hash="", admin_username="admin"):
        self.auth = _Auth(admin_password_hash, admin_username)


@pytest.fixture
def store():
    with SQLiteStore(":memory:") as s:
        yield s


@pytest.fixture(autouse=True)
def _no_env(monkeypatch):
    monkeypatch.delenv("ARGUS_ADMIN_PASSWORD", raising=False)
    monkeypatch.delenv("ARGUS_ADMIN_USERNAME", raising=False)


def test_seed_from_toml_hash(store):
    hashed = auth_core.hash_password("fromtoml1")
    ensure_admin_seeded(store, _Cfg(admin_password_hash=hashed))
    admin = store.get_user_by_username("admin")
    assert admin.role is Role.ADMIN and not admin.seeded_with_default
    assert store.user_password_hash(admin.id) == hashed
    assert not admin_uses_default_password(store)


def test_seed_with_default_when_nothing_configured(store):
    ensure_admin_seeded(store, _Cfg())
    admin = store.get_user_by_username("admin")
    assert admin.role is Role.ADMIN and admin.seeded_with_default
    assert auth_core.verify_password("Argus123", store.user_password_hash(admin.id))
    assert admin_uses_default_password(store)


def test_seed_from_env(store, monkeypatch):
    monkeypatch.setenv("ARGUS_ADMIN_PASSWORD", "fromenv-long")
    ensure_admin_seeded(store, _Cfg())
    admin = store.get_user_by_username("admin")
    assert not admin.seeded_with_default
    assert auth_core.verify_password("fromenv-long", store.user_password_hash(admin.id))
    assert not admin_uses_default_password(store)  # env overrides the hint


def test_env_resyncs_existing_admin(store, monkeypatch):
    ensure_admin_seeded(store, _Cfg(admin_password_hash=auth_core.hash_password("old-pass1")))
    admin = store.get_user_by_username("admin")
    old_hash = store.user_password_hash(admin.id)
    monkeypatch.setenv("ARGUS_ADMIN_PASSWORD", "new-env-pass")
    ensure_admin_seeded(store, _Cfg(admin_password_hash=auth_core.hash_password("old-pass1")))
    new_hash = store.user_password_hash(admin.id)
    assert new_hash != old_hash
    assert auth_core.verify_password("new-env-pass", new_hash)


def test_second_call_without_env_is_a_noop(store):
    ensure_admin_seeded(store, _Cfg())
    admin = store.get_user_by_username("admin")
    first_hash = store.user_password_hash(admin.id)
    ensure_admin_seeded(store, _Cfg())
    assert store.user_password_hash(admin.id) == first_hash
    assert len(store.list_users()) == 1
