"""Seed the admin user on first boot and keep `ARGUS_ADMIN_PASSWORD` authoritative.

Called at `argus serve` startup. On a fresh database it creates one admin, preserving the pre-
multiuser credential precedence (env → argus.toml → built-in default), so existing installs keep
logging in with the same password, now as the admin user. When the env var is set it stays
authoritative: the admin row's hash is re-synced from it on every boot, so a shop that rotates the
password by env + restart is not silently stranded once the row exists.
"""

from __future__ import annotations

import os

from cyllex_argus.knowledge.models import Role
from cyllex_argus.web import auth_core
from cyllex_argus.web.auth_core import DEFAULT_ADMIN_PASSWORD, DEFAULT_ADMIN_USERNAME


def _admin_username(config) -> str:
    env_user = os.environ.get("ARGUS_ADMIN_USERNAME", "").strip()
    cfg_auth = getattr(config, "auth", None) if config is not None else None
    cfg_user = (getattr(cfg_auth, "admin_username", "") or "").strip() if cfg_auth is not None else ""
    return env_user or cfg_user or DEFAULT_ADMIN_USERNAME


def ensure_admin_seeded(store, config) -> None:
    env_pass = os.environ.get("ARGUS_ADMIN_PASSWORD", "")
    cfg_auth = getattr(config, "auth", None) if config is not None else None
    admin_name = _admin_username(config)

    if not store.list_users():
        if env_pass:
            store.create_user(admin_name, auth_core.hash_password(env_pass), Role.ADMIN)
        elif cfg_auth is not None and getattr(cfg_auth, "admin_password_hash", ""):
            store.create_user(admin_name, cfg_auth.admin_password_hash, Role.ADMIN)
        else:
            store.create_user(
                admin_name, auth_core.hash_password(DEFAULT_ADMIN_PASSWORD), Role.ADMIN,
                seeded_with_default=True,
            )
        return

    # Users already exist: the env var remains authoritative for the admin account.
    if env_pass:
        admin = store.get_user_by_username(admin_name)
        if admin is not None and admin.role is Role.ADMIN:
            store.set_user_password(admin.id, auth_core.hash_password(env_pass))


def admin_uses_default_password(store) -> bool:
    """True while an enabled admin still holds the built-in default password. Env always overrides."""
    if os.environ.get("ARGUS_ADMIN_PASSWORD"):
        return False
    return any(
        u.role is Role.ADMIN and u.seeded_with_default and not u.disabled
        for u in store.list_users()
    )
