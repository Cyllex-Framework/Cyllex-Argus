"""The role policy: reads reader+, writes operator+, admin-only and any-session carve-outs."""

from __future__ import annotations

from cyllex_argus.knowledge.models import Role
from cyllex_argus.web.authz import required_role


def test_reads_are_reader():
    assert required_role("GET", "/api/threats") is Role.READER
    assert required_role("GET", "/api/investigations/5/dashboard") is Role.READER


def test_writes_default_to_operator():
    assert required_role("POST", "/api/jobs") is Role.OPERATOR
    assert required_role("DELETE", "/api/investigations/5") is Role.OPERATOR
    assert required_role("PUT", "/api/sources/9") is Role.OPERATOR


def test_user_and_db_admin_routes_require_admin():
    assert required_role("GET", "/api/admin/db/export") is Role.ADMIN
    assert required_role("DELETE", "/api/admin/db") is Role.ADMIN
    assert required_role("POST", "/api/users") is Role.ADMIN
    assert required_role("PUT", "/api/users/5") is Role.ADMIN


def test_any_session_routes_are_reader():
    assert required_role("POST", "/api/auth/logout") is Role.READER
    assert required_role("GET", "/api/auth/me") is Role.READER
    assert required_role("PUT", "/api/users/me/password") is Role.READER


def test_settings_reads_are_operator():
    assert required_role("GET", "/api/settings") is Role.OPERATOR
    assert required_role("GET", "/api/settings/webhooks") is Role.OPERATOR
