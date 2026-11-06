"""`argus user ...` management and admin recovery through reset-admin-password."""

from __future__ import annotations

import httpx
import pytest
from typer.testing import CliRunner

from cyllex_argus.cli import app as cli_module
from cyllex_argus.cli.app import app
from cyllex_argus.config.settings import ArgusConfig, get_paths
from cyllex_argus.documents.fetch import Fetcher
from cyllex_argus.knowledge.models import Role
from cyllex_argus.knowledge.sqlite_store import SQLiteStore
from cyllex_argus.services import Services
from cyllex_argus.web import auth_core
from tests.support import ScriptedLLM, _public_resolver, web_transport

runner = CliRunner(env={"COLUMNS": "200"})


@pytest.fixture
def cli(tmp_path, monkeypatch):
    home = tmp_path / "home"

    def factory():
        paths = get_paths(home)
        paths.ensure()
        http = httpx.Client(transport=web_transport())
        return Services(
            paths=paths, config=ArgusConfig(feeds=[]), store=SQLiteStore(paths.db_file),
            llm=ScriptedLLM(), http=http,
            fetcher=Fetcher(http, max_bytes=100_000, sleep=lambda s: None, resolve_host=_public_resolver),
        )

    monkeypatch.setattr(cli_module, "services_factory", factory)
    assert runner.invoke(app, ["init"]).exit_code == 0
    return home


def _store(home) -> SQLiteStore:
    return SQLiteStore(get_paths(home).db_file)


def test_user_add_creates_a_resolvable_user(cli):
    r = runner.invoke(app, ["user", "add", "bob", "--role", "operator", "--password", "bob-pass1"])
    assert r.exit_code == 0, r.output
    with _store(cli) as store:
        user = store.get_user_by_username("bob")
        assert user is not None and user.role is Role.OPERATOR


def test_user_list_shows_roles(cli):
    runner.invoke(app, ["user", "add", "al", "--role", "admin", "--password", "al-pass12"])
    r = runner.invoke(app, ["user", "list"])
    assert r.exit_code == 0 and "al" in r.output and "admin" in r.output


def test_user_disable_and_enable(cli):
    runner.invoke(app, ["user", "add", "c", "--role", "reader", "--password", "c-pass123"])
    assert runner.invoke(app, ["user", "disable", "c"]).exit_code == 0
    with _store(cli) as store:
        assert store.get_user_by_username("c").disabled
    assert runner.invoke(app, ["user", "enable", "c"]).exit_code == 0
    with _store(cli) as store:
        assert not store.get_user_by_username("c").disabled


def test_user_passwd_changes_the_hash(cli):
    runner.invoke(app, ["user", "add", "d", "--role", "reader", "--password", "d-pass123"])
    with _store(cli) as store:
        old = store.user_password_hash(store.get_user_by_username("d").id)
    assert runner.invoke(app, ["user", "passwd", "d", "--password", "d-newpass1"]).exit_code == 0
    with _store(cli) as store:
        assert store.user_password_hash(store.get_user_by_username("d").id) != old


def test_user_delete_tombstones(cli):
    runner.invoke(app, ["user", "add", "e", "--role", "reader", "--password", "e-pass123"])
    assert runner.invoke(app, ["user", "delete", "e"]).exit_code == 0
    with _store(cli) as store:
        assert store.get_user_by_username("e") is None


def test_reset_admin_password_updates_the_store_admin(cli):
    r = runner.invoke(app, ["reset-admin-password", "chosen-pass"])
    assert r.exit_code == 0, r.output
    with _store(cli) as store:
        admin = store.get_user_by_username("admin")
        assert admin is not None and admin.role is Role.ADMIN
        assert auth_core.verify_password("chosen-pass", store.user_password_hash(admin.id))


def test_deleting_the_last_admin_is_refused(cli):
    runner.invoke(app, ["reset-admin-password", "admin-pass1"])
    r = runner.invoke(app, ["user", "delete", "admin"])
    assert r.exit_code != 0 and "last admin" in r.output.lower()
