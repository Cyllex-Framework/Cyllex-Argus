"""Tests for `argus set-admin-password` and `argus reset-admin-password`.

Covers the operator-facing happy paths: both commands persist a bcrypt hash under
`[auth] admin_password_hash` in argus.toml, and `reset-admin-password` without an argument
restores the shipped default so a locked-out operator can log back in.
"""

from __future__ import annotations

import bcrypt
import httpx
import pytest
from typer.testing import CliRunner

from cyllex_argus.cli import app as cli_module
from cyllex_argus.cli.app import app
from cyllex_argus.config.settings import ArgusConfig, get_paths, load_config
from cyllex_argus.documents.fetch import Fetcher
from cyllex_argus.knowledge.sqlite_store import SQLiteStore
from cyllex_argus.services import Services
from cyllex_argus.web.api.auth import DEFAULT_ADMIN_PASSWORD, DEFAULT_ADMIN_USERNAME
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
    # `argus init` is a prerequisite for either command (the toml must exist to write into).
    assert runner.invoke(app, ["init"]).exit_code == 0
    return home


def _load_auth(home):
    cfg = load_config(get_paths(home).config_file)
    return cfg.auth


def test_set_admin_password_writes_bcrypt_hash(cli):
    r = runner.invoke(app, ["set-admin-password", "s3cret"])
    assert r.exit_code == 0, r.output
    auth = _load_auth(cli)
    assert auth.admin_username == "admin"
    assert auth.admin_password_hash.startswith("$2b$") or auth.admin_password_hash.startswith("$2a$")
    assert bcrypt.checkpw(b"s3cret", auth.admin_password_hash.encode("ascii"))


def test_set_admin_password_respects_username_flag(cli):
    r = runner.invoke(app, ["set-admin-password", "s3cret", "--username", "analyst"])
    assert r.exit_code == 0, r.output
    auth = _load_auth(cli)
    assert auth.admin_username == "analyst"


def test_reset_admin_password_without_arg_restores_the_default(cli):
    """Break-glass: operator lost the password. `argus reset-admin-password` with no argument
    puts the account back on 'admin' / 'Argus123' so they can log in and set a real one."""
    runner.invoke(app, ["set-admin-password", "some-forgotten-pass"])
    r = runner.invoke(app, ["reset-admin-password"])
    assert r.exit_code == 0, r.output
    # The CLI must say loudly that the default is in effect, so no one deploys with it.
    assert DEFAULT_ADMIN_PASSWORD in r.output
    assert "default" in r.output.lower()
    auth = _load_auth(cli)
    assert bcrypt.checkpw(DEFAULT_ADMIN_PASSWORD.encode("utf-8"), auth.admin_password_hash.encode("ascii"))
    assert auth.admin_username == DEFAULT_ADMIN_USERNAME


def test_reset_admin_password_with_arg_matches_set(cli):
    """With an argument it is a semantic alias of set-admin-password — same persisted state."""
    r = runner.invoke(app, ["reset-admin-password", "chosen-pass"])
    assert r.exit_code == 0, r.output
    auth = _load_auth(cli)
    assert bcrypt.checkpw(b"chosen-pass", auth.admin_password_hash.encode("ascii"))


def test_reset_admin_password_respects_username_flag(cli):
    r = runner.invoke(app, ["reset-admin-password", "--username", "analyst"])
    assert r.exit_code == 0, r.output
    auth = _load_auth(cli)
    assert auth.admin_username == "analyst"
    assert bcrypt.checkpw(DEFAULT_ADMIN_PASSWORD.encode("utf-8"), auth.admin_password_hash.encode("ascii"))
