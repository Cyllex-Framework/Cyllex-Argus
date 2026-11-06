import sqlite3

import httpx
import pytest
from typer.testing import CliRunner

from cyllex_argus.cli import app as cli_module
from cyllex_argus.cli.app import app
from cyllex_argus.config.settings import ArgusConfig
from cyllex_argus.documents.fetch import Fetcher
from cyllex_argus.knowledge.sqlite_store import SQLiteStore
from cyllex_argus.services import Services
from tests.support import World, _public_resolver

runner = CliRunner(env={"COLUMNS": "200"})


@pytest.fixture
def world(tmp_path, monkeypatch):
    world = World(tmp_path / "home")
    world.investigate()

    def factory():
        http = httpx.Client()
        return Services(
            paths=world.paths, config=ArgusConfig(feeds=[]), store=SQLiteStore(world.paths.db_file),
            llm=world.llm, http=http,
            fetcher=Fetcher(http, max_bytes=1000, sleep=lambda s: None, resolve_host=_public_resolver),
        )

    monkeypatch.setattr(cli_module, "services_factory", factory)
    return world


def _rows(world) -> list[tuple[int, str]]:
    conn = sqlite3.connect(str(world.paths.db_file))
    try:
        return conn.execute("SELECT investigation_id, created_at FROM pipeline_events ORDER BY id").fetchall()
    finally:
        conn.close()


def _age(world, investigation_id, created_at):
    conn = sqlite3.connect(str(world.paths.db_file))
    try:
        with conn:
            conn.execute("UPDATE pipeline_events SET created_at = ? WHERE investigation_id = ?",
                         (created_at, investigation_id))
    finally:
        conn.close()


def _second_investigation(world):
    world.investigate()
    assert {r[0] for r in _rows(world)} == {1, 2}


def test_no_arguments_prints_the_size_and_deletes_nothing(world):
    before = len(_rows(world))
    result = runner.invoke(app, ["trace", "purge"])
    assert result.exit_code == 0, result.output
    assert f"{before} events, ~" in result.output and result.output.strip().endswith("MB")
    assert len(_rows(world)) == before


def test_before_deletes_only_older_rows(world):
    _second_investigation(world)
    _age(world, 1, "2020-01-01T00:00:00+00:00")
    result = runner.invoke(app, ["trace", "purge", "--before", "2021-01-01"])
    assert result.exit_code == 0, result.output
    assert {r[0] for r in _rows(world)} == {2}


def test_investigation_deletes_only_that_one(world):
    _second_investigation(world)
    assert runner.invoke(app, ["trace", "purge", "--investigation", "1"]).exit_code == 0
    assert {r[0] for r in _rows(world)} == {2}


def test_both_options_narrow_the_selection(world):
    _second_investigation(world)
    _age(world, 1, "2020-01-01T00:00:00+00:00")
    _age(world, 2, "2020-01-01T00:00:00+00:00")
    assert runner.invoke(app, ["trace", "purge", "--before", "2021-01-01", "--investigation", "1"]).exit_code == 0
    assert {r[0] for r in _rows(world)} == {2}


def test_a_bad_date_is_refused(world):
    assert runner.invoke(app, ["trace", "purge", "--before", "yesterday"]).exit_code != 0
