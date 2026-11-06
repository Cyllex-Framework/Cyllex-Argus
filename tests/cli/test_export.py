import json

import httpx
import pytest
from typer.testing import CliRunner

from cyllex_argus.cli import app as cli_module
from cyllex_argus.cli.app import app
from cyllex_argus.config.settings import ArgusConfig, get_paths
from cyllex_argus.documents.fetch import Fetcher
from cyllex_argus.knowledge.models import AliasOrigin, Assessment, AssessmentStatus
from cyllex_argus.knowledge.sqlite_store import SQLiteStore
from cyllex_argus.services import Services
from tests.support import ScriptedLLM, _public_resolver, web_transport

runner = CliRunner(env={"COLUMNS": "200"})


@pytest.fixture
def investigated(tmp_path, monkeypatch):
    llm = ScriptedLLM()

    def factory():
        paths = get_paths(tmp_path / "home")
        paths.ensure()
        http = httpx.Client(transport=web_transport())
        return Services(
            paths=paths, config=ArgusConfig(feeds=[]), store=SQLiteStore(paths.db_file), llm=llm,
            http=http,
            fetcher=Fetcher(http, max_bytes=100_000, sleep=lambda s: None, resolve_host=_public_resolver),
        )

    monkeypatch.setattr(cli_module, "services_factory", factory)
    assert runner.invoke(app, ["attack", "update"]).exit_code == 0
    assert runner.invoke(app, ["investigate", "Scattered Spider"]).exit_code == 0
    return llm


def test_export_markdown_to_file(investigated, tmp_path):
    # The `investigated` fixture has already run an investigation, and a finished run writes
    # the actor's summary (config.pipeline.summary_on_finish), so count what EXPORT asks for
    # on top of that rather than the absolute number of summary calls in the process.
    before = len(investigated.calls_for("summary"))
    out = tmp_path / "spider.md"
    result = runner.invoke(app, ["export", "Scattered Spider", "--format", "markdown", "-o", str(out)])
    assert result.exit_code == 0, result.output
    text = out.read_text(encoding="utf-8")
    assert "## Executive summary" in text
    assert "Spearphishing Voice (T1566.004)" in text
    assert len(investigated.calls_for("summary")) == before + 1


def test_export_markdown_without_summary(investigated):
    before = len(investigated.calls_for("summary"))
    result = runner.invoke(app, ["export", "Scattered Spider", "--no-summary"])
    assert result.exit_code == 0
    assert "Executive summary" not in result.output
    assert len(investigated.calls_for("summary")) == before


def test_export_stix_to_stdout(investigated):
    result = runner.invoke(app, ["export", "Octo Tempest", "--format", "stix"])
    assert result.exit_code == 0, result.output
    bundle = json.loads(result.stdout)
    assert bundle["type"] == "bundle"
    [relationship] = [o for o in bundle["objects"] if o["type"] == "relationship"]
    assert relationship["x_argus_target_external_id"] == "T1566.004"
    # ATT&CK objects are never re-emitted; the relationship only references them.
    assert {o["type"] for o in bundle["objects"]} == {"relationship"}
    assert "Skipped" not in result.stderr


def _add_entity(kind: str, name: str, subject_of: str | None = None) -> None:
    """Add an entity straight to the database, optionally asserting `indicates` on an existing entity."""
    services = cli_module.services_factory()
    try:
        entity = services.store.create_entity(kind, name, AliasOrigin.DOCUMENT)
        if subject_of is not None:
            target = services.store.find_by_alias(subject_of)
            services.store.upsert_assessment(Assessment(
                subject_entity_id=entity.id, predicate="indicates", object_entity_id=target.id,
                status=AssessmentStatus.SINGLE_SOURCE, confidence=30, admiralty="F3",
            ))
    finally:
        services.close()


NON_LATIN_NAME = "Actor → 日本語"


def test_export_markdown_to_stdout_is_utf8_whatever_the_console_encoding(investigated):
    _add_entity("intrusion-set", NON_LATIN_NAME)
    legacy = CliRunner(env={"COLUMNS": "200"}, charset="cp1252")
    result = legacy.invoke(app, ["export", NON_LATIN_NAME, "--no-summary"])
    assert result.exit_code == 0, result.output
    text = result.stdout_bytes.decode("utf-8")
    assert text.startswith(f"# {NON_LATIN_NAME}\n")
    assert not text.endswith("\n\n")


def test_export_stix_reports_facts_it_could_not_map(investigated):
    _add_entity("indicator", "some weird value", subject_of="Scattered Spider")
    result = runner.invoke(app, ["export", "Scattered Spider", "--format", "stix"])
    assert result.exit_code == 0, result.output
    assert "Skipped 1 fact(s) with no STIX mapping" in result.stderr
    bundle = json.loads(result.stdout)
    assert not any(o.get("name") == "some weird value" for o in bundle["objects"])


def test_export_stix_warns_when_the_bundle_is_empty(investigated):
    _add_entity("indicator", "some weird value")
    result = runner.invoke(app, ["export", "some weird value", "--format", "stix"])
    assert result.exit_code == 0, result.output
    assert "no objects" in result.stderr
