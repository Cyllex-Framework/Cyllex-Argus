import io
import sys

import httpx
import pytest
from typer.testing import CliRunner

from cyllex_argus.cli import app as cli_module
from cyllex_argus.cli.app import app
from cyllex_argus.config.settings import ArgusConfig, get_paths
from cyllex_argus.documents.fetch import Fetcher
from cyllex_argus.knowledge.models import AliasOrigin, Assessment, AssessmentStatus  # noqa: F401
from cyllex_argus.knowledge.sqlite_store import SQLiteStore
from cyllex_argus.services import Services
from tests.support import ScriptedLLM, _public_resolver, web_transport

runner = CliRunner(env={"COLUMNS": "200"})


@pytest.fixture
def cli(tmp_path, monkeypatch):
    state = {"llm": ScriptedLLM(), "transport": None}
    home = tmp_path / "home"

    def factory():
        paths = get_paths(home)
        paths.ensure()
        http = httpx.Client(transport=state["transport"] or web_transport())
        return Services(
            paths=paths, config=ArgusConfig(feeds=[]), store=SQLiteStore(paths.db_file),
            llm=state["llm"], http=http,
            fetcher=Fetcher(http, max_bytes=100_000, sleep=lambda s: None, resolve_host=_public_resolver),
        )

    monkeypatch.setattr(cli_module, "services_factory", factory)
    state["home"] = home
    return state


def test_init_creates_config_and_keeps_it(cli):
    first = runner.invoke(app, ["init"])
    assert first.exit_code == 0, first.output
    assert (cli["home"] / "argus.toml").exists()
    assert "Next: run `argus attack update`" in first.output
    second = runner.invoke(app, ["init"])
    assert "Kept existing" in second.output


def test_investigate_requires_attack_data(cli):
    result = runner.invoke(app, ["investigate", "Scattered Spider"])
    assert result.exit_code == 1
    assert "argus attack update" in result.output


def test_backup_defaults_to_home_backups_dir(cli):
    """`argus backup` with no flag writes a timestamped file under ~/.cyllex-argus/backups/."""
    import sqlite3
    assert runner.invoke(app, ["init"]).exit_code == 0
    result = runner.invoke(app, ["backup"])
    assert result.exit_code == 0, result.output
    assert "Backup written" in result.output
    backups_dir = cli["home"] / "backups"
    assert backups_dir.is_dir()
    files = list(backups_dir.glob("argus-*.db"))
    assert len(files) == 1, f"expected one argus-<stamp>.db, got {files}"
    # The snapshot must be a readable SQLite db (not just an empty file).
    conn = sqlite3.connect(str(files[0]))
    try:
        rows = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    finally:
        conn.close()
    assert len(rows) > 0, "backup contained no tables"


def test_backup_honours_explicit_out(cli, tmp_path):
    assert runner.invoke(app, ["init"]).exit_code == 0
    dest = tmp_path / "nested" / "my-backup.db"
    result = runner.invoke(app, ["backup", "--out", str(dest)])
    assert result.exit_code == 0, result.output
    assert dest.exists()
    assert dest.stat().st_size > 0




def test_full_flow(cli):
    assert runner.invoke(app, ["attack", "update"]).exit_code == 0
    result = runner.invoke(app, ["investigate", "Scattered Spider"])
    assert result.exit_code == 0, result.output
    assert "finished" in result.output
    assert "validated: 2" in result.output

    shown = runner.invoke(app, ["show", "octo tempest", "--citations"])
    assert shown.exit_code == 0, shown.output
    assert "Spearphishing Voice (T1566.004)" in shown.output
    assert "corroborated" in shown.output
    assert "impersonated an employee" in shown.output

    status = runner.invoke(app, ["status"])
    assert "failed: 1" in status.output and "404" in status.output












def test_enrich_refuses_when_the_enricher_is_disabled(cli):
    """Default install must never hit the network for enrichment."""
    result = runner.invoke(app, ["enrich", "example.com", "--type", "domain-name", "--with", "crt.sh"])
    assert result.exit_code == 1
    assert "disabled" in result.output.lower()


def test_enrich_list_shows_each_enrichers_outbound_statement(cli):
    """--list must print the outbound statement so the operator sees what would leave the machine,
    with no required indicator or --with (listing the catalog is a standalone mode)."""
    result = runner.invoke(app, ["enrich", "--list"])
    assert result.exit_code == 0, result.output
    assert "crt.sh" in result.output
    assert "disabled" in result.output.lower()
    assert "outbound" in result.output.lower()


def test_enrich_requires_an_indicator_without_list(cli):
    result = runner.invoke(app, ["enrich"])
    assert result.exit_code == 1
    assert "indicator" in result.output.lower()


def test_enrich_requires_with_when_an_indicator_is_given(cli):
    result = runner.invoke(app, ["enrich", "example.com"])
    assert result.exit_code == 1
    assert "--with" in result.output or "with" in result.output.lower()


def test_entity_merge_fuses_duplicates_and_recomputes(cli):
    """The classic post-ATT&CK-update scenario: a document-origin duplicate of C0027 and the
    official ATT&CK-origin one are merged into a single entity."""
    from cyllex_argus.config.settings import get_paths
    from cyllex_argus.knowledge.sqlite_store import SQLiteStore
    paths = get_paths(cli["home"])
    paths.ensure()
    with SQLiteStore(paths.db_file) as store:
        duplicate = store.create_entity("campaign", "DUP-NAME", AliasOrigin.DOCUMENT)
        official = store.create_entity(
            "campaign", "OFFICIAL", AliasOrigin.ATTACK,
            external_id="X-TEST-0001", entity_id="campaign--official",
        )
    cancel = runner.invoke(app, ["entity-merge", duplicate.id, official.id])
    assert cancel.exit_code == 1 and "proceed" in cancel.output.lower()
    confirm = runner.invoke(app, ["entity-merge", duplicate.id, official.id, "--yes"])
    assert confirm.exit_code == 0, confirm.output
    assert "Merged" in confirm.output
    with SQLiteStore(paths.db_file) as store:
        assert store.get_entity(duplicate.id) is None
        survivor = store.find_by_external_id("X-TEST-0001")
        assert survivor is not None and survivor.id == official.id


def test_entity_merge_refuses_cross_stix_type(cli):
    from cyllex_argus.config.settings import get_paths
    from cyllex_argus.knowledge.sqlite_store import SQLiteStore
    paths = get_paths(cli["home"])
    paths.ensure()
    with SQLiteStore(paths.db_file) as store:
        a = store.create_entity("intrusion-set", "WeirdGroupA", AliasOrigin.DOCUMENT)
        b = store.create_entity("campaign", "WeirdGroupB", AliasOrigin.DOCUMENT)
    result = runner.invoke(app, ["entity-merge", a.id, b.id, "--yes"])
    assert result.exit_code == 1
    assert "stix" in result.output.lower() or "type" in result.output.lower()


def test_identity_set_annotates_an_identity(cli):
    """identity-set stores sector/country on an identity entity and the readback shows them."""
    from cyllex_argus.config.settings import get_paths
    from cyllex_argus.knowledge.sqlite_store import SQLiteStore
    paths = get_paths(cli["home"])
    paths.ensure()
    with SQLiteStore(paths.db_file) as store:
        store.create_entity("identity", "Acme Corp", AliasOrigin.DOCUMENT)
    result = runner.invoke(app, [
        "identity-set", "Acme Corp", "--sector", "energy", "--country", "DE",
    ])
    assert result.exit_code == 0, result.output
    assert "sector=energy" in result.output and "country=DE" in result.output


def test_identity_set_refuses_a_non_identity_entity(cli):
    from cyllex_argus.config.settings import get_paths
    from cyllex_argus.knowledge.sqlite_store import SQLiteStore
    paths = get_paths(cli["home"])
    paths.ensure()
    with SQLiteStore(paths.db_file) as store:
        store.create_entity("intrusion-set", "Fake Actor", AliasOrigin.ATTACK)
    result = runner.invoke(app, ["identity-set", "Fake Actor", "--sector", "energy"])
    assert result.exit_code == 1
    assert "not an identity" in result.output


def test_query_targets_lists_actors_ranked_by_assessment_count(cli):
    """End-to-end: annotate two identities, add targets assessments, query by sector."""
    from cyllex_argus.config.settings import get_paths
    from cyllex_argus.knowledge.sqlite_store import SQLiteStore
    paths = get_paths(cli["home"])
    paths.ensure()
    with SQLiteStore(paths.db_file) as store:
        actor_a = store.create_entity("intrusion-set", "Alpha", AliasOrigin.ATTACK)
        actor_b = store.create_entity("intrusion-set", "Beta", AliasOrigin.ATTACK)
        bank_1 = store.create_entity("identity", "Bank One", AliasOrigin.DOCUMENT)
        bank_2 = store.create_entity("identity", "Bank Two", AliasOrigin.DOCUMENT)
        for ident in (bank_1, bank_2):
            store.set_entity_attributes(ident.id, sector="financial-services", country="US")
        store.upsert_assessment(Assessment(
            subject_entity_id=actor_a.id, predicate="targets", object_entity_id=bank_1.id,
            status=AssessmentStatus.CORROBORATED, confidence=80, admiralty="A2",
        ))
        store.upsert_assessment(Assessment(
            subject_entity_id=actor_a.id, predicate="targets", object_entity_id=bank_2.id,
            status=AssessmentStatus.CORROBORATED, confidence=80, admiralty="A2",
        ))
        store.upsert_assessment(Assessment(
            subject_entity_id=actor_b.id, predicate="targets", object_entity_id=bank_1.id,
            status=AssessmentStatus.CORROBORATED, confidence=80, admiralty="A2",
        ))
    result = runner.invoke(app, ["query-targets", "--sector", "financial-services"])
    assert result.exit_code == 0, result.output
    assert "Alpha" in result.output and "Beta" in result.output
    # Alpha (2 assessments) should appear before Beta (1 assessment) in the ranked table.
    assert result.output.index("Alpha") < result.output.index("Beta")


def test_query_targets_requires_at_least_one_filter(cli):
    result = runner.invoke(app, ["query-targets"])
    assert result.exit_code == 1
    assert "at least" in result.output.lower()


def test_import_stix_merges_a_bundle_and_prints_a_report(cli, tmp_path):
    import json as _json
    bundle = tmp_path / "bundle.json"
    bundle.write_text(_json.dumps({
        "type": "bundle",
        "id": "bundle--aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "created": "2024-06-01T00:00:00Z",
        "objects": [
            {"type": "intrusion-set", "id": "intrusion-set--1", "name": "FakeActor",
             "aliases": ["AKA-ONE", "AKA-TWO"]},
            {"type": "malware", "id": "malware--1", "name": "FakeMalware"},
            {"type": "relationship", "id": "relationship--1", "relationship_type": "uses",
             "source_ref": "intrusion-set--1", "target_ref": "malware--1"},
        ],
    }), encoding="utf-8")
    result = runner.invoke(app, ["import-stix", str(bundle)])
    assert result.exit_code == 0, result.output
    assert "entities added:   2" in result.output
    assert "aliases added:    2" in result.output
    assert "claims added:     1" in result.output


def test_import_stix_refuses_non_bundle_input(cli, tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text('{"not": "a bundle"}', encoding="utf-8")
    result = runner.invoke(app, ["import-stix", str(bad)])
    assert result.exit_code == 1
    assert "STIX bundle" in result.output


def test_paused_investigation_exits_2(cli):
    cli["llm"] = ScriptedLLM(analyst_error_on_call=1)
    runner.invoke(app, ["attack", "update"])
    result = runner.invoke(app, ["investigate", "Scattered Spider"])
    assert result.exit_code == 2
    assert "Re-run the same command" in result.output


def test_show_unknown_entity(cli):
    result = runner.invoke(app, ["show", "Nobody"])
    assert result.exit_code == 1
    assert "Unknown entity" in result.output


def test_sources_reliability_recomputes_confidence(cli):
    runner.invoke(app, ["attack", "update"])
    runner.invoke(app, ["investigate", "Scattered Spider"])
    listed = runner.invoke(app, ["sources", "list"])
    assert "Mandiant" in listed.output
    assert runner.invoke(app, ["sources", "set-reliability", "Mandiant", "Z"]).exit_code == 1
    assert runner.invoke(app, ["sources", "set-reliability", "Nobody", "A"]).exit_code == 1
    before = runner.invoke(app, ["show", "Scattered Spider"]).output
    assert runner.invoke(app, ["sources", "set-reliability", "mandiant", "a"]).exit_code == 0
    after = runner.invoke(app, ["show", "Scattered Spider"]).output
    assert before != after
    assert "A2" in after


def test_ingest_command(cli, tmp_path):
    runner.invoke(app, ["attack", "update"])
    memo = tmp_path / "memo.txt"
    memo.write_text("Memo\n\nScattered Spider operators called the IT help desk and impersonated "
                    "an employee to reset MFA.", encoding="utf-8")
    result = runner.invoke(app, ["ingest", str(memo), "--target", "Scattered Spider"])
    assert result.exit_code == 0, result.output
    assert "validated: 1" in result.output


def test_resume_without_force_bails_out_on_finished_investigation(cli, tmp_path):
    """A clean FINISHED investigation returns immediately with the "already finished" message
    even without --force. The guard protects the operator from paying LLM tokens by mistake."""
    runner.invoke(app, ["attack", "update"])
    memo = tmp_path / "memo.txt"
    memo.write_text("Memo\n\nScattered Spider operators called the IT help desk.", encoding="utf-8")
    runner.invoke(app, ["ingest", str(memo), "--target", "Scattered Spider"])
    # The ingest above creates investigation #1 and finishes it. A plain resume should bail.
    result = runner.invoke(app, ["resume", "1"])
    assert result.exit_code == 0, result.output
    assert "already finished" in result.output.lower()


def test_resume_with_force_reruns_a_finished_investigation(cli, tmp_path):
    """`--force` flips the state back to RUNNING and re-processes the docs. Nothing new to
    extract from the same prompt version — the stage counts stay the same — but the command
    does not bail out, which is the semantic the CLI must deliver."""
    runner.invoke(app, ["attack", "update"])
    memo = tmp_path / "memo.txt"
    memo.write_text("Memo\n\nScattered Spider operators called the IT help desk.", encoding="utf-8")
    runner.invoke(app, ["ingest", str(memo), "--target", "Scattered Spider"])
    result = runner.invoke(app, ["resume", "1", "--force"])
    assert result.exit_code == 0, result.output
    # No "already finished" message now — the forced path ran.
    assert "already finished" not in result.output.lower()


def test_untrusted_names_are_not_parsed_as_markup(cli):
    services = cli_module.services_factory()
    try:
        services.store.get_or_create_publisher("Vendor [/x] Labs", domain="[bold]labs[/bold].example")
        actor = services.store.create_entity("intrusion-set", "APT [aka Cozy Bear]", AliasOrigin.USER)
        tool = services.store.create_entity("malware", "Loader [/x] tail", AliasOrigin.USER)
        services.store.upsert_assessment(Assessment(
            subject_entity_id=actor.id, predicate="uses", object_entity_id=tool.id,
            status=AssessmentStatus.SINGLE_SOURCE, confidence=50, admiralty="C3",
        ))
    finally:
        services.close()

    listed = runner.invoke(app, ["sources", "list"])
    assert listed.exit_code == 0, listed.output
    assert "Vendor [/x] Labs" in listed.output
    assert "[bold]labs[/bold].example" in listed.output

    shown = runner.invoke(app, ["show", "APT [aka Cozy Bear]", "--citations"])
    assert shown.exit_code == 0, shown.output
    assert "APT [aka Cozy Bear]" in shown.output
    assert "Loader [/x] tail" in shown.output


def test_say_prints_untrusted_text_verbatim(capsys):
    cli_module._say("quote :warning: [bold]x[/bold] [/y]")
    assert capsys.readouterr().out.strip() == "quote :warning: [bold]x[/bold] [/y]"


def test_attack_update_rejects_non_json_download(cli):
    cli["transport"] = httpx.MockTransport(lambda request: httpx.Response(200, content=b"<html>portal</html>"))
    result = runner.invoke(app, ["attack", "update"])
    assert result.exit_code == 1
    assert "Could not update ATT&CK data" in result.output
    assert not (cli["home"] / "attack" / "enterprise-attack.json").exists()


@pytest.mark.parametrize("content", [
    "this is not json",
    "[]",
    '{"objects": [{"type": "intrusion-set", "name": "No id"}]}',
])
def test_unreadable_attack_data_asks_for_update(cli, content):
    paths = get_paths(cli["home"])
    paths.ensure()
    paths.attack_file.write_text(content, encoding="utf-8")
    result = runner.invoke(app, ["investigate", "Scattered Spider"])
    assert result.exit_code == 1
    assert "argus attack update" in result.output


def test_set_reliability_reports_unreadable_attack_data(cli):
    runner.invoke(app, ["attack", "update"])
    runner.invoke(app, ["investigate", "Scattered Spider"])
    get_paths(cli["home"]).attack_file.write_text("this is not json", encoding="utf-8")
    result = runner.invoke(app, ["sources", "set-reliability", "Mandiant", "A"])
    assert result.exit_code == 1
    assert "not recomputed" in result.output and "argus attack update" in result.output


def test_main_survives_output_that_the_console_encoding_cannot_represent(monkeypatch):
    raw = io.BytesIO()
    stream = io.TextIOWrapper(raw, encoding="cp1252")
    monkeypatch.setattr(sys, "stdout", stream)
    monkeypatch.setattr(sys, "stderr", stream)
    cli_module.main(version=False)
    cli_module._say("Привет → мир")
    stream.flush()
    assert b"?" in raw.getvalue()
