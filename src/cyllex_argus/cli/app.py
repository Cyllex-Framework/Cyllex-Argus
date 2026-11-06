"""Command-line interface for Cyllex Argus."""

from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import sys
import threading
import webbrowser
from collections.abc import Callable
from datetime import UTC, date, datetime
from pathlib import Path
from typing import NoReturn

import httpx
import typer
import uvicorn
from rich.console import Console
from rich.table import Table
from rich.text import Text

from cyllex_argus import __version__
from cyllex_argus.attack.catalog import AttackCatalog, download_attack, load_catalog_into_store
from cyllex_argus.config.settings import ConfigError, save_config
from cyllex_argus.enrichment import (
    EnrichmentDisabledError,
    EnrichmentRequest,
    EnrichmentUnavailable,
    available_enrichers,
)
from cyllex_argus.exporters.markdown import render_markdown
from cyllex_argus.exporters.stix import to_stix_bundle
from cyllex_argus.exporters.summary import summarize_profile
from cyllex_argus.importers import import_stix_bundle
from cyllex_argus.knowledge.models import TLP, InvestigationState
from cyllex_argus.knowledge.names import normalize_name
from cyllex_argus.knowledge.profile import Profile, build_profile
from cyllex_argus.llm.base import InvalidOutput, LLMUnavailable, RateLimited
from cyllex_argus.pipeline.investigation import InvestigationReport
from cyllex_argus.services import MissingAttackData, Services, build_services

app = typer.Typer(help="Cyllex Argus: AI-powered adversary intelligence.", no_args_is_help=True)


attack_app = typer.Typer(help="MITRE ATT&CK reference data.", no_args_is_help=True)
sources_app = typer.Typer(help="Publishers and their Admiralty reliability.", no_args_is_help=True)
app.add_typer(attack_app, name="attack")
trace_app = typer.Typer(help="Pipeline trace data.", no_args_is_help=True)
app.add_typer(sources_app, name="sources")
app.add_typer(trace_app, name="trace")

services_factory: Callable[[], Services] = build_services
RELIABILITY_LETTERS = ("A", "B", "C", "D", "E", "F")


def _say(message: str, style: str | None = None, stderr: bool = False, soft_wrap: bool = False) -> None:
    Console(stderr=stderr).print(
        message, style=style, markup=False, highlight=False, emoji=False, soft_wrap=soft_wrap
    )


def _cell(value: object) -> Text:
    """Table cells hold untrusted names; Text keeps Rich from parsing them as markup."""
    return Text(str(value))


def _fail(message: str) -> NoReturn:
    _say(message, style="red", stderr=True)
    raise typer.Exit(1)


def _open() -> Services:
    try:
        services = services_factory()
    except ConfigError as exc:
        _fail(str(exc))
    services.log = lambda message: _say(message, style="yellow", stderr=True)
    return services


def _version(value: bool) -> None:
    if value:
        typer.echo(f"Cyllex Argus {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False, "--version", callback=_version, is_eager=True, help="Show the version and exit."
    ),
) -> None:
    """Cyllex Argus: AI-powered adversary intelligence."""
    # Redirected Windows output is often cp1252; never crash on characters it cannot encode.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass


@app.command()
def init() -> None:
    """Create the data directory, a default argus.toml and the database."""
    services = _open()
    try:
        config_file = services.paths.config_file
        if config_file.exists():
            _say(f"Kept existing {config_file}")
        else:
            save_config(services.config, config_file)
            _say(f"Created {config_file}")
        _say(f"Database ready at {services.paths.db_file}")
        if shutil.which(services.config.llm.claude_binary) is None:
            _say("Claude Code CLI not found. Install it and run `claude` once to log in.", style="yellow")
        else:
            _say("Claude Code CLI found.")
        if not services.attack_ready():
            _say("Next: run `argus attack update`.")
    finally:
        services.close()


@attack_app.command("update")
def attack_update() -> None:
    """Download MITRE ATT&CK Enterprise and load its groups, software and techniques."""
    services = _open()
    try:
        download_attack(services.paths.attack_file, services.http)
        catalog = AttackCatalog.from_file(services.paths.attack_file)
        created = load_catalog_into_store(catalog, services.store)
        _say(
            f"ATT&CK loaded: {len(catalog.active_techniques())} techniques, {len(catalog.groups)} groups, "
            f"{len(catalog.software)} software ({created} new entities)."
        )
    except (httpx.HTTPError, json.JSONDecodeError, OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        _fail(f"Could not update ATT&CK data: {exc}")
    finally:
        services.close()


def _print_report(report: InvestigationReport) -> None:
    counts = ", ".join(f"{k}: {v}" for k, v in sorted(report.stage_counts.items())) or "no documents"
    _say(f"Investigation #{report.investigation_id} ({report.target}): {report.state.value}")
    _say(f"Documents: {counts}")
    _say(f"Claims: {report.claims_accepted} accepted, {report.claims_rejected} rejected")
    if report.message:
        _say(report.message, style="yellow")


def _run(action: Callable[[Services], InvestigationReport]) -> None:
    services = _open()
    try:
        report = action(services)
    except MissingAttackData:
        _fail("ATT&CK data is missing. Run `argus attack update` first.")
    except LLMUnavailable as exc:
        _fail(f"The LLM provider is unavailable: {exc}")
    finally:
        services.close()
    _print_report(report)
    if report.state is InvestigationState.PAUSED:
        raise typer.Exit(2)


@app.command()
def investigate(
    target: str = typer.Argument(..., help='Threat to investigate, e.g. "Scattered Spider".'),
    max_docs: int | None = typer.Option(None, "--max-docs", min=1, help="Maximum documents to collect."),
    concurrency: int = typer.Option(
        1, "--concurrency", "-c", min=1, max=16,
        help="Number of documents the Triage+Analyst stages process in parallel. Default 1 "
             "(sequential, matches pre-0.19 behaviour). Each parallel worker launches its own "
             "Claude Code subprocess, so the practical ceiling is your Claude Code tier's rate "
             "limit — 3-5 is a safe starting point.",
    ),
) -> None:
    """Collect sources, extract claims and consolidate what is known about a threat."""
    _run(lambda s: s.pipeline().investigate(target, max_docs, concurrency=concurrency))


@app.command()
def ingest(
    files: list[Path] = typer.Argument(..., exists=True, dir_okay=False, readable=True),
    target: str | None = typer.Option(None, "--target", "-t", help="Threat the documents are about."),
) -> None:
    """Analyze local documents (PDF, HTML, TXT) with the same pipeline."""
    _run(lambda s: s.pipeline().ingest(files, target))


@app.command()
def resume(
    investigation_id: int = typer.Argument(..., min=1, help="Numeric investigation id to continue."),
    concurrency: int = typer.Option(
        1, "--concurrency", "-c", min=1, max=16,
        help="Documents processed in parallel. Default 1 (sequential). See `argus investigate --help`.",
    ),
    force: bool = typer.Option(
        False, "--force", "-f",
        help="Re-process the investigation even when it is already FINISHED. Useful after an "
             "ANALYST_PROMPT_VERSION bump: `_needs_processing` already compares prompt versions, "
             "so the forced resume re-analyses stored VALIDATED docs with the new prompt. "
             "FAILED and IRRELEVANT docs stay as they are — use the retry endpoint for those.",
    ),
) -> None:
    """Continue a paused, interrupted or finished investigation.

    Without `--force` a FINISHED investigation returns immediately with the "already finished"
    message. With `--force` the investigation state flips to RUNNING, `_process_all` runs over
    the linked documents (skipping those whose prompt_version already matches the current
    ANALYST_PROMPT_VERSION), and the state settles back to FINISHED. The common use case is a
    prompt-engineering pass: bump the version in `analyst.py`, run `argus resume <id> --force`,
    pay the same LLM tokens as the original run, get cleaner output.
    """
    _run(lambda s: s.pipeline().resume(investigation_id, force=force, concurrency=concurrency))


def _print_profile(profile: Profile, with_citations: bool) -> None:
    entity = profile.entity
    _say(f"{entity.name} [{entity.stix_type}]", style="bold")
    _say("Aliases: " + (", ".join(profile.aliases) or "none"))
    if not profile.facts:
        _say(f'No assessments yet. Run `argus investigate "{entity.name}"`.')
        return
    table = Table(show_lines=False)
    for column in ("#", "Subject", "Relation", "Object", "Status", "Conf.", "Admiralty", "Seen", "Sources"):
        table.add_column(column)
    for index, fact in enumerate(profile.facts, start=1):
        seen = f"{fact.first_seen or '?'} .. {fact.last_seen or '?'}" if fact.first_seen or fact.last_seen else "-"
        table.add_row(*(_cell(value) for value in (
            index, fact.subject.label, fact.predicate, fact.object.label, fact.status.value,
            fact.confidence, fact.admiralty, seen, fact.source_count,
        )))
    Console().print(table)
    if with_citations:
        for index, fact in enumerate(profile.facts, start=1):
            _say(f"[{index}] {fact.subject.label} {fact.predicate} {fact.object.label}", style="bold")
            for citation in fact.citations:
                marker = "refutes" if citation.polarity.value == "refutes" else "supports"
                _say(f'  - {citation.publisher} ({citation.published_at or "undated"}, {marker}): "{citation.quote}"')
                _say(f"    {citation.document_title} {citation.location or ''}".rstrip())


@app.command()
def show(
    entity: str = typer.Argument(..., help="Entity name or alias."),
    citations: bool = typer.Option(False, "--citations", help="Print the supporting quotes."),
) -> None:
    """Show the consolidated profile of an entity."""
    services = _open()
    try:
        found = services.store.find_by_alias(entity)
        if found is None:
            _fail(f"Unknown entity: {entity}")
        profile = build_profile(services.store, found)
    finally:
        services.close()
    _print_profile(profile, citations)


@app.command()
def status(
    investigation: int | None = typer.Option(None, "--investigation", "-i", help="Investigation id."),
) -> None:
    """Show document counts and failures for the latest (or a given) investigation."""
    services = _open()
    try:
        if investigation is None:
            inv = services.store.latest_investigation()
        else:
            try:
                inv = services.store.get_investigation(investigation)
            except KeyError:
                _fail(f"Unknown investigation: {investigation}")
        if inv is None:
            _say("No investigations yet.")
            return
        counts = services.store.stage_counts(inv.id)
        failures = services.store.failures(inv.id)
    finally:
        services.close()
    _say(f"Investigation #{inv.id} ({inv.target}): {inv.state.value}, started {inv.started_at:%Y-%m-%d %H:%M}")
    _say("Documents: " + (", ".join(f"{k}: {v}" for k, v in sorted(counts.items())) or "none"))
    for title, reason in failures:
        _say(f"  failed: {title}: {reason}", style="yellow")


@sources_app.command("list")
def sources_list() -> None:
    """List publishers with their reliability, TLP label and the other bylines they cover."""
    from cyllex_argus.knowledge.publisher_merge import find_duplicate_publishers, organisation_keys
    from cyllex_argus.knowledge.publisher_ratings import known_rating
    services = _open()
    try:
        publishers = services.store.list_publishers()
        # One row can speak for several bylines after a merge, and the row is the unit of
        # independence — so an operator about to rate it needs to see whose reporting it covers.
        bylines = {
            publisher.id: [
                name for name in services.store.publisher_names(publisher.id)
                if normalize_name(name) != normalize_name(publisher.name)
            ]
            for publisher in publishers
        }
        keys = organisation_keys(services.store.connection)
        gradeable = sum(
            1 for p in publishers
            if p.reliability == "F" and known_rating(keys.get(p.id)) is not None
        )
        unjudged = sum(1 for p in publishers if p.reliability == "F")
        duplicate_rows = sum(g.rows for g in find_duplicate_publishers(services.store.connection))
    finally:
        services.close()
    table = Table()
    for column in ("Publisher", "Reliability", "TLP", "Domain"):
        table.add_column(column)
    for publisher in publishers:
        tlp_cell = publisher.tlp.value if publisher.tlp else "-"
        # The other bylines go inside the publisher cell rather than in a column of their own:
        # a fifth column wraps at an 80-column terminal, and these names are untrusted text that
        # has to reach the operator intact.
        name = _cell(publisher.name)
        if bylines[publisher.id]:
            name.append("\nalso: " + ", ".join(bylines[publisher.id]), style="dim")
        table.add_row(name, *(_cell(value) for value in (
            publisher.reliability, tlp_cell, publisher.domain or "-",
        )))
    Console().print(table)
    # Lead to the fix. F is the floor `scoring.score` multiplies by, not a neutral middle, so a
    # table of unjudged sources is a table of suppressed confidence — and a table with one
    # organisation on several rows is a table that corroborates itself.
    if gradeable:
        _say(f"{gradeable} of the {unjudged} unjudged publisher(s) have a rating Argus ships: "
             "`argus sources rate-known --dry-run` shows it.", style="yellow")
    elif unjudged:
        _say(f"{unjudged} publisher(s) are unjudged (F suppresses the confidence of everything "
             "they report): `argus sources set-reliability <name> <A-F>`.", style="yellow")
    if duplicate_rows:
        _say(f"{duplicate_rows} rows are the same organisation under different bylines, so they "
             "corroborate each other: `argus sources merge-duplicates --dry-run`.", style="yellow")


def _recompute_affected(services, touched, *, done: str) -> None:
    """Rescore the assessments a publisher change touched, or say why it could not.

    Both merging publishers and grading them change the inputs to `scoring.score` — how many
    independent sources a fact has, and how much each one weighs — so the stored assessments
    stay wrong until this runs. That is why a failure here is reported loudly rather than
    swallowed. The shape mirrors `entity-merge-ghosts`.
    """
    try:
        validator = services.validator()
    except MissingAttackData as exc:
        _say(
            f"{done}, but assessments were not recomputed ({exc}). "
            "Run `argus attack update`, then `argus recompute`.",
            style="yellow", stderr=True,
        )
        return
    validator.recompute(touched)
    _say(f"{done}. {len(touched)} assessment(s) recomputed.")


@sources_app.command("rate-known")
def sources_rate_known(
    dry_run: bool = typer.Option(False, "--dry-run", help="Show the proposed grades without applying them."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip the confirmation prompt."),
    include_rated: bool = typer.Option(
        False, "--include-rated",
        help="Also overwrite publishers that already carry a grade other than F. Off by default: "
             "a grade on the row is an analyst's judgement and outranks the shipped table.",
    ),
) -> None:
    """Give every recognised publisher its starting Admiralty reliability, and rescore.

    In the Admiralty system F does not mean "average" — it means reliability cannot be judged,
    and it is the floor that `scoring.score` multiplies evidence by. A store that has never used
    the axis therefore files CISA, NCSC-UK, Mandiant and Unit 42 as unjudgeable and pins
    everything they report to the bottom of the confidence scale. That is not a cautious default;
    it is a false claim about the sources.

    This matches each publisher to its organisation by domain and applies the grade Argus ships
    for it (`knowledge/publisher_ratings.py`, which lists only well-established track records and
    gives a reason for each one). A publisher Argus cannot speak to is left at F, which is then
    accurate rather than merely cautious.

    Expect confidence to go UP on facts from graded sources. Read the table before accepting it:
    these are a starting point for your judgement, and `argus sources set-reliability` overrides
    any of them.
    """
    from cyllex_argus.knowledge.publisher_merge import organisation_keys
    from cyllex_argus.knowledge.publisher_ratings import known_rating
    services = _open()
    try:
        keys = organisation_keys(services.store.connection)
        publishers = services.store.list_publishers()
        proposals = []
        for publisher in publishers:
            known = known_rating(keys.get(publisher.id))
            if known is None or known.reliability == publisher.reliability:
                continue
            if publisher.reliability != "F" and not include_rated:
                continue
            proposals.append((publisher, known))
        if not proposals:
            _say("Nothing to grade: every publisher Argus recognises already carries its rating.")
            unrated = [p for p in publishers if p.reliability == "F"]
            if unrated:
                _say(f"{len(unrated)} publisher(s) are still F — Argus cannot speak to those. "
                     "Rate them with `argus sources set-reliability <name> <A-F>`.", style="yellow")
            return
        table = Table()
        for column in ("Publisher", "Now", "Proposed", "Why"):
            table.add_column(column)
        for publisher, known in proposals:
            table.add_row(*(_cell(value) for value in (
                publisher.name, publisher.reliability, known.reliability, known.rationale,
            )))
        Console().print(table)
        if dry_run:
            _say("Dry run: no changes made. Re-run without --dry-run to apply.")
            return
        if not yes:
            _say(f"\nAbout to grade {len(proposals)} publisher(s) and rescore every fact they "
                 "support. Pass --yes to proceed.", style="yellow")
            raise typer.Exit(code=1)
        for publisher, known in proposals:
            services.store.grade_publisher(publisher.id, known.reliability)
        touched = services.store.assessment_keys_for_publishers([p.id for p, _ in proposals])
        _recompute_affected(services, touched, done=f"Graded {len(proposals)} publisher(s)")
    finally:
        services.close()


@sources_app.command("merge-duplicates")
def sources_merge_duplicates(
    dry_run: bool = typer.Option(False, "--dry-run", help="Show what would be merged without changing anything."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip the confirmation prompt."),
) -> None:
    """Fold every publisher row that is the same organisation into one source.

    Corroboration is counted per publisher row (`scoring.score` keeps one piece of evidence per
    `publisher_id`), so a store that holds CISA under seven bylines can report a fact as
    confirmed by three independent sources when all three are CISA. This groups rows by the
    registrable domain they publish from — never by name similarity, and never for a domain
    that hosts unrelated authors such as medium.com — and merges each group into one row.

    Nothing is lost: every byline survives in the publisher's name list, so
    `argus sources set-reliability "<old byline>"` keeps working and `argus sources list` shows
    which names a row covers. Documents are repointed, not deleted.

    Expect confidence to go DOWN on the facts this touches. That is the point: a merge can only
    remove supporters, and the scores it lowers were overstated before.
    """
    from cyllex_argus.knowledge.publisher_merge import find_duplicate_publishers
    services = _open()
    try:
        # Rows written before organisation identity existed carry no key, and a row created from
        # a byline alone only learns its domain from the documents it published. Fill both in
        # before grouping, or the scan finds nothing on exactly the stores that need it.
        filled = services.store.backfill_publisher_org_keys()
        if filled:
            _say(f"Identified the organisation behind {filled} publisher row(s).")
        groups = find_duplicate_publishers(services.store.connection)
        if not groups:
            _say("No duplicate publishers. Every organisation already has exactly one source row.")
            return
        rows = sum(group.rows for group in groups)
        _say(f"{len(groups)} organisation(s) are filed under {rows} publisher rows:")
        for group in groups:
            _say(f"  {group.org_key}: keep {group.keep.name!r} ({group.keep.documents} doc(s))")
            for row in group.drop:
                _say(f"    + {row.name!r} ({row.documents} doc(s))", style="yellow")
        if dry_run:
            _say("Dry run: no changes made. Re-run without --dry-run to apply.")
            return
        if not yes:
            _say(
                f"\nAbout to merge {rows} rows into {len(groups)}. Confidence will drop on facts "
                "whose supporters turn out to be one organisation. Pass --yes to proceed.",
                style="yellow",
            )
            raise typer.Exit(code=1)

        touched: set[tuple[str, str, str]] = set()
        moved = 0
        for group in groups:
            keys = services.store.assessment_keys_for_publishers(
                [group.keep.id, *(row.id for row in group.drop)]
            )
            touched.update(keys)
            moved += services.store.merge_publishers(group.keep.id, [row.id for row in group.drop])
            _say(f"  merged {len(group.drop)} row(s) into {group.keep.name!r}")
        _recompute_affected(
            services, touched,
            done=f"Merged {rows} rows into {len(groups)} source(s), repointing {moved} document reference(s)",
        )
    finally:
        services.close()


@sources_app.command("merge")
def sources_merge(
    keep: str = typer.Argument(..., help="The publisher to keep. Any byline it has published under."),
    drop: list[str] = typer.Argument(..., help="The publisher(s) to fold into it."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip the confirmation prompt."),
) -> None:
    """Fold one or more publishers into another, by hand.

    For the cases `merge-duplicates` deliberately refuses: two organisations that share a
    publishing platform, a vendor that changed name, or a domain the identity rules cannot
    read. Every byline is preserved and the affected assessments are recomputed.
    """
    services = _open()
    try:
        try:
            keep_id = services.store.publisher_id_by_name(keep)
            drop_ids = [services.store.publisher_id_by_name(name) for name in drop]
        except KeyError as exc:
            _fail(f"Unknown publisher: {exc.args[0]}")
        if all(publisher_id == keep_id for publisher_id in drop_ids):
            _fail("Nothing to merge: every publisher named is already the one being kept.")
        keeper = services.store.get_publisher(keep_id)
        names = [services.store.get_publisher(i).name for i in drop_ids if i != keep_id]
        if not yes:
            _say(f"About to fold {', '.join(repr(n) for n in names)} into {keeper.name!r}. "
                 "Pass --yes to proceed.", style="yellow")
            raise typer.Exit(code=1)
        touched = services.store.assessment_keys_for_publishers([keep_id, *drop_ids])
        moved = services.store.merge_publishers(keep_id, drop_ids)
        _recompute_affected(
            services, touched,
            done=f"Folded {len(names)} publisher(s) into {keeper.name!r}, "
                 f"repointing {moved} document reference(s)",
        )
    finally:
        services.close()


@sources_app.command("set-tlp")
def sources_set_tlp(
    publisher: str = typer.Argument(..., help="Publisher name."),
    tlp: str = typer.Argument(
        ..., help="TLP 2.0 label: clear, green, amber, amber-strict, red. Pass 'none' to clear.",
    ),
) -> None:
    """Attach (or clear) a TLP 2.0 label on a publisher. Export filters respect it."""
    normalized = tlp.strip().lower()
    if normalized in ("none", "clear-tlp", ""):
        value: TLP | None = None
    else:
        try:
            value = TLP(normalized)
        except ValueError:
            _fail("TLP must be one of clear, green, amber, amber-strict, red (or 'none' to clear).")
    services = _open()
    try:
        try:
            updated = services.store.set_publisher_tlp(publisher, value)
        except KeyError:
            _fail(f"Unknown publisher: {publisher}")
    finally:
        services.close()
    _say(f"{updated.name}: tlp={updated.tlp.value if updated.tlp else '-'}")


@sources_app.command("set-reliability")
def sources_set_reliability(
    publisher: str = typer.Argument(..., help="Publisher name."),
    reliability: str = typer.Argument(..., help="Admiralty source reliability, A (best) to F (unknown)."),
) -> None:
    """Set a publisher's reliability and recompute every assessment."""
    letter = reliability.strip().upper()
    if letter not in RELIABILITY_LETTERS:
        _fail("Reliability must be one of A, B, C, D, E, F.")
    services = _open()
    try:
        try:
            updated = services.store.set_publisher_reliability(publisher, letter)
        except KeyError:
            _fail(f"Unknown publisher: {publisher}")
        if services.attack_ready():
            try:
                validator = services.validator()
            except MissingAttackData as exc:
                _fail(
                    f"{updated.name} is now {updated.reliability}, but assessments were not recomputed "
                    f"({exc}). Run `argus attack update`, then repeat this command."
                )
            validator.recompute(services.store.assessment_keys())
        bylines = [
            name for name in services.store.publisher_names(updated.id)
            if normalize_name(name) != normalize_name(updated.name)
        ]
    finally:
        services.close()
    _say(f"{updated.name}: {updated.reliability}")
    if bylines:
        # The rating applies to the organisation, not to the byline that was typed.
        _say(f"  also covers: {', '.join(bylines)}", style="dim")


@trace_app.command("purge")
def trace_purge(
    before: datetime | None = typer.Option(
        None, "--before", formats=["%Y-%m-%d"], help="Delete events created before this date (YYYY-MM-DD)."
    ),
    investigation: int | None = typer.Option(None, "--investigation", help="Delete this investigation's events."),
    raw: bool = typer.Option(
        False, "--raw",
        help="Null out raw_prompt/raw_response on existing events instead of deleting the rows. "
             "Combine with --before to reclaim space from old runs without losing the audit trail.",
    ),
) -> None:
    """Delete pipeline events. Without options, print how much the trace table holds.

    `--raw` is non-destructive to the events themselves: counts, timings, decisions and
    rejection reasons stay. Only the LLM prompt/response blobs disappear. That is the right
    knob when the Logs tab shows "~84 MB" and you want to shrink the DB without losing
    the ability to tell what the pipeline did.
    """
    services = _open()
    try:
        recorder = services.trace_recorder()
        if before is None and investigation is None and not raw:
            rows, size = recorder.size()
            _say(f"{rows} events, ~{size / (1024 * 1024):.2f} MB")
            return
        if raw:
            if investigation is not None:
                _fail("--raw and --investigation cannot be combined (--raw is global; narrow with --before)")
            updated = recorder.purge_raw_only(before.date() if before else None)
            _say(f"Nulled raw payloads on {updated} event(s).")
            return
        deleted = recorder.delete_matching(before.date() if before else None, investigation)
    finally:
        services.close()
    _say(f"Deleted {deleted} events.")


def _write_stdout(text: str) -> None:
    """Write UTF-8 whatever the console code page is, so redirected output never loses characters."""
    buffer = getattr(sys.stdout, "buffer", None)
    if buffer is None:
        typer.echo(text, nl=False)
        return
    sys.stdout.flush()
    buffer.write(text.encode("utf-8"))
    buffer.flush()


@app.command()
def export(
    entity: str = typer.Argument(..., help="Entity name or alias."),
    fmt: str = typer.Option("markdown", "--format", "-f", help="markdown or stix."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write to this file instead of stdout."),
    no_summary: bool = typer.Option(False, "--no-summary", help="Skip the LLM executive summary (markdown)."),
    tlp_cap: str | None = typer.Option(
        None, "--tlp-cap",
        help="Drop citations from publishers whose TLP exceeds this cap (clear/green/amber/"
             "amber-strict/red). Facts left with no evidence are omitted. Publishers with no TLP "
             "set are kept — the operator decides.",
    ),
) -> None:
    """Export an entity profile as Markdown or a STIX 2.1 bundle."""
    kind = fmt.strip().lower()
    if kind not in ("markdown", "stix"):
        _fail("Format must be markdown or stix.")
    cap: TLP | None = None
    if tlp_cap:
        try:
            cap = TLP(tlp_cap.strip().lower())
        except ValueError:
            _fail("--tlp-cap must be one of clear, green, amber, amber-strict, red.")
    services = _open()
    try:
        found = services.store.find_by_alias(entity)
        if found is None:
            _fail(f"Unknown entity: {entity}")
        profile = build_profile(services.store, found)
        if kind == "markdown":
            summary = None
            if not no_summary and profile.facts:
                try:
                    summary = summarize_profile(profile, services.llm)
                except (LLMUnavailable, RateLimited, InvalidOutput) as exc:
                    _say(f"Executive summary skipped: {exc}", style="yellow", stderr=True)
            text = render_markdown(
                profile, summary, date.today(), tlp_cap=cap,
                coverage=services.store.coverage_for_entity(found.id),
            )
        else:
            skipped = []
            bundle = to_stix_bundle(profile, datetime.now(UTC), on_skip=skipped.append, tlp_cap=cap)
            if skipped:
                _say(f"Skipped {len(skipped)} fact(s) with no STIX mapping", style="yellow", stderr=True)
            if not bundle.get("objects"):
                _say("Warning: the bundle has no objects; nothing here maps to STIX.", style="yellow", stderr=True)
            text = json.dumps(bundle, indent=2) + "\n"
    finally:
        services.close()
    if output is not None:
        output.write_text(text, encoding="utf-8")
        _say(f"Wrote {output}")
    else:
        _write_stdout(text)


@app.command("import-stix")
def import_stix(
    bundle: Path = typer.Argument(..., exists=True, dir_okay=False, readable=True,
                                   help="Path to a STIX 2.1 bundle (JSON)."),
) -> None:
    """Merge a STIX 2.1 bundle written by MISP, OpenCTI or any other STIX-aware tool into the store.

    SDOs become entities (deduped by MITRE external_id for attack-patterns, by name for the rest).
    Identity SDOs with `sectors` or an extension-provided country are tagged with the structured
    attributes `argus query-targets` reads. Relationships become claims anchored on the bundle
    itself as a document, so the audit trail stays intact. Unsupported SDO and relationship
    types are counted in the printed report instead of silently dropped.
    """
    services = _open()
    try:
        try:
            report = import_stix_bundle(services, bundle)
        except ValueError as exc:
            _fail(str(exc))
    finally:
        services.close()
    _say(f"Bundle: {report.bundle_id or '(no id)'}", style="bold")
    _say(f"  entities added:   {report.entities_added}")
    _say(f"  entities matched: {report.entities_matched}")
    _say(f"  aliases added:    {report.aliases_added}")
    _say(f"  claims added:     {report.claims_added}")
    _say(f"  identities tagged: {report.identities_tagged}")
    if report.skipped:
        _say(f"Skipped {len(report.skipped)} item(s):", style="yellow")
        for reason in report.skipped[:10]:
            _say(f"  - {reason}")
        if len(report.skipped) > 10:
            _say(f"  (+ {len(report.skipped) - 10} more)")


@app.command("entity-merge")
def entity_merge(
    source: str = typer.Argument(..., help="Name or alias of the entity to merge FROM (will be deleted)."),
    target: str = typer.Argument(..., help="Name or alias of the entity to merge INTO (survives)."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip the confirmation prompt."),
) -> None:
    """Fuse two entities for the same real-world object into one.

    Every claim pointing at `source` is re-pointed at `target`. Aliases on `source` are moved
    (deduped). Assessments that referenced `source` are deleted and then recomputed against the
    target's claim set. The source entity is removed. Both entities must share the same STIX
    type (merging an intrusion-set into a campaign is refused).

    Classic use case: `argus attack update` has just loaded ATT&CK Enterprise and the campaign
    C0027 is now in the store twice — once as the official ATT&CK entity and once as a
    document-origin duplicate the Analyst extracted from a prior investigation. This command
    fuses the duplicate into the official one so the real-world object has one row.
    """
    services = _open()
    try:
        src = services.store.get_entity(source) or services.store.find_by_alias(source)
        if src is None:
            _fail(f"Unknown source entity: {source}")
        tgt = services.store.get_entity(target) or services.store.find_by_alias(target)
        if tgt is None:
            _fail(f"Unknown target entity: {target}")
        if src.id == tgt.id:
            _fail("Source and target resolve to the same entity.")
        if src.stix_type != tgt.stix_type:
            _fail(
                f"Cannot merge across STIX type: {src.canonical_name} is {src.stix_type}, "
                f"{tgt.canonical_name} is {tgt.stix_type}."
            )
        if not yes:
            _say(
                f"About to delete {src.canonical_name} ({src.id}) and move everything into "
                f"{tgt.canonical_name} ({tgt.id}). Pass --yes to proceed.",
                style="yellow",
            )
            raise typer.Exit(code=1)
        touched = services.store.merge_entities(src.id, tgt.id)
        try:
            validator = services.validator()
        except MissingAttackData as exc:
            _say(
                f"Merged, but assessments were not recomputed ({exc}). "
                "Run `argus attack update` and the assessments will rebuild on the next pass.",
                style="yellow", stderr=True,
            )
            touched = set()
        else:
            validator.recompute(touched)
    finally:
        services.close()
    _say(f"Merged {src.canonical_name} into {tgt.canonical_name}. Recomputed {len(touched)} assessment(s).")


@app.command("entity-merge-ghosts")
def entity_merge_ghosts(
    dry_run: bool = typer.Option(False, "--dry-run", help="Show what would be merged without changing anything."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip the confirmation prompt."),
    stix_types: list[str] = typer.Option(
        ["intrusion-set", "malware", "tool", "campaign"], "--stix-type",
        help="Which stix_types to scan. Repeat for multiple; defaults scan all four STIX "
             "categories that have MITRE catalog identifiers (G/S/C codes).",
    ),
) -> None:
    """Fuse every document-origin ghost entity into its MITRE-catalog counterpart.

    When an operator ran investigations BEFORE their first `argus attack update`, the
    Analyst stage created document-origin entities for every group / malware / tool
    name it saw. Later, when the ATT&CK catalog populates the official entities (with
    "Midnight Blizzard" as alias of G0016 "APT29", "Mimikatz" with S0002, etc.), the
    historical facts stay stuck on the ghosts and the Threat profile shows partial data.

    This command discovers every ghost whose aliases overlap with exactly ONE catalog
    entity, prints the plan, and (unless --dry-run) fuses each ghost into its catalog
    counterpart using the same code `argus entity-merge` uses for a single pair, then
    recomputes affected assessments. Ambiguous ghosts (aliases match 2+ catalog
    entities) are skipped — those need `argus entity-merge <ghost> <chosen-canonical>`
    manually.

    Scope defaults to all four MITRE-coded STIX types (intrusion-set / malware / tool
    / campaign). Narrow with --stix-type if you only want to triage one at a time.
    """
    from cyllex_argus.knowledge.entity_merge import find_mergeable
    services = _open()
    try:
        candidates = []
        for stix_type in stix_types:
            candidates.extend(find_mergeable(services.store.connection, stix_type=stix_type))
        if not candidates:
            scope = ", ".join(stix_types)
            _say(f"No ghost {scope} entities to merge. Everything is attached to a catalog entity already.")
            return
        _say(f"Found {len(candidates)} ghost entity(ies) with an unambiguous catalog match:")
        for c in candidates:
            _say(f"  {c.ghost_name} ({c.ghost_id})  →  "
                 f"{c.canonical_name} [{c.canonical_external_id}]  "
                 f"(shared alias: {', '.join(sorted(c.shared_aliases))})")
        if dry_run:
            _say("Dry run: no changes made. Re-run without --dry-run to apply.")
            return
        if not yes:
            _say(
                f"\nAbout to merge {len(candidates)} ghost(s) into their catalog counterparts. "
                "Pass --yes to proceed.",
                style="yellow",
            )
            raise typer.Exit(code=1)

        total_touched: set[tuple[str, str, str]] = set()
        for c in candidates:
            touched = services.store.merge_entities(c.ghost_id, c.canonical_id)
            total_touched.update(touched)
            _say(f"  merged: {c.ghost_name} → {c.canonical_name} "
                 f"({len(touched)} assessment key(s) touched)")

        try:
            validator = services.validator()
        except MissingAttackData as exc:
            _say(
                f"Merges done, but assessments were not recomputed ({exc}). "
                "Run `argus attack update` and the assessments will rebuild on the next pass.",
                style="yellow", stderr=True,
            )
            return
        validator.recompute(total_touched)
        _say(f"\nDone. {len(candidates)} ghost(s) merged, "
             f"{len(total_touched)} assessment(s) recomputed.")
    finally:
        services.close()


@app.command("entity-retype")
def entity_retype(
    entity: str = typer.Argument(..., help="Entity name, alias or full stix id."),
    to: str = typer.Option(..., "--to", "-t", help="New STIX type: tool / malware / identity / location / indicator / vulnerability / intrusion-set / campaign."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip the confirmation prompt."),
) -> None:
    """Change an entity's STIX type in place.

    Common case: the Analyst wrote "AWS" or "ADFS" as an `identity` SDO during extraction
    when they are really tools / infrastructure. This swaps the type without losing any
    aliases, claims or assessments. The entity's UUID is preserved — only the type prefix
    of the stix id changes (`identity--<uuid>` → `tool--<uuid>`), and every foreign key
    that pointed at the old id gets re-pointed in the same transaction.

    Refusals: identical type, unknown target type, ATT&CK-origin entities (their alias
    from the MITRE bundle would be mislabelled on the next sync).
    """
    services = _open()
    try:
        found = services.store.get_entity(entity) or services.store.find_by_alias(entity)
        if found is None:
            _fail(f"Unknown entity: {entity}")
        if found.stix_type == to:
            _fail(f"{found.canonical_name} is already {to!r}.")
        if not yes:
            _say(
                f"About to retype {found.canonical_name} ({found.id}) from {found.stix_type!r} "
                f"to {to!r}. Pass --yes to proceed.",
                style="yellow",
            )
            raise typer.Exit(code=1)
        try:
            updated = services.store.retype_entity(found.id, to)
        except ValueError as exc:
            _fail(str(exc))
    finally:
        services.close()
    _say(f"Retyped {updated.canonical_name}: {found.stix_type} → {to} (new id: {updated.id}).")


@app.command("identity-set")
def identity_set(
    entity: str = typer.Argument(..., help="Identity entity name or alias."),
    sector: str | None = typer.Option(
        None, "--sector", "-s",
        help="Free-text sector label such as 'energy', 'financial-services', 'healthcare'. "
             "Pass an empty string to clear.",
    ),
    country: str | None = typer.Option(
        None, "--country", "-c",
        help="ISO 3166 alpha-2 country code such as 'US', 'DE', 'ES'. Pass an empty string to clear.",
    ),
) -> None:
    """Annotate an `identity` entity with sector and/or country.

    Enables `argus query-targets --sector <s>` / `--country <c>` to list actors seen targeting
    that sector or geography. The annotations are stored on the entity's attributes_json so no
    schema change is needed and future entity types can carry their own keys.
    """
    if sector is None and country is None:
        _fail("Pass at least --sector or --country.")
    services = _open()
    try:
        found = services.store.find_by_alias(entity)
        if found is None:
            _fail(f"Unknown entity: {entity}")
        if found.stix_type != "identity":
            _fail(f"{entity} is a {found.stix_type}, not an identity")
        kwargs: dict = {}
        if sector is not None:
            kwargs["sector"] = sector  # empty string → store.set_entity_attributes drops the key
        if country is not None:
            kwargs["country"] = country
        updated = services.store.set_entity_attributes(found.id, **kwargs)
    finally:
        services.close()
    _say(
        f"{updated.canonical_name}: "
        f"sector={updated.attributes.get('sector', '-')} "
        f"country={updated.attributes.get('country', '-')}"
    )


@app.command("query-targets")
def query_targets(
    sector: str | None = typer.Option(None, "--sector", "-s", help="Sector label (case-insensitive)."),
    country: str | None = typer.Option(None, "--country", "-c", help="ISO 3166 alpha-2 code (case-insensitive)."),
) -> None:
    """List actors with observed `targets` claims against identities in the given sector / country.

    Annotate identities with `argus identity-set` first; otherwise the query has nothing to filter
    against. Ranking is by number of distinct target assessments, descending.
    """
    if not sector and not country:
        _fail("Pass at least --sector or --country.")
    services = _open()
    try:
        results = services.store.actors_targeting(sector=sector, country=country)
        identities = services.store.identities_matching(sector=sector, country=country)
    finally:
        services.close()
    _say(f"{len(identities)} identity entity(ies) matched.")
    if not results:
        _say("No actors with `targets` assessments against those identities.")
        return
    table = Table(show_lines=False)
    for column in ("Actor", "Type", "Targeting assessments"):
        table.add_column(column)
    for actor, count in results:
        table.add_row(actor.canonical_name, actor.stix_type, str(count))
    Console().print(table)


@app.command()
def enrich(
    indicator: str | None = typer.Argument(
        None, help="The indicator value (e.g. 'example.com', '1.2.3.4'). Omit when using --list.",
    ),
    indicator_type: str = typer.Option(
        "domain-name", "--type",
        help="STIX observable type: domain-name, ipv4-addr, ipv6-addr, url, file-hash, vulnerability.",
    ),
    with_: str | None = typer.Option(
        None, "--with",
        help="Enricher name. Required unless --list is set. Use `argus enrich --list` to see which.",
    ),
    list_enrichers: bool = typer.Option(False, "--list", help="List built-in enrichers and their config state."),
) -> None:
    """Enrich an indicator with a configured enricher.

    Every enricher is DISABLED by default. Enable one you understand by adding to argus.toml:

        [enrichment.enrichers."<name>"]
        enabled = true

    Each enricher documents, in its `outbound` text, exactly what leaves your machine. Nothing
    outbound happens unless the toggle above is explicitly `true`.
    """
    if list_enrichers:
        services = _open()
        try:
            runner = services.enrichment_runner()
            enabled = set(runner.enabled_names())
            for name, enricher in sorted(available_enrichers().items()):
                mark = "enabled" if name in enabled else "disabled"
                _say(f"- {name}  [{mark}]  types={','.join(enricher.supported_types)}")
                _say(f"    {enricher.description}")
                _say(f"    outbound: {enricher.outbound}", soft_wrap=True)
        finally:
            services.close()
        return
    if not indicator:
        _fail("Pass an indicator to enrich, or use --list to see the catalog.")
    if not with_:
        _fail("Pass --with <enricher>. Use `argus enrich --list` to see the catalog.")
    services = _open()
    try:
        runner = services.enrichment_runner()
        request = EnrichmentRequest(indicator=indicator, indicator_type=indicator_type)  # type: ignore[arg-type]
        try:
            result = runner.enrich(request, with_)
        except EnrichmentDisabledError as exc:
            _fail(str(exc))
        except EnrichmentUnavailable as exc:
            _fail(str(exc))
    finally:
        services.close()
    if result.error:
        _say(f"Enrichment failed: {result.error}", style="yellow", stderr=True)
        raise typer.Exit(code=1)
    _say(f"{with_}: {len(result.findings)} finding(s) in {result.duration_ms} ms", style="bold")
    if not result.findings:
        return
    table = Table(show_lines=False)
    for column in ("Key", "Value", "Observed", "Detail"):
        table.add_column(column)
    for f in result.findings:
        table.add_row(f.key, f.value, f.observed_at or "-", f.detail or "-")
    Console().print(table)


def _default_detections_out(entity_name: str) -> Path:
    slug = "".join(c if c.isalnum() else "-" for c in entity_name).strip("-").lower() or "entity"
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return Path(f"argus-detections/{slug}-{stamp}")






schedule_app = typer.Typer(
    help="Manage recurring investigations. The scheduler thread inside `argus serve` fires them "
    "when their cron fires; CLI alone does not run the ticker.",
    no_args_is_help=True,
)
app.add_typer(schedule_app, name="schedule")


@schedule_app.command("add")
def schedule_add_cmd(
    target: str = typer.Argument(..., help="Threat to investigate (e.g. \"Scattered Spider\")."),
    cron: str = typer.Option(..., "--cron", help="Cron expression. 5 fields: m h dom mon dow. Example: \"0 8 * * 1\" = every Monday 8am."),
    max_docs: int | None = typer.Option(None, "--max-docs", min=1, max=200, help="Cap documents collected per run. Default: config value."),
    concurrency: int = typer.Option(1, "--concurrency", "-c", min=1, max=16, help="Parallel workers for Triage+Analyst."),
) -> None:
    """Create a recurring investigation."""
    from datetime import UTC, datetime

    from cyllex_argus.pipeline.scheduler import is_valid_cron, next_fire

    if not is_valid_cron(cron):
        _fail(f"Invalid cron expression: {cron!r}")
    services = _open()
    try:
        s = services.store.create_schedule(
            target=target.strip(), cron_expr=cron.strip(), max_docs=max_docs,
            concurrency=concurrency, next_run_at=next_fire(cron, datetime.now(UTC)),
        )
    finally:
        services.close()
    _say(
        f"Created schedule #{s.id} for \"{s.target}\" ({s.cron_expr}). Next fire: {s.next_run_at.isoformat()}.",
        style="green",
    )


@schedule_app.command("list")
def schedule_list_cmd() -> None:
    """List every recurring investigation on this install."""
    services = _open()
    try:
        rows = services.store.list_schedules()
    finally:
        services.close()
    if not rows:
        _say("No schedules yet. Add one with `argus schedule add`.")
        return
    table = Table(show_lines=False)
    for col in ("#", "Target", "Cron", "Max docs", "Concurrency", "Enabled", "Last run", "Next run"):
        table.add_column(col)
    for s in rows:
        table.add_row(
            str(s.id), s.target, s.cron_expr,
            str(s.max_docs) if s.max_docs else "-", str(s.concurrency),
            "yes" if s.enabled else "no",
            s.last_run_at.isoformat() if s.last_run_at else "-",
            s.next_run_at.isoformat(),
        )
    Console().print(table)


@schedule_app.command("remove")
def schedule_remove_cmd(schedule_id: int = typer.Argument(..., help="Schedule id (from `argus schedule list`).")) -> None:
    """Delete a schedule. Idempotent: a missing id is a no-op."""
    services = _open()
    try:
        removed = services.store.delete_schedule(schedule_id)
    finally:
        services.close()
    _say(f"Removed schedule #{schedule_id}." if removed else f"No schedule #{schedule_id}.", style="green" if removed else "yellow")


@schedule_app.command("enable")
def schedule_enable_cmd(schedule_id: int = typer.Argument(...)) -> None:
    """Re-enable a paused schedule. It fires at the next tick (or immediately if next_run_at is in the past)."""
    _set_enabled(schedule_id, True)


@schedule_app.command("disable")
def schedule_disable_cmd(schedule_id: int = typer.Argument(...)) -> None:
    """Pause a schedule without deleting it. Resume with `argus schedule enable <id>`."""
    _set_enabled(schedule_id, False)


def _set_enabled(schedule_id: int, enabled: bool) -> None:
    services = _open()
    try:
        if services.store.get_schedule(schedule_id) is None:
            _fail(f"No schedule #{schedule_id}.")
        services.store.set_schedule_enabled(schedule_id, enabled)
    finally:
        services.close()
    _say(f"Schedule #{schedule_id} {'enabled' if enabled else 'disabled'}.", style="green")


@app.command(name="backup")
def backup_cmd(
    out: Path | None = typer.Option(
        None, "--out", "-o",
        help="Where to write the backup .db. Default: ~/.cyllex-argus/backups/argus-<timestamp>.db.",
    ),
) -> None:
    """Snapshot the Argus SQLite store to a portable `.db` file using SQLite's online backup API.

    The snapshot is consistent even if an investigation is writing to the live store at the same
    time: SQLite's `backup()` acquires a shared lock and copies pages page-by-page, so the
    destination is always a valid database at some point in time. The result is a single file —
    move it off the laptop (S3, network share, encrypted USB) and you have a one-command restore
    path (`cp <backup> ~/.cyllex-argus/argus.db` or the Admin → Database → Import flow in the UI).
    """
    import sqlite3
    from datetime import datetime

    services = _open()
    try:
        source = services.paths.db_file
        if not source.exists():
            _fail(f"No database to back up at {source}. Run `argus init` first.")
    finally:
        services.close()
    if out is None:
        home = services.paths.home
        stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%SZ")
        out = home / "backups" / f"argus-{stamp}.db"
    out.parent.mkdir(parents=True, exist_ok=True)
    src_conn = sqlite3.connect(str(source))
    try:
        dst_conn = sqlite3.connect(str(out))
        try:
            src_conn.backup(dst_conn)
        finally:
            dst_conn.close()
    finally:
        src_conn.close()
    size_mb = out.stat().st_size / (1024 * 1024)
    _say(f"Backup written to {out} ({size_mb:.1f} MB)", style="green")


user_app = typer.Typer(help="Manage web UI users and roles.", no_args_is_help=True)
app.add_typer(user_app, name="user")


def _sync_admin_user(store, username: str, hashed: str) -> None:
    """Keep the store's admin row in step with set/reset-admin-password, so the web login (which
    validates against the store) reflects the new password immediately, not only on a fresh seed."""
    from cyllex_argus.knowledge.models import Role
    user = store.get_user_by_username(username)
    if user is None:
        store.create_user(username, hashed, Role.ADMIN)
    else:
        store.set_user_role(user.id, Role.ADMIN)
        store.set_user_password(user.id, hashed, clear_default=True)


@user_app.command("add")
def user_add_cmd(
    username: str = typer.Argument(..., help="New user's login name."),
    role: str = typer.Option("reader", "--role", help="reader | operator | admin."),
    password: str = typer.Option(..., prompt=True, hide_input=True, confirmation_prompt=True,
                                 help="The user's password (prompted if omitted)."),
) -> None:
    """Create a web UI user with a role."""
    from cyllex_argus.knowledge.models import Role
    from cyllex_argus.web import auth_core
    try:
        parsed = Role(role)
    except ValueError:
        _fail(f"invalid role {role!r}: expected reader, operator or admin")
    try:
        auth_core.validate_password(password)
    except ValueError as exc:
        _fail(str(exc))
    services = _open()
    try:
        if services.store.get_user_by_username(username) is not None:
            _fail(f"user {username!r} already exists")
        services.store.create_user(username, auth_core.hash_password(password), parsed)
    finally:
        services.close()
    _say(f"Created user '{username}' with role '{parsed.value}'.", style="green")


@user_app.command("list")
def user_list_cmd() -> None:
    """List web UI users."""
    services = _open()
    try:
        users = services.store.list_users()
    finally:
        services.close()
    if not users:
        _say("No users.")
        return
    for user in users:
        flag = " (disabled)" if user.disabled else ""
        _say(f"{user.id:>3}  {user.username:<24} {user.role.value}{flag}")


@user_app.command("disable")
def user_disable_cmd(username: str = typer.Argument(..., help="User to disable.")) -> None:
    """Disable a user: blocks login and kills their live sessions."""
    _set_user_disabled(username, True)


@user_app.command("enable")
def user_enable_cmd(username: str = typer.Argument(..., help="User to enable.")) -> None:
    """Re-enable a disabled user."""
    _set_user_disabled(username, False)


def _set_user_disabled(username: str, disabled: bool) -> None:
    from cyllex_argus.knowledge.models import Role
    services = _open()
    try:
        store = services.store
        user = store.get_user_by_username(username)
        if user is None:
            _fail(f"no such user: {username}")
        if disabled and user.role is Role.ADMIN and store.count_enabled_admins() <= 1:
            _fail("cannot disable the last admin")
        store.set_user_disabled(user.id, disabled)
    finally:
        services.close()
    _say(f"User '{username}' {'disabled' if disabled else 'enabled'}.", style="green")


@user_app.command("delete")
def user_delete_cmd(username: str = typer.Argument(..., help="User to delete.")) -> None:
    """Delete a user (tombstoned so attribution survives)."""
    from cyllex_argus.knowledge.models import Role
    services = _open()
    try:
        store = services.store
        user = store.get_user_by_username(username)
        if user is None:
            _fail(f"no such user: {username}")
        if user.role is Role.ADMIN and store.count_enabled_admins() <= 1:
            _fail("cannot delete the last admin")
        store.delete_user(user.id)
    finally:
        services.close()
    _say(f"Deleted user '{username}'.", style="green")


@user_app.command("passwd")
def user_passwd_cmd(
    username: str = typer.Argument(..., help="User whose password to set."),
    password: str = typer.Option(..., prompt=True, hide_input=True, confirmation_prompt=True,
                                 help="The new password (prompted if omitted)."),
) -> None:
    """Set a user's password."""
    from cyllex_argus.web import auth_core
    try:
        auth_core.validate_password(password)
    except ValueError as exc:
        _fail(str(exc))
    services = _open()
    try:
        user = services.store.get_user_by_username(username)
        if user is None:
            _fail(f"no such user: {username}")
        services.store.set_user_password(user.id, auth_core.hash_password(password))
        services.store.delete_user_sessions(user.id)  # a password change logs the user out everywhere
    finally:
        services.close()
    _say(f"Password updated for '{username}'.", style="green")


@app.command(name="set-admin-password")
def set_admin_password_cmd(
    password: str = typer.Argument(
        ..., help="New admin password. Hashed with bcrypt and persisted to argus.toml under [auth].",
    ),
    username: str = typer.Option(
        "admin", "--username", help="Admin username. Default: admin.",
    ),
) -> None:
    """Hash and store the admin password for the web login screen.

    The hash lands in `~/.cyllex-argus/argus.toml` under `[auth] admin_password_hash` so the
    login endpoint can validate credentials without the plaintext being on disk. If the operator
    prefers the env route (preferred for shared / containerised deployments), skip this command
    and set `ARGUS_ADMIN_PASSWORD` before starting `argus serve`.
    """
    import bcrypt

    services = _open()
    hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("ascii")
    try:
        cfg = services.config
        config_path = services.paths.config_file
        cfg.auth.admin_username = username
        cfg.auth.admin_password_hash = hashed
        from cyllex_argus.config.settings import save_config
        save_config(cfg, config_path)
        _sync_admin_user(services.store, username, hashed)
    finally:
        services.close()
    _say(
        f"Admin password set for user '{username}'. Login via the web UI; the hash lives in {config_path}.",
        style="green",
    )


@app.command(name="reset-admin-password")
def reset_admin_password_cmd(
    password: str | None = typer.Argument(
        None,
        help="New admin password. If omitted, resets to the shipped default 'Argus123' so you "
             "can log in again — change it immediately after.",
    ),
    username: str = typer.Option(
        "admin", "--username", help="Admin username. Default: admin.",
    ),
) -> None:
    """Break-glass reset for the admin password.

    Writes directly to `~/.cyllex-argus/argus.toml` without needing the running server, so a
    lost password is recoverable from the host without re-provisioning the config. Without a password argument,
    the account is reset to the shipped default (`admin` / `Argus123`); with one, the behaviour
    matches `set-admin-password`.
    """
    import bcrypt

    from cyllex_argus.web.api.auth import DEFAULT_ADMIN_PASSWORD

    effective_password = password or DEFAULT_ADMIN_PASSWORD
    hashed = bcrypt.hashpw(effective_password.encode("utf-8"), bcrypt.gensalt()).decode("ascii")
    services = _open()
    try:
        cfg = services.config
        config_path = services.paths.config_file
        cfg.auth.admin_username = username
        cfg.auth.admin_password_hash = hashed
        from cyllex_argus.config.settings import save_config
        save_config(cfg, config_path)
        _sync_admin_user(services.store, username, hashed)
    finally:
        services.close()
    if password is None:
        _say(
            f"Admin password reset to the default ('{DEFAULT_ADMIN_PASSWORD}') for user '{username}'. "
            f"Change it with `argus set-admin-password <new>` right after logging in. "
            f"Hash lives in {config_path}.",
            style="yellow",
        )
    else:
        _say(
            f"Admin password reset for user '{username}'. Login via the web UI; "
            f"the hash lives in {config_path}.",
            style="green",
        )


@app.command(name="generate-detections")
def generate_detections_cmd(
    entity: str = typer.Argument(..., help="Threat whose IOCs/techniques to generate Sigma detections for."),
    out: Path | None = typer.Option(
        None, "--out", "-o",
        help="Directory to write into. Defaults to argus-detections/<entity>-<timestamp>/.",
    ),
    author: str = typer.Option("Cyllex Argus", "--author", help="Rule author field."),
) -> None:
    """Generate Sigma detections from a threat profile.

    Writes one Sigma rule per indicator (IP/domain/URL/hash) with the right logsource, and a
    SIGMAHQ-REFERENCES.md linking every observed MITRE technique to the existing SigmaHQ rules
    tagged with it. Argus does not invent a detection per technique; it points you at the
    community's vetted ones. IOCs with no known Sigma shape are skipped silently.
    """
    from cyllex_argus.detections.sigma import generate as sigma_generate
    from cyllex_argus.detections.sigma import references_markdown, sigmahq_references
    from cyllex_argus.knowledge.profile import build_profile

    services = _open()
    try:
        found = services.store.find_by_alias(entity)
        if found is None:
            _fail(f"Unknown entity: {entity}")
        profile = build_profile(services.store, services.store.get_entity(found.id))
        rules = sigma_generate(profile, author=author)
        references = sigmahq_references(profile)
    finally:
        services.close()
    if not rules and not references:
        _say("No IOCs or techniques to turn into detections.", style="yellow")
        return

    target = out or _default_detections_out(found.canonical_name)
    target.mkdir(parents=True, exist_ok=True)
    for rule in rules:
        safe = re.sub(r"[^a-z0-9]+", "-", rule.title.lower()).strip("-")[:80] or rule.id
        (target / f"{safe}.yml").write_text(rule.to_yaml() + "\n", encoding="utf-8")
    if references:
        (target / "SIGMAHQ-REFERENCES.md").write_text(references_markdown(references), encoding="utf-8")
    _say(
        f"Wrote {len(rules)} Sigma rule(s)"
        + (f" and {len(references)} SigmaHQ reference(s)" if references else "")
        + f" to {target}"
    )


def _open_browser_later(url: str) -> threading.Timer:
    timer = threading.Timer(1.0, webbrowser.open, args=(url,))
    timer.daemon = True  # a failed bind must not keep the process alive for the timer
    timer.start()
    return timer


def _lan_ip() -> str | None:
    """Best-effort local LAN IP; used only to print a usable URL when binding to a non-loopback address."""
    import socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("192.0.2.1", 80))  # RFC 5737 TEST-NET-1; no packet is sent for UDP connect.
        return sock.getsockname()[0]
    except OSError:
        return None
    finally:
        sock.close()


def _default_password_in_use() -> bool:
    """True when neither `ARGUS_ADMIN_PASSWORD` env nor `[auth] admin_password_hash` is set —
    the server will accept the built-in `Argus123` default and the CLI prints a nudge to change
    it. Mirrors `cyllex_argus.web.api.auth.is_using_default_password` so the two never drift.
    """
    if os.environ.get("ARGUS_ADMIN_PASSWORD"):
        return False
    try:
        services = _open()
        try:
            return not services.config.auth.admin_password_hash
        finally:
            services.close()
    except Exception:  # noqa: BLE001 — a missing / malformed config means "fresh install → default".
        return True


@app.command()
def serve(
    port: int = typer.Option(8765, "--port", min=1024, max=65535, help="Local port."),
    host: str = typer.Option(
        "127.0.0.1",
        "--host",
        help=(
            "Interface to bind: 127.0.0.1 (default, local-only) or 0.0.0.0 to accept LAN connections. "
            "In LAN mode the session token travels in plain HTTP after login; use only on a trusted network."
        ),
    ),
    no_browser: bool = typer.Option(False, "--no-browser", help="Do not open a browser tab."),
    session_ttl: int = typer.Option(
        7 * 24 * 3600, "--session-ttl", min=0,
        help="How long (in seconds) the session token issued by /api/auth/login is accepted before "
             "'session expired' is returned. Default is 7 days. Pass 0 to disable expiry (not "
             "recommended; the token stays valid for the lifetime of the server).",
    ),
) -> None:
    """Start the local web interface.

    The UI is gated by a login screen. If neither `ARGUS_ADMIN_PASSWORD` nor the toml hash is set,
    the server accepts the built-in default `admin` / `Argus123`; change it with
    `argus reset-admin-password <new>` or set `ARGUS_ADMIN_PASSWORD` before running serve.
    """
    from cyllex_argus.web.app import create_app

    # Session token: the opaque string the UI holds in localStorage after /api/auth/login
    # succeeds, and that the middleware checks on every subsequent request. It is NEVER
    # distributed via URL fragment — the login screen is the only way to obtain it.
    token = secrets.token_urlsafe(32)
    max_age: int | None = session_ttl if session_ttl > 0 else None

    extra_hosts: list[str] = []
    reachable_url = f"http://127.0.0.1:{port}/"
    if host != "127.0.0.1":
        lan_ip = _lan_ip()
        if lan_ip:
            extra_hosts.append(f"{lan_ip}:{port}")
            reachable_url = f"http://{lan_ip}:{port}/"
        _say(
            "LAN mode: the API accepts requests from other machines on your network. "
            "The session token travels in plain HTTP after login; do not use this on a network you do not trust.",
            style="yellow", stderr=True,
        )

    web_app = create_app(
        services_factory, token=token, port=port, extra_hosts=extra_hosts,
        token_max_age_seconds=max_age,
    )
    _say(f"Cyllex Argus is running at {reachable_url}", soft_wrap=True)
    if _default_password_in_use():
        _say(
            "Default admin credentials in use: 'admin' / 'Argus123'. Change them with "
            "`argus reset-admin-password <new>` or set ARGUS_ADMIN_PASSWORD.",
            style="yellow",
        )
    else:
        _say("Login screen gates every page — authenticate as admin to open the dashboard.", style="green")
    _say("Press Ctrl+C to stop.")
    local_url = f"http://127.0.0.1:{port}/"
    timer = None if no_browser else _open_browser_later(local_url)
    try:
        # The graceful-shutdown timeout keeps an open live-progress (SSE) stream from holding Ctrl+C
        # until the running job ends.
        uvicorn.run(web_app, host=host, port=port, log_level="warning", timeout_graceful_shutdown=3)
    finally:
        if timer is not None:
            timer.cancel()
        web_app.state.jobs.shutdown()
