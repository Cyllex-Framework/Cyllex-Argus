from datetime import date

import httpx
import pytest

from cyllex_argus.config.settings import ArgusConfig, LimitsConfig, get_paths
from cyllex_argus.documents.fetch import Fetcher
from cyllex_argus.knowledge.models import AliasOrigin, AssessmentStatus, InvestigationState, Stage
from cyllex_argus.knowledge.trace import SQLiteTraceRecorder
from cyllex_argus.llm.base import InvalidOutput, LLMTimeout, LLMUnavailable
from cyllex_argus.pipeline.investigation import INTERNAL_PUBLISHER, Pipeline
from cyllex_argus.sources.base import CandidateSource
from cyllex_argus.sources.web_search import WebSearchConnector
from tests.support import INVALID_URLS, QUOTE, SPIDER, ScriptedLLM, _public_resolver, web_transport

MANDIANT = "https://mandiant.example/spider"
MICROSOFT = "https://microsoft.example/octo"
NEWS = "https://news.example/other"
IMAGE = "https://img.example/chart"


class World:
    def __init__(
        self, store, catalog, tmp_path, analyst_error_on_call=None, *,
        llm=None, connectors=None, transport=None, failing_urls=None, config=None,
    ):
        self.store = store
        self.logs: list[str] = []
        self.llm = llm or ScriptedLLM(analyst_error_on_call)
        paths = get_paths(tmp_path / "home")
        paths.ensure()
        fetcher = Fetcher(
            httpx.Client(transport=transport or web_transport(failing_urls)),
            max_bytes=100_000, sleep=lambda s: None, resolve_host=_public_resolver,
        )
        self.recorder = SQLiteTraceRecorder(store.connection, retain_raw=True)
        self.pipeline = Pipeline(
            store, config or ArgusConfig(), paths, self.llm, fetcher,
            connectors if connectors is not None else [WebSearchConnector(self.llm)], catalog,
            trace=self.recorder, log=self.logs.append, today=lambda: date(2026, 9, 29),
        )


class StaticConnector:
    """A connector that returns fixed candidates."""

    def __init__(self, candidates, name="static"):
        self.name = name
        self._candidates = candidates

    def search(self, target, limit=None):
        return list(self._candidates)


FALCON = "PROJECT-FALCON-7"
FALCON_MEMO = f"Internal memo\n\nScattered Spider {QUOTE}. Scattered Spider is also tracked internally as {FALCON}."
FALCON_ALIAS_CLAIM = {
    "subject": FALCON, "subject_type": "intrusion-set", "predicate": "alias-of",
    "object": "Scattered Spider", "object_type": "intrusion-set", "polarity": "asserts",
    "quote": f"Scattered Spider is also tracked internally as {FALCON}",
}


class AliasLearningLLM(ScriptedLLM):
    """A ScriptedLLM whose Analyst also extracts the internal codename from any part that states it."""

    def _handle(self, request):
        answer = super()._handle(request)
        if request.prompt_version.startswith("analyst") and "tracked internally" in request.content:
            answer = {**answer, "claims": [*answer["claims"], FALCON_ALIAS_CLAIM]}
        return answer


class BrokenClaimLLM(ScriptedLLM):
    """A ScriptedLLM whose Analyst quotes text that is not in any document."""

    def _handle(self, request):
        answer = super()._handle(request)
        if request.prompt_version.startswith("analyst"):
            answer = {**answer, "claims": [{**c, "quote": "this sentence appears nowhere in the report"}
                                           for c in answer["claims"]]}
        return answer


class BrokenConnector:
    name = "broken"

    def search(self, target, limit=None):
        raise RuntimeError("feed exploded")


class BrokenLLM(ScriptedLLM):
    """A ScriptedLLM that answers with an error whenever `fail(request)` returns one."""

    def __init__(self, fail):
        self._fail = fail
        super().__init__()

    def _handle(self, request):
        error = self._fail(request)
        return error if error is not None else super()._handle(request)


def image_transport():
    """Serves an image at IMAGE and the usual fake world everywhere else."""
    inner = web_transport()

    def handler(request):
        if str(request.url) == IMAGE:
            return httpx.Response(200, content=b"\x89PNG\r\n", headers={"content-type": "image/png"})
        return inner.handle_request(request)

    return httpx.MockTransport(handler)


def claim_counts_of_validated_documents(store, investigation_id):
    documents = store.investigation_documents(investigation_id)
    return [len(store.claims_for_document(d.id)) for d in documents if d.stage is Stage.VALIDATED]


@pytest.fixture
def world(attack_store, attack_catalog, tmp_path):
    return World(attack_store, attack_catalog, tmp_path)


def test_resolve_target_uses_attack_aliases(world):
    target = world.pipeline.resolve_target("octo tempest")
    assert target.name == "Scattered Spider"
    assert target.entity_id == SPIDER
    assert "UNC3944" in target.aliases
    unknown = world.pipeline.resolve_target("New Actor")
    assert (unknown.name, unknown.entity_id, unknown.aliases) == ("New Actor", None, ["New Actor"])


def test_resolve_target_recognises_a_known_group_inside_a_long_query(world):
    """When the full phrase doesn't name an entity but one of the proper-noun chunks does
    ("Scattered Spider" inside "Scattered Spider Microsoft breach 2024"), that entity's
    full MITRE alias set is pulled in. Without this, triage would scan docs for the long
    phrase, drop every one (10-word phrases never appear verbatim), and no claims extract.

    This is the "operator typed a search-engine-style query" rescue path."""
    target = world.pipeline.resolve_target("Scattered Spider Microsoft breach 2024")
    assert target.name == "Scattered Spider"
    assert target.entity_id == SPIDER
    assert "UNC3944" in target.aliases
    # Also exercised when the known alias is a bare proper-noun token, not a two-word run.
    # (In MITRE 'APT29' is the canonical name; here we'll use the fixture equivalent.)
    bare = world.pipeline.resolve_target("UNC3944 campaign targeting hospitality 2024")
    assert bare.entity_id == SPIDER
    assert bare.name == "Scattered Spider"


def test_search_aliases_exclude_aliases_learned_from_documents(world):
    world.store.add_alias(FALCON, SPIDER, AliasOrigin.DOCUMENT)
    world.store.add_alias("Spidey", SPIDER, AliasOrigin.USER)
    target = world.pipeline.resolve_target("Scattered Spider")
    assert FALCON in target.aliases
    assert FALCON not in target.search_aliases
    assert target.search_aliases[0] == "Scattered Spider"
    assert {"UNC3944", "Octo Tempest", "Spidey"} <= set(target.search_aliases)
    # An analyst who types the internal codename still gets a search for the public names only.
    assert FALCON not in world.pipeline.resolve_target(FALCON.lower()).search_aliases
    assert world.pipeline.resolve_target("New Actor").search_aliases == ["New Actor"]


def test_a_canonical_name_learned_from_documents_never_reaches_the_web_search(world):
    internal = world.store.create_entity("intrusion-set", FALCON, AliasOrigin.DOCUMENT)
    world.store.add_alias("Storm-1234", internal.id, AliasOrigin.DOCUMENT)
    target = world.pipeline.resolve_target("storm-1234")
    assert target.name == FALCON and FALCON in target.aliases
    assert target.search_aliases == ["storm-1234"]  # only what the user typed
    WebSearchConnector(world.llm).search(target)
    [search] = world.llm.calls_for("web-search")
    assert FALCON not in search.content
    assert search.content.startswith("Threat: storm-1234\n")


def test_aliases_learned_from_documents_never_reach_the_web_search(attack_store, attack_catalog, tmp_path):
    memo = tmp_path / "memo.txt"
    memo.write_text(FALCON_MEMO, encoding="utf-8")
    llm = AliasLearningLLM()
    world = World(attack_store, attack_catalog, tmp_path, llm=llm)
    world.pipeline.ingest([memo])
    assert attack_store.find_by_alias(FALCON).id == SPIDER  # the memo taught the internal codename

    report = world.pipeline.investigate("Scattered Spider")
    assert report.state is InvestigationState.FINISHED
    searches = llm.calls_for("web-search")
    assert searches and all(FALCON not in call.content for call in searches)
    assert all("UNC3944" in call.content for call in searches)
    # Local steps (triage, Analyst) still know every alias.
    assert FALCON in world.pipeline.resolve_target("Scattered Spider").aliases


def test_investigate_end_to_end(world):
    report = world.pipeline.investigate("Scattered Spider")
    assert report.state is InvestigationState.FINISHED
    assert report.stage_counts == {"failed": 1, "irrelevant": 1, "validated": 2}
    assert report.claims_accepted == 2
    assert world.llm.analyst_calls == 2
    assert world.llm.calls_for("triage") == []
    [assessment] = world.store.assessments_involving(SPIDER)
    assert assessment.status is AssessmentStatus.CORROBORATED
    failures = world.store.failures(report.investigation_id)
    assert failures[0][0] == "Gone" and "404" in failures[0][1]


def test_cancel_flag_primitives(world):
    """`request_investigation_cancel` / `is_investigation_cancel_requested` are the
    coordination primitives the pipeline uses to stop a run between docs. A deleted
    investigation reads as "cancel requested" so the DELETE path (which fires the
    flag + removes the row) still produces a clean pipeline exit on its next check."""
    world.pipeline.investigate("Scattered Spider")  # creates investigation #1
    assert world.store.is_investigation_cancel_requested(1) is False
    world.store.request_investigation_cancel(1)
    assert world.store.is_investigation_cancel_requested(1) is True
    # Transitioning to RUNNING clears the flag (otherwise Resume would immediately re-cancel).
    world.store.set_investigation_state(1, InvestigationState.RUNNING)
    assert world.store.is_investigation_cancel_requested(1) is False
    # A row that no longer exists reads as "cancel requested" — same signal to the pipeline.
    world.store.delete_investigation(1)
    assert world.store.is_investigation_cancel_requested(1) is True
    assert world.store.is_investigation_cancel_requested(99999) is True


def test_investigate_with_concurrency_matches_sequential_output(world):
    """`concurrency > 1` runs the Triage+Analyst stages on a ThreadPoolExecutor. Each doc
    is independent at this layer so the output must be identical to the sequential run —
    same stage counts, same claims, same final assessment. The `_LockedConnection` wrapper
    on SQLiteStore is what makes this safe: writes from parallel workers hit the store
    one at a time, so the Validator and TraceRecorder never trip `InterfaceError`."""
    report = world.pipeline.investigate("Scattered Spider", concurrency=3)
    assert report.state is InvestigationState.FINISHED
    assert report.stage_counts == {"failed": 1, "irrelevant": 1, "validated": 2}
    assert report.claims_accepted == 2
    [assessment] = world.store.assessments_involving(SPIDER)
    assert assessment.status is AssessmentStatus.CORROBORATED


def test_investigate_records_a_trace_per_decision(world):
    report = world.pipeline.investigate("Scattered Spider")
    events = world.recorder.list_events(report.investigation_id)
    by_stage = [(e.stage, e.decision) for e in events]
    assert by_stage.count(("collector", "collected")) == 3
    assert by_stage.count(("collector", "failed")) == 1
    assert by_stage.count(("analyst", "analyzed")) == 2
    assert by_stage.count(("validator", "validated")) == 2
    assert ("triage", "triaged-out") in by_stage
    # Every per-document decision is attributed to its document; the executive summary is the
    # one run-level event — it summarizes the whole profile, so it belongs to no single document.
    assert all(e.document_id is not None for e in events if e.stage != "summary")
    [summary_event] = [e for e in events if e.stage == "summary"]
    assert summary_event.document_id is None
    # Collection precedes analysis, and analysis precedes validation, for the whole run.
    stages = [e.stage for e in events]
    assert stages.index("collector") < stages.index("analyst") < stages.index("validator")
    [failed] = [e for e in events if e.decision == "failed"]
    assert "404" in failed.reason


def test_analyst_event_carries_the_raw_exchange_for_the_recorder(world):
    report = world.pipeline.investigate("Scattered Spider")
    [first, *_] = [e for e in world.recorder.list_events(report.investigation_id) if e.stage == "analyst"]
    prompt, response = world.recorder.raw(first.id)
    assert "<document>" in prompt and "claims" in response


def test_rejected_claims_are_traced_with_a_reason(world):
    world.llm = world.pipeline._llm = BrokenClaimLLM()
    report = world.pipeline.investigate("Scattered Spider")
    events = world.recorder.list_events(report.investigation_id)
    rejected = [e for e in events if e.decision == "rejected"]
    assert rejected and all(e.stage == "validator" and e.reason for e in rejected)


def test_a_failing_analyst_is_traced(attack_store, attack_catalog, tmp_path):
    llm = BrokenLLM(lambda r: InvalidOutput("bad json") if r.prompt_version.startswith("analyst") else None)
    world = World(attack_store, attack_catalog, tmp_path, llm=llm)
    report = world.pipeline.investigate("Scattered Spider")
    events = world.recorder.list_events(report.investigation_id)
    assert ("analyst", "failed") in [(e.stage, e.decision) for e in events]


def test_the_default_recorder_records_nothing(attack_store, attack_catalog, tmp_path):
    world = World(attack_store, attack_catalog, tmp_path)
    pipeline = Pipeline(
        world.store, ArgusConfig(), get_paths(tmp_path / "home"), world.llm, world.pipeline._fetcher,
        [], attack_catalog,
    )
    report = pipeline.investigate("Scattered Spider")
    assert report.state is InvestigationState.FINISHED
    assert world.recorder.list_events(report.investigation_id) == []


def test_investigate_reports_progress(world):
    world.pipeline.investigate("Scattered Spider")
    progress = [m for m in world.logs if m.startswith(("Collected", "Downloading", "Analyzing", "Irrelevant"))]
    assert progress == [
        "Collected 4 candidate(s)",
        f"Downloading 1/4: {MANDIANT}",
        f"Downloading 2/4: {MICROSOFT}",
        f"Downloading 3/4: {NEWS}",
        "Downloading 4/4: https://gone.example/404",
        "Analyzing 1/3: Scattered Spider deep dive",
        "Analyzing 2/3: Octo Tempest update",
        "Analyzing 3/3: Weekly news",
        "Irrelevant: Weekly news",
    ]


def test_max_docs_is_reported_when_it_drops_candidates(attack_store, attack_catalog, tmp_path):
    # A source supplies more candidates than the run's budget; the collector downloads the
    # first max_docs and reports how many it dropped. Web search now respects max_docs itself,
    # so the over-supply here comes from a feed-like connector that ignores the per-run limit.
    cands = [CandidateSource(url=u) for u in (MANDIANT, MICROSOFT, NEWS, IMAGE)]
    world = World(attack_store, attack_catalog, tmp_path, connectors=[StaticConnector(cands)])
    world.pipeline.investigate("Scattered Spider", max_docs=1)
    assert "Collected 4 candidate(s); downloading the first 1" in world.logs


def test_ingest_reports_progress(world, tmp_path):
    memo = tmp_path / "memo.txt"
    memo.write_text(f"Incident memo\n\nScattered Spider {QUOTE}.", encoding="utf-8")
    world.pipeline.ingest([memo])
    assert "Analyzing 1/1: Incident memo" in world.logs


def test_rate_limit_pauses_and_resume_does_not_redo_work(attack_store, attack_catalog, tmp_path):
    world = World(attack_store, attack_catalog, tmp_path, analyst_error_on_call=2)
    first = world.pipeline.investigate("Scattered Spider")
    assert first.state is InvestigationState.PAUSED
    assert "Re-run" in first.message
    assert first.stage_counts["validated"] == 1 and first.stage_counts["triaged"] == 1
    searches_after_pause = len(world.llm.calls_for("web-search"))
    assert searches_after_pause >= 1  # collection ran once: one web search per alias
    second = world.pipeline.investigate("Scattered Spider")
    assert second.investigation_id == first.investigation_id
    assert second.state is InvestigationState.FINISHED
    assert world.llm.analyst_calls == 3
    # Resume does not re-collect: the web-search count is unchanged from the single collection pass.
    assert len(world.llm.calls_for("web-search")) == searches_after_pause
    assert claim_counts_of_validated_documents(attack_store, first.investigation_id) == [1, 1]


def test_max_docs_limits_downloads(world):
    report = world.pipeline.investigate("Scattered Spider", max_docs=1)
    assert sum(report.stage_counts.values()) == 1


def test_rerun_after_finish_reuses_validated_documents(world):
    world.pipeline.investigate("Scattered Spider")
    again = world.pipeline.investigate("Scattered Spider")
    assert again.state is InvestigationState.FINISHED
    assert world.llm.analyst_calls == 2


def test_rerun_logs_reuse_honestly(world):
    """A second run must not claim to "download" a document it reuses from the store, and it
    reports the fetched/reused/failed split so the operator can see re-running is incremental."""
    world.pipeline.investigate("Scattered Spider")
    first_run_logs = len(world.logs)
    world.pipeline.investigate("Scattered Spider")
    second = world.logs[first_run_logs:]
    reused = [m for m in second if m.startswith("Reusing")]
    assert len(reused) == 3  # the three successfully-read sources; the 404 is re-attempted
    assert not any(m.startswith("Downloading 1/") for m in second)  # nothing fetched anew succeeds
    assert "Documents: 0 fetched, 3 reused, 1 failed" in second


def test_prompt_version_change_reanalyzes_without_duplicates(world):
    first = world.pipeline.investigate("Scattered Spider")
    for document in world.store.investigation_documents(first.investigation_id):
        if document.analyzed_prompt_version:
            world.store.set_analysis(document.id, document.effective_publisher_id, "analyst-v0")
    world.pipeline.investigate("Scattered Spider")
    assert world.llm.analyst_calls == 4
    assert claim_counts_of_validated_documents(world.store, first.investigation_id) == [1, 1]


def test_ingest_without_target_skips_triage(world, tmp_path):
    memo = tmp_path / "memo.txt"
    memo.write_text(f"Incident memo\n\nScattered Spider {QUOTE}.", encoding="utf-8")
    report = world.pipeline.ingest([memo])
    assert report.state is InvestigationState.FINISHED
    assert report.stage_counts == {"validated": 1}
    [call] = world.llm.calls_for("analyst")
    assert "every threat actor" in call.content
    assert f"Publisher: {INTERNAL_PUBLISHER}" in call.content
    [document] = world.store.investigation_documents(report.investigation_id)
    assert document.local_path == str(memo.resolve())


def test_ingest_unreadable_file_fails_only_that_document(world, tmp_path):
    good = tmp_path / "good.txt"
    good.write_text(f"Notes\n\nScattered Spider {QUOTE}.", encoding="utf-8")
    bad = tmp_path / "bad.bin"
    bad.write_bytes(b"\x00\x01binary")
    report = world.pipeline.ingest([bad, good], target="Scattered Spider")
    assert report.stage_counts == {"failed": 1, "validated": 1}


def test_ingest_missing_file_fails_only_that_document(world, tmp_path):
    good = tmp_path / "good.txt"
    good.write_text(f"Notes\n\nScattered Spider {QUOTE}.", encoding="utf-8")
    missing = tmp_path / "missing.txt"
    report = world.pipeline.ingest([missing, good], target="Scattered Spider")
    assert report.state is InvestigationState.FINISHED
    assert report.stage_counts == {"failed": 1, "validated": 1}
    [(title, reason)] = world.store.failures(report.investigation_id)
    assert title == "missing.txt" and reason


def test_malformed_candidate_url_is_skipped_not_fatal(attack_store, attack_catalog, tmp_path):
    connector = StaticConnector([
        CandidateSource(url="https://host:abc/x", title="Bad port"),
        CandidateSource(url="http://[::1/x", title="Bad host"),
        CandidateSource(url=MANDIANT, title="Deep dive", publisher="Mandiant"),
    ])
    world = World(attack_store, attack_catalog, tmp_path, connectors=[connector])
    report = world.pipeline.investigate("Scattered Spider")
    assert report.state is InvestigationState.FINISHED
    assert report.stage_counts == {"validated": 1}
    assert len([m for m in world.logs if m.startswith("Skipping malformed URL: https://host:abc/x")]) == 1
    assert any(m.startswith("Skipping malformed URL: http://[::1/x") for m in world.logs)
    assert attack_store.get_investigation(report.investigation_id).collected


def test_failed_download_is_retried_by_a_later_investigation(attack_store, attack_catalog, tmp_path):
    failing = {MANDIANT}
    world = World(attack_store, attack_catalog, tmp_path, failing_urls=failing)
    first = world.pipeline.investigate("Scattered Spider")
    assert first.state is InvestigationState.FINISHED
    assert first.stage_counts == {"failed": 2, "irrelevant": 1, "validated": 1}
    failed = attack_store.find_document_by_canonical_url(MANDIANT)
    assert failed.stage is Stage.FAILED and "503" in failed.failure_reason

    failing.clear()
    second = world.pipeline.investigate("Scattered Spider")
    assert second.investigation_id != first.investigation_id
    assert second.stage_counts == {"failed": 1, "irrelevant": 1, "validated": 2}
    revived = attack_store.find_document_by_canonical_url(MANDIANT)
    assert revived.id == failed.id
    assert revived.stage is Stage.VALIDATED and revived.failure_reason is None
    assert len(attack_store.claims_for_document(revived.id)) == 1
    assert world.llm.analyst_calls == 2


def test_known_documents_are_not_downloaded_again(attack_store, attack_catalog, tmp_path):
    requested: list[str] = []
    inner = web_transport()

    def handler(request):
        requested.append(str(request.url))
        return inner.handle_request(request)

    world = World(attack_store, attack_catalog, tmp_path, transport=httpx.MockTransport(handler))
    world.pipeline.investigate("Scattered Spider")
    # The 404 doc goes through the Wayback rescue (also 404 against the mock), so it
    # appears twice in the recorded calls — original URL + the archive.org hop.
    assert sorted(requested) == sorted([
        MANDIANT, MICROSOFT, NEWS,
        "https://gone.example/404",
        "https://web.archive.org/web/0/https://gone.example/404",
    ])
    requested.clear()
    again = world.pipeline.investigate("Scattered Spider")
    # Only the failed download is retried; its Wayback rescue runs again on retry.
    assert requested == [
        "https://gone.example/404",
        "https://web.archive.org/web/0/https://gone.example/404",
    ]
    assert again.stage_counts == {"failed": 1, "irrelevant": 1, "validated": 2}


def test_paused_ingest_is_not_resumed_by_investigate(attack_store, attack_catalog, tmp_path):
    memo = tmp_path / "memo.txt"
    memo.write_text(f"Incident memo\n\nScattered Spider {QUOTE}.", encoding="utf-8")
    ingest_world = World(attack_store, attack_catalog, tmp_path, analyst_error_on_call=1)
    paused = ingest_world.pipeline.ingest([memo], target="Scattered Spider")
    assert paused.state is InvestigationState.PAUSED
    assert paused.target == "ingest: Scattered Spider"
    assert ingest_world.pipeline.ingest([memo]).target == "ingest: all"

    web_world = World(attack_store, attack_catalog, tmp_path)
    report = web_world.pipeline.investigate("Scattered Spider")
    assert report.investigation_id != paused.investigation_id
    assert len(web_world.llm.calls_for("web-search")) >= 1  # a fresh investigate runs its own collection (one search per alias)
    assert report.state is InvestigationState.FINISHED


def test_triage_invalid_output_fails_only_that_document(attack_store, attack_catalog, tmp_path):
    single = tmp_path / "single.txt"
    single.write_text(f"Single mention\n\nScattered Spider {QUOTE}.", encoding="utf-8")
    double = tmp_path / "double.txt"
    double.write_text(
        f"Double mention\n\nScattered Spider {QUOTE}. Scattered Spider persists.", encoding="utf-8"
    )
    llm = BrokenLLM(lambda r: InvalidOutput("not json") if r.prompt_version.startswith("triage") else None)
    world = World(attack_store, attack_catalog, tmp_path, llm=llm)
    report = world.pipeline.ingest([single, double], target="Scattered Spider")
    assert report.state is InvestigationState.FINISHED
    assert report.stage_counts == {"failed": 1, "validated": 1}
    # Triage retries once before giving up (max_retries=1); the single-mention doc still fails.
    assert len(llm.calls_for("triage")) == 2
    [(title, reason)] = attack_store.failures(report.investigation_id)
    assert title == "Single mention" and reason.startswith("triage:")


def test_analyst_invalid_output_fails_only_that_document(attack_store, attack_catalog, tmp_path):
    bad = tmp_path / "bad.txt"
    bad.write_text(f"Bad answer\n\nScattered Spider {QUOTE}. Scattered Spider persists.", encoding="utf-8")
    good = tmp_path / "good.txt"
    good.write_text(f"Good answer\n\nScattered Spider {QUOTE}. Scattered Spider persists.", encoding="utf-8")

    def fail(request):
        if request.prompt_version.startswith("analyst") and "Document title: Bad answer" in request.content:
            return InvalidOutput("not json")
        return None

    llm = BrokenLLM(fail)
    world = World(attack_store, attack_catalog, tmp_path, llm=llm)
    report = world.pipeline.ingest([bad, good], target="Scattered Spider")
    assert report.state is InvestigationState.FINISHED
    assert report.stage_counts == {"failed": 1, "validated": 1}
    assert len(llm.calls_for("analyst")) == 3 + 1  # the bad document is retried twice, the good one answers once
    [(title, reason)] = attack_store.failures(report.investigation_id)
    assert title == "Bad answer" and reason.startswith("analyst:")
    assert claim_counts_of_validated_documents(attack_store, report.investigation_id) == [1]


def test_failing_connector_is_logged_and_skipped(attack_store, attack_catalog, tmp_path):
    llm = ScriptedLLM()
    world = World(
        attack_store, attack_catalog, tmp_path, llm=llm,
        connectors=[BrokenConnector(), WebSearchConnector(llm)],
    )
    report = world.pipeline.investigate("Scattered Spider")
    assert report.state is InvestigationState.FINISHED
    assert report.stage_counts == {"failed": 1, "irrelevant": 1, "validated": 2}
    assert "Source broken failed: feed exploded" in world.logs


def test_llm_unavailable_propagates_and_the_investigation_can_be_resumed(attack_store, attack_catalog, tmp_path):
    llm = BrokenLLM(
        lambda r: LLMUnavailable("not logged in") if r.prompt_version.startswith("web-search") else None
    )
    broken = World(attack_store, attack_catalog, tmp_path, llm=llm)
    with pytest.raises(LLMUnavailable):
        broken.pipeline.investigate("Scattered Spider")
    interrupted = attack_store.latest_investigation()
    assert not interrupted.collected

    healthy = World(attack_store, attack_catalog, tmp_path)
    report = healthy.pipeline.investigate("Scattered Spider")
    assert report.investigation_id == interrupted.id
    assert report.state is InvestigationState.FINISHED


def test_extraction_failure_fails_only_that_document(attack_store, attack_catalog, tmp_path):
    connector = StaticConnector([
        CandidateSource(url=IMAGE, title="Chart", publisher="Charts"),
        CandidateSource(url=MANDIANT, title="Deep dive", publisher="Mandiant"),
    ])
    world = World(attack_store, attack_catalog, tmp_path, connectors=[connector], transport=image_transport())
    report = world.pipeline.investigate("Scattered Spider")
    assert report.stage_counts == {"failed": 1, "validated": 1}
    [(title, reason)] = attack_store.failures(report.investigation_id)
    assert title == "Chart" and "image/png" in reason


def test_max_docs_keeps_the_most_recent_candidates(attack_store, attack_catalog, tmp_path):
    connector = StaticConnector([
        CandidateSource(url=NEWS, title="Old", published_at=date(2025, 1, 1)),
        CandidateSource(url=MICROSOFT, title="Newest", published_at=date(2026, 6, 1)),
        CandidateSource(url=MANDIANT, title="Middle", published_at=date(2026, 1, 1)),
    ])
    world = World(attack_store, attack_catalog, tmp_path, connectors=[connector])
    report = world.pipeline.investigate("Scattered Spider", max_docs=1)
    [document] = attack_store.investigation_documents(report.investigation_id)
    assert document.url == MICROSOFT


def test_max_docs_zero_is_not_treated_as_unlimited(attack_store, attack_catalog, tmp_path):
    connector = StaticConnector([CandidateSource(url=MANDIANT, title="Deep dive", publisher="Mandiant")])
    world = World(attack_store, attack_catalog, tmp_path, connectors=[connector])
    report = world.pipeline.investigate("Scattered Spider", max_docs=0)
    assert report.stage_counts == {}


def test_invalid_candidate_urls_fail_only_those_documents(attack_store, attack_catalog, tmp_path):
    nul_byte, zero_width = INVALID_URLS
    connector = StaticConnector([
        CandidateSource(url=nul_byte, title="Nul byte"),
        CandidateSource(url=zero_width, title="Zero width"),
        CandidateSource(url=MANDIANT, title="Deep dive", publisher="Mandiant"),
    ])
    world = World(attack_store, attack_catalog, tmp_path, connectors=[connector])
    report = world.pipeline.investigate("Scattered Spider")
    assert report.state is InvestigationState.FINISHED
    assert report.stage_counts == {"failed": 2, "validated": 1}
    assert attack_store.get_investigation(report.investigation_id).collected
    failures = attack_store.failures(report.investigation_id)
    assert [title for title, _ in failures] == ["Nul byte", "Zero width"]
    assert all("invalid URL" in reason for _, reason in failures)


def test_analyst_timeout_fails_only_that_document_without_retries(attack_store, attack_catalog, tmp_path):
    slow = tmp_path / "slow.txt"
    slow.write_text(f"Slow answer\n\nScattered Spider {QUOTE}. Scattered Spider persists.", encoding="utf-8")
    good = tmp_path / "good.txt"
    good.write_text(f"Good answer\n\nScattered Spider {QUOTE}. Scattered Spider persists.", encoding="utf-8")

    def fail(request):
        if request.prompt_version.startswith("analyst") and "Document title: Slow answer" in request.content:
            return LLMTimeout("claude timed out after 600s")
        return None

    llm = BrokenLLM(fail)
    world = World(attack_store, attack_catalog, tmp_path, llm=llm)
    report = world.pipeline.ingest([slow, good], target="Scattered Spider")
    assert report.state is InvestigationState.FINISHED
    assert report.stage_counts == {"failed": 1, "validated": 1}
    assert len(llm.calls_for("analyst")) == 1 + 1  # the timed-out part is not re-sent
    [(title, reason)] = attack_store.failures(report.investigation_id)
    assert title == "Slow answer"
    assert reason.startswith("analyst:") and "timed out" in reason and "part 1 of 1" in reason


def test_unexpected_download_error_fails_only_that_document(attack_store, attack_catalog, tmp_path):
    boom = "https://boom.example/crash"
    inner = web_transport()

    def handler(request):
        if str(request.url) == boom:
            raise RuntimeError("parser exploded")
        return inner.handle_request(request)

    connector = StaticConnector([
        CandidateSource(url=boom, title="Boom"),
        CandidateSource(url=MANDIANT, title="Deep dive", publisher="Mandiant"),
    ])
    world = World(attack_store, attack_catalog, tmp_path, connectors=[connector], transport=httpx.MockTransport(handler))
    report = world.pipeline.investigate("Scattered Spider")
    assert report.state is InvestigationState.FINISHED
    assert report.stage_counts == {"failed": 1, "validated": 1}
    assert attack_store.failures(report.investigation_id) == [("Boom", "unexpected error: RuntimeError: parser exploded")]


def test_unexpected_processing_error_fails_only_that_document(attack_store, attack_catalog, tmp_path):
    bad = tmp_path / "bad.txt"
    bad.write_text(f"Bad answer\n\nScattered Spider {QUOTE}. Scattered Spider persists.", encoding="utf-8")
    good = tmp_path / "good.txt"
    good.write_text(f"Good answer\n\nScattered Spider {QUOTE}. Scattered Spider persists.", encoding="utf-8")

    def fail(request):
        if request.prompt_version.startswith("analyst") and "Document title: Bad answer" in request.content:
            return RuntimeError("kaboom")
        return None

    world = World(attack_store, attack_catalog, tmp_path, llm=BrokenLLM(fail))
    report = world.pipeline.ingest([bad, good], target="Scattered Spider")
    assert report.state is InvestigationState.FINISHED
    assert report.stage_counts == {"failed": 1, "validated": 1}
    assert attack_store.failures(report.investigation_id) == [("Bad answer", "unexpected error: RuntimeError: kaboom")]


def test_unexpected_error_after_validation_leaves_no_claims_behind(world, tmp_path):
    memo = tmp_path / "memo.txt"
    memo.write_text(f"Incident memo\n\nScattered Spider {QUOTE}. Scattered Spider persists.", encoding="utf-8")
    process = world.pipeline.validator.process

    def process_then_explode(document, drafts, prompt_version):
        process(document, drafts, prompt_version)
        raise RuntimeError("disk hiccup")

    world.pipeline.validator.process = process_then_explode
    report = world.pipeline.ingest([memo], target="Scattered Spider")
    assert report.stage_counts == {"failed": 1}
    [document] = world.store.investigation_documents(report.investigation_id)
    assert world.store.claims_for_document(document.id) == []
    assert world.store.assessments_involving(SPIDER) == []


def test_long_documents_are_analyzed_up_to_the_configured_number_of_parts(attack_store, attack_catalog, tmp_path):
    memo = tmp_path / "long.txt"
    # Each paragraph is sized to fit in one chunk with the Analyst's default overlap enabled.
    paragraphs = [f"Scattered Spider {QUOTE}. " + "x" * 500 for _ in range(6)]  # one part each
    memo.write_text("Long memo\n\n" + "\n\n".join(paragraphs), encoding="utf-8")
    config = ArgusConfig(limits=LimitsConfig(chunk_chars=1_000, max_chunks_per_document=2))
    world = World(attack_store, attack_catalog, tmp_path, config=config)
    report = world.pipeline.ingest([memo], target="Scattered Spider")
    assert report.stage_counts == {"validated": 1}
    assert world.llm.analyst_calls == 2
    assert "Analyzed only the first 2 of 6 parts of Long memo" in world.logs


def test_llm_unavailable_during_analysis_still_stops_the_run(attack_store, attack_catalog, tmp_path):
    memo = tmp_path / "memo.txt"
    memo.write_text(f"Incident memo\n\nScattered Spider {QUOTE}. Scattered Spider persists.", encoding="utf-8")
    llm = BrokenLLM(lambda r: LLMUnavailable("logged out") if r.prompt_version.startswith("analyst") else None)
    world = World(attack_store, attack_catalog, tmp_path, llm=llm)
    with pytest.raises(LLMUnavailable):
        world.pipeline.ingest([memo], target="Scattered Spider")


def test_resume_finishes_a_paused_investigation(attack_store, attack_catalog, tmp_path):
    world = World(attack_store, attack_catalog, tmp_path, analyst_error_on_call=2)
    first = world.pipeline.investigate("Scattered Spider")
    assert first.state is InvestigationState.PAUSED
    resumed = world.pipeline.resume(first.investigation_id)
    assert resumed.state is InvestigationState.FINISHED
    assert resumed.investigation_id == first.investigation_id


def test_resume_a_paused_ingest(attack_store, attack_catalog, tmp_path):
    world = World(attack_store, attack_catalog, tmp_path, analyst_error_on_call=1)
    memo = tmp_path / "memo.txt"
    memo.write_text(f"Incident memo\n\nScattered Spider {QUOTE}.", encoding="utf-8")
    paused = world.pipeline.ingest([memo], target="Scattered Spider")
    assert paused.state is InvestigationState.PAUSED
    resumed = world.pipeline.resume(paused.investigation_id)
    assert resumed.state is InvestigationState.FINISHED
    assert resumed.target == "ingest: Scattered Spider"
    assert resumed.stage_counts == {"validated": 1}


def test_resume_finished_or_unknown(attack_store, attack_catalog, tmp_path):
    world = World(attack_store, attack_catalog, tmp_path)
    done = world.pipeline.investigate("Scattered Spider")
    again = world.pipeline.resume(done.investigation_id)
    assert again.state is InvestigationState.FINISHED
    assert again.message == "Investigation already finished."
    with pytest.raises(KeyError):
        world.pipeline.resume(999)


def test_resume_continues_the_requested_row_not_the_newest_open_one(attack_store, attack_catalog, tmp_path):
    world = World(attack_store, attack_catalog, tmp_path)
    older = attack_store.create_investigation("Scattered Spider")
    newer = attack_store.create_investigation("Scattered Spider")
    attack_store.set_investigation_state(older.id, InvestigationState.PAUSED)
    attack_store.set_investigation_state(newer.id, InvestigationState.PAUSED)
    report = world.pipeline.resume(older.id)
    assert report.investigation_id == older.id
    assert report.state is InvestigationState.FINISHED
    assert attack_store.get_investigation(older.id).state is InvestigationState.FINISHED
    assert attack_store.investigation_documents(older.id) != []
    untouched = attack_store.get_investigation(newer.id)
    assert untouched.state is InvestigationState.PAUSED and not untouched.collected
    assert attack_store.investigation_documents(newer.id) == []


def test_investigate_writes_the_investigation_id_on_every_claim(world):
    report = world.pipeline.investigate("Scattered Spider")
    claims = [c for d in world.store.investigation_documents(report.investigation_id)
              for c in world.store.claims_for_document(d.id)]
    assert len(claims) == 2
    assert {c.investigation_id for c in claims} == {report.investigation_id}


def test_ingest_writes_the_investigation_id_on_every_claim(world, tmp_path):
    memo = tmp_path / "memo.txt"
    memo.write_text(f"Incident memo\n\nScattered Spider {QUOTE}.", encoding="utf-8")
    report = world.pipeline.ingest([memo])
    [document] = world.store.investigation_documents(report.investigation_id)
    claims = world.store.claims_for_document(document.id)
    assert claims and {c.investigation_id for c in claims} == {report.investigation_id}


# -- end-of-run executive summary -------------------------------------------------


def test_finished_run_writes_the_executive_summary(world):
    """The dashboard's first screen must answer "what did we learn?" without the operator
    paying a click for it, so a finished run leaves the summary in the store."""
    world.pipeline.investigate("Scattered Spider")
    stored = world.store.get_entity_summary(SPIDER)
    assert stored is not None
    assert "financially motivated" in stored.summary
    assert stored.prompt_version == "summary-v5"
    assert stored.fact_count == 1
    # Written from the knowledge as it stands, so the UI opens on a current (not stale) answer.
    from cyllex_argus.exporters.summary import profile_fingerprint
    from cyllex_argus.knowledge.profile import build_profile
    profile = build_profile(world.store, world.store.get_entity(SPIDER))
    assert stored.fingerprint == profile_fingerprint(profile)


def test_summary_on_finish_can_be_turned_off(attack_store, attack_catalog, tmp_path):
    config = ArgusConfig()
    config.pipeline.summary_on_finish = False
    world = World(attack_store, attack_catalog, tmp_path, config=config)
    world.pipeline.investigate("Scattered Spider")
    assert world.store.get_entity_summary(SPIDER) is None


def test_a_failing_summary_does_not_fail_the_run(attack_store, attack_catalog, tmp_path):
    """Every fact is already on disk by the time the summary is attempted. A provider that
    rate-limits on that one last call must not turn a finished investigation into a failed
    one — it logs and the UI offers "Write summary" instead."""

    class SummaryBreaksLLM(ScriptedLLM):
        def _handle(self, request):
            if request.prompt_version.startswith("summary"):
                raise LLMUnavailable("claude binary not found")
            return super()._handle(request)

    world = World(attack_store, attack_catalog, tmp_path, llm=SummaryBreaksLLM())
    report = world.pipeline.investigate("Scattered Spider")
    assert report.state is InvestigationState.FINISHED
    assert report.claims_accepted == 2
    assert world.store.get_entity_summary(SPIDER) is None
    assert any("summary skipped" in line.lower() for line in world.logs)


def test_finished_run_records_the_summary_llm_usage(attack_store, attack_catalog, tmp_path):
    """The executive summary is a billable LLM call. Its tokens and cost must be recorded as a
    pipeline event like every other stage, or the run's cost total silently undercounts the
    summary — exactly what `status` and the dashboard read back."""
    from cyllex_argus.llm.base import LLMUsage

    class SummaryUsageLLM(ScriptedLLM):
        """Reports usage on the summary call the way a real provider does; None elsewhere."""

        def complete_json(self, request, schema):
            response = super().complete_json(request, schema)
            if request.prompt_version.startswith("summary"):
                return response.model_copy(update={"usage": LLMUsage(
                    input_tokens=1000, output_tokens=200, model="claude-sonnet-5-5", duration_ms=5)})
            return response

    world = World(attack_store, attack_catalog, tmp_path, llm=SummaryUsageLLM())
    world.pipeline.investigate("Scattered Spider")

    rows = world.store.connection.execute(
        "SELECT input_tokens, output_tokens, cost_usd, model FROM pipeline_events WHERE stage = 'summary'"
    ).fetchall()
    assert len(rows) == 1, "the summary stage must record exactly one pipeline event"
    row = rows[0]
    assert row["input_tokens"] == 1000
    assert row["output_tokens"] == 200
    assert row["model"] == "claude-sonnet-5-5"
    assert row["cost_usd"] == pytest.approx((1000 * 2.00 + 200 * 10.00) / 1_000_000)  # sonnet-5-5 $2/$10 → $0.004


class RecordingConnector:
    """Records the per-run limit each search() receives, and returns no candidates."""

    name = "recording"

    def __init__(self):
        self.limits: list[int | None] = []

    def search(self, target, limit=None):
        self.limits.append(limit)
        return []


def test_collect_passes_run_max_docs_to_connectors_as_the_search_limit(attack_store, attack_catalog, tmp_path):
    """The max_docs the operator chose for the run governs discovery: it is handed to each
    source connector as the search limit, so web search fans out to what was asked for."""
    rec = RecordingConnector()
    world = World(attack_store, attack_catalog, tmp_path, connectors=[rec])
    world.pipeline.investigate("Scattered Spider", max_docs=37)
    assert rec.limits == [37]


def test_collect_passes_configured_max_docs_when_the_run_does_not_override(attack_store, attack_catalog, tmp_path):
    """With no per-run max_docs, the [limits] max_docs default flows through to the connectors."""
    rec = RecordingConnector()
    config = ArgusConfig(limits=LimitsConfig(max_docs=9))
    world = World(attack_store, attack_catalog, tmp_path, connectors=[rec], config=config)
    world.pipeline.investigate("Scattered Spider")
    assert rec.limits == [9]
