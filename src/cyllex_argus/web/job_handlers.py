"""Job kinds the web UI can run. Each job opens its own Services (its own SQLite connection)."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from cyllex_argus.attack.catalog import AttackCatalog, download_attack, load_catalog_into_store
from cyllex_argus.knowledge.models import InvestigationState
from cyllex_argus.pipeline.investigation import InvestigationReport
from cyllex_argus.services import MissingAttackData, Services
from cyllex_argus.web.jobs import Handler

_CLI_RESUME_HINT = "Re-run the same command to resume."
_WEB_RESUME_HINT = "Use Resume to continue."


def _finish_watch(services: Services, report: InvestigationReport, watcher_id: Any = None) -> None:
    """After a run, record which watcher fired it (attribution) and reconcile the watcher's
    change feed. Reconcile gates on a committed FINISHED state internally, so a paused/failed
    run only records attribution. Keyed by target, so a hand-run of a watched target counts too."""
    from cyllex_argus.watchers.runner import dispatch_pending, reconcile_report
    if watcher_id is not None:
        services.store.set_investigation_watcher(report.investigation_id, int(watcher_id))
    reconcile_report(services.store, services.config, report)
    # Dispatch on every finished run, not only when this run produced changes, so an undelivered
    # backlog (a change that failed to send earlier) is retried rather than stranded until the
    # next run that happens to emit something.
    dispatcher = services.webhook_dispatcher()
    if dispatcher is not None:
        dispatch_pending(services.store, dispatcher)


def _report(report: InvestigationReport) -> dict[str, Any]:
    message = report.message
    if report.state is InvestigationState.PAUSED and message:
        message = message.replace(_CLI_RESUME_HINT, _WEB_RESUME_HINT)  # the web UI has a Resume button, not a command
    return {
        "state": report.state.value, "investigation_id": report.investigation_id, "target": report.target,
        "stage_counts": dict(report.stage_counts), "claims_accepted": report.claims_accepted,
        "claims_rejected": report.claims_rejected, "message": message,
    }


def build_handlers(services_factory: Callable[[], Services]) -> dict[str, Handler]:
    def run(log: Callable[[str], None], action: Callable[[Services], dict[str, Any]]) -> dict[str, Any]:
        # Opened and closed here, on the thread that runs the job: SQLite connections never cross threads.
        services = services_factory()
        services.log = log
        try:
            return action(services)
        finally:
            services.close()

    def investigate(params: dict[str, Any], log: Callable[[str], None]) -> dict[str, Any]:
        target = str(params.get("target") or "").strip()
        if not target:
            raise ValueError("target is required")
        max_docs = params.get("max_docs")
        concurrency = int(params.get("concurrency") or 1)
        log(f"Investigating {target}" + (f" (parallel={concurrency})" if concurrency > 1 else ""))
        user_id = params.get("user_id")
        watcher_id = params.get("watcher_id")

        prefer_recent = watcher_id is not None  # scheduled watcher runs hunt for new material

        def action(s: Services) -> dict[str, Any]:
            report = s.pipeline().investigate(
                target, max_docs, concurrency=concurrency, created_by=user_id, prefer_recent=prefer_recent,
            )
            _finish_watch(s, report, watcher_id)
            return _report(report)
        return run(log, action)

    def resume(params: dict[str, Any], log: Callable[[str], None]) -> dict[str, Any]:
        investigation_id = int(params["investigation_id"])
        concurrency = int(params.get("concurrency") or 1)
        log(f"Resuming investigation #{investigation_id}"
            + (f" (parallel={concurrency})" if concurrency > 1 else ""))
        watcher_id = params.get("watcher_id")

        def action(s: Services) -> dict[str, Any]:
            report = s.pipeline().resume(investigation_id, concurrency=concurrency)
            _finish_watch(s, report, watcher_id)
            return _report(report)
        return run(log, action)

    def ingest(params: dict[str, Any], log: Callable[[str], None]) -> dict[str, Any]:
        files = [Path(f) for f in params.get("files") or []]
        if not files:
            raise ValueError("no files to ingest")
        target = params.get("target") or None
        log(f"Ingesting {len(files)} file(s)")
        user_id = params.get("user_id")

        def action(s: Services) -> dict[str, Any]:
            report = s.pipeline().ingest(files, target, created_by=user_id)
            _finish_watch(s, report)
            return _report(report)
        return run(log, action)

    def attack_update(params: dict[str, Any], log: Callable[[str], None]) -> dict[str, Any]:
        def action(services: Services) -> dict[str, Any]:
            log("Downloading MITRE ATT&CK Enterprise")
            download_attack(services.paths.attack_file, services.http)
            catalog = AttackCatalog.from_file(services.paths.attack_file)
            created = load_catalog_into_store(catalog, services.store)
            message = (
                f"ATT&CK loaded: {len(catalog.active_techniques())} techniques, {len(catalog.groups)} groups, "
                f"{len(catalog.software)} software ({created} new entities)."
            )
            log(message)
            return {"state": "finished", "message": message}
        return run(log, action)

    def recompute(params: dict[str, Any], log: Callable[[str], None]) -> dict[str, Any]:
        def action(services: Services) -> dict[str, Any]:
            try:
                validator = services.validator()
            except MissingAttackData as exc:
                message = f"Confidences were not recomputed: ATT&CK data is missing ({exc})."
                log(message)
                return {"state": "finished", "recomputed": False, "message": message}
            keys = services.store.assessment_keys()
            log(f"Recomputing {len(keys)} assessment(s)")
            validator.recompute(keys)
            message = f"Recomputed {len(keys)} assessment(s)."
            log(message)
            return {"state": "finished", "recomputed": True, "message": message}
        return run(log, action)

    def retry_document(params: dict[str, Any], log: Callable[[str], None]) -> dict[str, Any]:
        """Retry a single failed document — the common 'LLM rate-limited us' or 'URL was 403
        at the time' recovery flow. Routes through `pipeline.retry_document`, which handles
        both re-fetching the URL and re-processing a cached body transparently.

        `as_browser` (optional) switches the fetcher's User-Agent to a mainstream Chrome
        fingerprint for THIS retry only. Scheduled runs keep the Argus UA so they stay
        identifiable in publisher logs; the browser UA is only for one-off recoveries where
        the publisher's WAF rejects anything non-browser-shaped (CISA, Trellix, …).
        """
        from cyllex_argus.documents.fetch import BROWSER_USER_AGENT
        document_id = int(params["document_id"])
        as_browser = bool(params.get("as_browser"))
        user_agent = BROWSER_USER_AGENT if as_browser else None
        log(f"Retrying document #{document_id}" + (" (as browser)" if as_browser else ""))

        def action(services: Services) -> dict[str, Any]:
            result = services.pipeline().retry_document(document_id, user_agent=user_agent)
            log(result.get("message") or f"Retry finished, final stage: {result.get('stage')}")
            return {"state": "finished", "document_id": document_id, **result}
        return run(log, action)

    def supply_document(params: dict[str, Any], log: Callable[[str], None]) -> dict[str, Any]:
        """Process a file the operator supplied for a document the collector could not fetch.

        The upload is already on disk (the endpoint streams it there under a size limit, as
        `/api/ingest` does) and the path travels in the job params, because job params have to
        be JSON. The file is removed whatever happens: it has been copied into the raw store by
        then, and leaving operator uploads lying around is how a disk fills up quietly.
        """
        import pathlib as _pathlib
        document_id = int(params["document_id"])
        upload = _pathlib.Path(str(params["path"]))
        filename = str(params.get("filename") or upload.name)
        log(f"Supplying document #{document_id} from {filename}")

        def action(services: Services) -> dict[str, Any]:
            try:
                content = upload.read_bytes()
                result = services.pipeline().supply_document(document_id, content, filename)
            finally:
                upload.unlink(missing_ok=True)
            log(result.get("message") or f"Finished, final stage: {result.get('stage')}")
            return {"state": "finished", "document_id": document_id, **result}
        return run(log, action)


    return {
        "investigate": investigate, "resume": resume, "ingest": ingest, "attack_update": attack_update,
        "recompute": recompute,
        "retry_document": retry_document, "supply_document": supply_document,
    }
