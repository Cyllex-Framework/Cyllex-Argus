"""FastAPI application factory for the local Cyllex Argus web interface."""

from __future__ import annotations

import logging
import shutil
from collections.abc import Callable
from pathlib import Path

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from starlette.exceptions import HTTPException as StarletteHTTPException

from cyllex_argus.attack.catalog import catalog_looks_complete
from cyllex_argus.knowledge.models import InvestigationState
from cyllex_argus.pipeline.scheduler import SchedulerThread
from cyllex_argus.services import Services
from cyllex_argus.web import auth_core
from cyllex_argus.web.api import (
    admin_db,
    assessments,
    attack,
    auth,
    clock,
    detections,
    documents,
    enrichers,
    entities,
    health,
    investigations,
    live_tree,
    logs,
    overview,
    session,
    settings,
    sources,
    stix,
    taxii,
    threats,
    trace,
    users,
    watchers,
)
from cyllex_argus.web.api import jobs as jobs_api
from cyllex_argus.web.auth_seed import ensure_admin_seeded
from cyllex_argus.web.authz import enforce
from cyllex_argus.web.job_handlers import build_handlers
from cyllex_argus.web.jobs import JobManager
from cyllex_argus.web.security import SecurityMiddleware

DEFAULT_STATIC_DIR = Path(__file__).parent / "static"
_API_METHODS = ["GET", "HEAD", "POST", "PUT", "DELETE", "PATCH"]  # HEAD too: the SPA route answers it, and must not swallow /api
# Windows can map these to text/plain through the registry; module scripts then fail under nosniff.
_MEDIA_TYPES = {
    ".js": "text/javascript",
    ".mjs": "text/javascript",
    ".css": "text/css",
    ".html": "text/html",
    ".svg": "image/svg+xml",
    ".json": "application/json",
    ".map": "application/json",
    ".woff2": "font/woff2",
    ".woff": "font/woff",
    ".png": "image/png",
    ".ico": "image/x-icon",
}
_PLACEHOLDER = (
    "<!doctype html><html lang='en'><head><meta charset='utf-8'><title>Cyllex Argus</title></head>"
    "<body><p>Frontend not built. Run <code>npm run build</code> in <code>web/</code>.</p></body></html>"
)


def _default_claude_check(services_factory: Callable[[], Services]) -> Callable[[], bool]:
    def check() -> bool:
        services = services_factory()
        try:
            return shutil.which(services.config.llm.claude_binary) is not None
        finally:
            services.close()
    return check


def _llm_snapshot(services_factory: Callable[[], Services]) -> dict | None:
    """The LLM config this process starts with; /api/settings compares argus.toml against it (restart_required)."""
    try:
        services = services_factory()
    except Exception:  # an unreadable argus.toml surfaces on the first request, as before
        return None
    try:
        return services.config.llm.model_dump(mode="json")
    finally:
        services.close()


def create_app(
    services_factory: Callable[[], Services],
    *,
    token: str,
    port: int,
    static_dir: Path | None = None,
    jobs=None,
    claude_available: Callable[[], bool] | None = None,
    extra_hosts: list[str] | None = None,
    http_transport: httpx.BaseTransport | None = None,
    token_max_age_seconds: int | None = None,
    now: Callable[[], float] | None = None,
    auto_update_attack: bool = True,
) -> FastAPI:
    if not token:
        raise ValueError("token must not be empty")
    app = FastAPI(title="Cyllex Argus", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.services_factory = services_factory
    app.state.token = token
    app.state.login_throttle = auth.LoginThrottle()
    app.state.port = port
    app.state.jobs = jobs if jobs is not None else JobManager(build_handlers(services_factory))
    # Orphan recovery: the JobManager lives in RAM, so an `argus serve` that died mid-run
    # leaves investigations marked RUNNING with no worker. Without this the UI shows "RUNNING
    # 23m 1s" forever while nothing advances — a UI lie the operator cannot escape. On every
    # startup, flip RUNNING → PAUSED so the Resume button (or `argus resume <id>`) is the
    # correct next action. Tests supply their own JobManager and may want to seed state, so
    # recovery only runs with the real path.
    if jobs is None:
        _recover_orphan_investigations(services_factory)
        if auto_update_attack:
            _ensure_attack_catalog_loaded(services_factory, app.state.jobs)
    # Scheduler thread for recurring investigations. Only when the host provided the real
    # JobManager (not a test-supplied one): tests exercise the ticker in isolation.
    if jobs is None:
        scheduler = SchedulerThread(services_factory, app.state.jobs)
        scheduler.start()
        app.state.scheduler = scheduler
    else:
        app.state.scheduler = None
    app.state.claude_available = claude_available or _default_claude_check(services_factory)
    app.state.http_transport = http_transport  # lets tests stand in for the Ollama server
    app.state.llm_config_snapshot = _llm_snapshot(services_factory)
    # Expose the config so /api/auth/login can read `[auth]` without reopening a Services every call.
    try:
        _s = services_factory()
        try:
            app.state.config = _s.config
            # Seed the admin user on first boot and keep ARGUS_ADMIN_PASSWORD authoritative.
            ensure_admin_seeded(_s.store, _s.config)
        finally:
            _s.close()
    except Exception:
        app.state.config = None  # the auth endpoint falls back to "login not configured" (503)

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        return JSONResponse({"error": str(exc.detail)}, status_code=exc.status_code)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        first = exc.errors()[0] if exc.errors() else {}
        where = ".".join(str(part) for part in first.get("loc", ()) if part != "body")
        return JSONResponse({"error": f"invalid request: {where} {first.get('msg', '')}".strip()}, status_code=400)

    for module in (session, overview, attack, threats, documents, investigations, live_tree, sources, settings, trace, logs, jobs_api, admin_db, enrichers, entities, stix, assessments, detections, health, clock, auth, users, watchers):
        app.include_router(module.router, prefix="/api", dependencies=[Depends(enforce)])
    # TAXII 2.1 routes publish their own path prefix (/taxii2/...) per the spec; no /api prefix.
    app.include_router(taxii.router)

    @app.api_route("/api", methods=_API_METHODS)
    @app.api_route("/api/{rest:path}", methods=_API_METHODS)
    def unknown_api() -> Response:
        raise HTTPException(status_code=404, detail="not found")

    _mount_spa(app, (static_dir or DEFAULT_STATIC_DIR).resolve())
    def _session_resolver(presented: str):
        # Resolve an /api token to a live session user. Opens a short-lived Services, matching the
        # per-request connection model the handlers already use.
        services = services_factory()
        try:
            return services.store.session_user(auth_core.token_hash(presented))
        finally:
            services.close()

    middleware_kwargs: dict = {
        "token": token, "port": port, "extra_hosts": extra_hosts,
        "session_resolver": _session_resolver,
    }
    if token_max_age_seconds is not None:
        middleware_kwargs["token_max_age_seconds"] = token_max_age_seconds
    if now is not None:
        middleware_kwargs["now"] = now
    app.add_middleware(SecurityMiddleware, **middleware_kwargs)
    return app


def _mount_spa(app: FastAPI, static_dir: Path) -> None:
    index = static_dir / "index.html"

    # The index names the current build's hashed assets, so it must be revalidated on every load: a cached copy
    # would keep pointing at assets a rebuild has deleted.
    revalidate = {"Cache-Control": "no-cache"}

    @app.api_route("/{path:path}", methods=["GET", "HEAD"], include_in_schema=False)
    def spa(path: str) -> Response:
        if not index.is_file():
            return HTMLResponse(_PLACEHOLDER, headers=revalidate)
        # Serve only exact matches from a listing of the build. A request-derived path must never reach the
        # filesystem: on Windows `static_dir / "//host/share"` is a UNC path, and stat-ing it leaks NTLM credentials.
        candidate = _static_files(static_dir).get(path)
        if candidate is not None:
            return FileResponse(
                candidate,
                media_type=_MEDIA_TYPES.get(candidate.suffix.lower()),  # None: Starlette guesses
                headers=revalidate if candidate == index else None,
            )
        if path.startswith("assets/"):
            raise HTTPException(status_code=404, detail="not found")
        return FileResponse(index, media_type=_MEDIA_TYPES[".html"], headers=revalidate)


def _static_files(static_dir: Path) -> dict[str, Path]:
    """Map each built file's POSIX path, relative to `static_dir`, to the file. The build is a handful of files."""
    return {file.relative_to(static_dir).as_posix(): file for file in static_dir.rglob("*") if file.is_file()}


_log = logging.getLogger(__name__)


# Threshold below which the ATT&CK store is considered unloaded. The current MITRE Enterprise
# catalog ships ~176 active intrusion-sets; anything under 30 is either a fresh install that
# never ran `argus attack update`, or a crash during a prior load that only persisted part of
# the catalog. Either way, re-running the loader against a fresh download is the safe answer.


def _ensure_attack_catalog_loaded(services_factory: Callable[[], Services], jobs) -> None:
    """Submit an `attack_update` job on serve-startup if the ATT&CK catalog has not been
    loaded into the store. Without a loaded catalog, every Analyst extraction creates a
    document-origin entity for every group it sees (one "Midnight Blizzard" per paper), the
    aliases table never ties "APT29" to "Nobelium" to "Midnight Blizzard", and the generator
    sees fractured facts. The command exists (`argus attack update`), but a first-time
    operator does not know to run it; booting without a loaded catalog is the single most
    common source of "Argus is returning garbage" reports in practice. Hooking it to serve
    startup makes "fresh install → investigate" produce coherent output without a manual
    prerequisite step.

    This submits the job (does not block startup); the job runs in the background and the
    serve process stays available on port 8765 throughout. Any failure here must not block
    startup — a user can always run `argus attack update` by hand, so printing a visible
    warning and continuing is the right failure mode.
    """
    try:
        services = services_factory()
    except Exception as exc:  # noqa: BLE001
        _log.warning("attack-catalog check skipped: cannot open services: %s", exc)
        return
    try:
        loaded = catalog_looks_complete(services.store.connection)
    except Exception as exc:  # noqa: BLE001
        _log.warning("attack-catalog check failed: %s", exc)
        return
    finally:
        services.close()

    if loaded:
        return  # catalog is already loaded; nothing to do

    try:
        job = jobs.submit("attack_update", {}, dedupe_key=())
    except Exception as exc:  # noqa: BLE001 — the job system refusing is not a startup blocker
        print(f"[argus] ATT&CK catalog not loaded. "
              f"Run `argus attack update` to download it. (auto-submit failed: {exc})", flush=True)
        return
    print(f"[argus] ATT&CK catalog not loaded — auto-submitted "
          f"download job {job['id']}. Investigations started before it finishes may extract "
          f"fewer techniques; the first run after it completes will be fully grounded in MITRE.",
          flush=True)


def _recover_orphan_investigations(services_factory: Callable[[], Services]) -> int:
    """Flip RUNNING investigations to PAUSED on startup. The old process is gone and its
    in-memory JobManager with it, so no worker is actually advancing these rows. Without this
    the UI shows "RUNNING 23m" forever and the operator has to figure out they need
    `argus resume <id>` on their own.

    Returns the count of recovered rows; prints a one-line banner so the operator sees it in
    the serve log without needing debug logging on.
    """
    try:
        services = services_factory()
    except Exception as exc:  # noqa: BLE001 — a missing / corrupt DB must not block startup
        _log.warning("orphan-recovery skipped: cannot open services: %s", exc)
        return 0
    try:
        rows = services.store.connection.execute(
            "SELECT id, target FROM investigations WHERE state = ?",
            (InvestigationState.RUNNING.value,),
        ).fetchall()
        for row in rows:
            services.store.set_investigation_state(
                row["id"], InvestigationState.PAUSED,
                reason="Server restart interrupted this run.",
            )
        if rows:
            targets = ", ".join(f"#{r['id']} '{r['target']}'" for r in rows)
            print(f"[argus] orphan recovery: paused {len(rows)} RUNNING investigation(s) "
                  f"from the previous process ({targets}). Use the Resume button or "
                  f"`argus resume <id>` to continue.", flush=True)
        return len(rows)
    except Exception as exc:  # noqa: BLE001
        _log.warning("orphan-recovery failed: %s", exc)
        return 0
    finally:
        services.close()
