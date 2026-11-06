"""Database management: export the current argus.db, replace it with an uploaded one, or wipe it.

The import/wipe endpoints make the live SQLiteStore connection stale and the user is told to restart
Argus afterwards: a server restart is the simplest way to pick up a fresh database file on both
Windows (where an in-use handle cannot be deleted) and POSIX.

Destructive operations refuse to run when any job is active and require the client to send
``X-Argus-Confirm: yes`` in the headers, so a stray UI click cannot wipe the DB.
"""

from __future__ import annotations

import sqlite3
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse

from cyllex_argus.knowledge.sqlite_store import SQLiteStore
from cyllex_argus.web.deps import open_services
from cyllex_argus.web.jobs import TERMINAL_STATES

router = APIRouter()

# A fresh DB file is tiny; cap uploads at 500 MB which is more than enough for huge investigations.
_MAX_UPLOAD_BYTES = 500 * 1024 * 1024
# SQLite file header: "SQLite format 3\0".
_SQLITE_MAGIC = b"SQLite format 3\x00"
_CONFIRM_HEADER = "X-Argus-Confirm"
_CONFIRM_VALUE = "yes"


def _require_idle(request: Request) -> None:
    active = [job for job in request.app.state.jobs.list()
              if job["state"] not in {s.value for s in TERMINAL_STATES}]
    if active:
        raise HTTPException(
            status_code=409,
            detail=f"a job is still active ({active[0]['kind']}): wait for it or cancel before touching the database",
        )


def _require_confirm(request: Request) -> None:
    if request.headers.get(_CONFIRM_HEADER, "").lower() != _CONFIRM_VALUE:
        raise HTTPException(status_code=400, detail=f"destructive operation requires the '{_CONFIRM_HEADER}: yes' header")


@router.get("/admin/db/export")
def export_db(request: Request) -> FileResponse:
    """Download a consistent snapshot of the current argus.db. Uses SQLite's online backup API so an
    in-flight investigation does not corrupt the copy; the snapshot is written to a temp file and
    streamed to the client. The temp file is removed when the response finishes.
    """
    with open_services(request) as services:
        source = services.paths.db_file
        if not source.exists():
            raise HTTPException(status_code=404, detail="no database to export yet")
        snapshot = Path(tempfile.NamedTemporaryFile(prefix="argus-export-", suffix=".db", delete=False).name)
        src_conn = sqlite3.connect(str(source))
        try:
            dst_conn = sqlite3.connect(str(snapshot))
            try:
                src_conn.backup(dst_conn)
            finally:
                dst_conn.close()
        finally:
            src_conn.close()
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%SZ")
    filename = f"argus-{stamp}.db"
    return FileResponse(
        snapshot, media_type="application/octet-stream", filename=filename,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        background=_remove_file(snapshot),
    )


def _remove_file(path: Path):
    from starlette.background import BackgroundTask

    def cleanup() -> None:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass  # best-effort; a leftover temp file is harmless

    return BackgroundTask(cleanup)


@router.post("/admin/db/import")
async def import_db(file: UploadFile, request: Request) -> dict:
    """Replace the current argus.db with the uploaded file. The live store is closed first; the
    client must restart Argus for the new DB to be used, because the running process keeps the old
    SQLiteStore wrapper that was built against the previous file. On Windows the replace step may
    fail if any lingering handle holds the file open, in which case the user restarts and tries again.
    """
    _require_confirm(request)
    _require_idle(request)
    data = await file.read(_MAX_UPLOAD_BYTES + 1)
    if len(data) > _MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail=f"database file exceeds {_MAX_UPLOAD_BYTES // (1024 * 1024)} MB cap")
    if not data.startswith(_SQLITE_MAGIC):
        raise HTTPException(status_code=400, detail="uploaded file is not a SQLite database")

    # Write to a sibling temp file first, validate schema minimally, then replace atomically.
    with open_services(request) as services:
        target = services.paths.db_file
        tmp = target.with_suffix(".db.import.tmp")
        tmp.write_bytes(data)
        try:
            with SQLiteStore(tmp) as store:
                # Round-trip a trivial query to ensure the schema loads; SQLiteStore applies migrations
                # on open, so an unschemad import gets fixed up before replacement.
                store.connection.execute("SELECT COUNT(*) FROM entities")
        except sqlite3.DatabaseError as exc:
            tmp.unlink(missing_ok=True)
            raise HTTPException(status_code=400, detail=f"uploaded file is not a valid Argus database: {exc}") from None
        # Close the live store so Windows can replace the file.
        services.store.close()
        try:
            tmp.replace(target)
        except OSError as exc:
            tmp.unlink(missing_ok=True)
            raise HTTPException(status_code=500,
                                detail=f"could not replace the database file: {exc}. Restart Argus and try again.") from None
    return {"ok": True, "message": "Database replaced. Restart Argus to use the imported file."}


@router.delete("/admin/db")
def wipe_db(request: Request) -> dict:
    """Delete every row Argus knows about and leave an empty schema in place. The on-disk file is
    truncated through SQLiteStore's migrator so the next session opens a brand-new DB. The caller
    must confirm with the header, and no job may be running.
    """
    _require_confirm(request)
    _require_idle(request)
    with open_services(request) as services:
        services.store.close()
        target = services.paths.db_file
        try:
            target.unlink(missing_ok=True)
        except OSError as exc:
            raise HTTPException(status_code=500,
                                detail=f"could not delete the database file: {exc}. Restart Argus and try again.") from None
        # Create an empty schema so the next request opens a usable DB.
        SQLiteStore(target).close()
    return {"ok": True, "message": "Database wiped. Restart Argus to clear in-memory state."}
