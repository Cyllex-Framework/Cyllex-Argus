"""STIX 2.1 bundle ingest over HTTP."""

from __future__ import annotations

import tempfile
from pathlib import Path

from fastapi import APIRouter, File, HTTPException, Request, UploadFile

from cyllex_argus.importers import import_stix_bundle
from cyllex_argus.web.deps import open_services

router = APIRouter()
MAX_BUNDLE_BYTES = 50_000_000


@router.post("/import/stix")
async def post_stix_import(request: Request, bundle: UploadFile = File(...)) -> dict:
    """Upload a STIX 2.1 bundle (JSON) and merge it into the store.

    The uploaded file is written to a short-lived temp path (never under the store's raw/ dir)
    so the importer's existing document-anchoring semantics work without a special in-memory
    code path. On success the ImportReport is returned verbatim.
    """
    raw = await bundle.read()
    if len(raw) > MAX_BUNDLE_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"bundle larger than {MAX_BUNDLE_BYTES // 1_000_000} MB; split it first",
        )
    if not raw:
        raise HTTPException(status_code=400, detail="empty bundle")
    with tempfile.NamedTemporaryFile(
        prefix="argus-stix-", suffix=".json", delete=False,
    ) as tmp:
        tmp.write(raw)
        path = Path(tmp.name)
    try:
        with open_services(request) as services:
            try:
                report = import_stix_bundle(services, path)
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
    finally:
        path.unlink(missing_ok=True)
    return {
        "bundle_id": report.bundle_id,
        "entities_added": report.entities_added,
        "entities_matched": report.entities_matched,
        "aliases_added": report.aliases_added,
        "claims_added": report.claims_added,
        "identities_tagged": report.identities_tagged,
        "skipped": report.skipped,
    }
