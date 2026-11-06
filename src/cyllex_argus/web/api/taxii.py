"""TAXII 2.1 server: expose this Argus instance as a readable/writable CTI node.

Standards tracked:
- OASIS TAXII 2.1: https://docs.oasis-open.org/cti/taxii/v2.1/os/taxii-v2.1-os.html
- OASIS STIX 2.1: served as the collection's media type.

Design scope for this release (read-only MVP):

- Discovery + API Root + one collection ("argus") covering every STIX object the local store
  can produce (entities + Relationships derived from assessments).
- Pagination via `limit` + `next` (opaque cursor; implemented as a decimal offset).
- Incremental sync via `added_after` on the manifest and objects endpoints, filtered against
  each assessment's `updated_at`.
- Auth: the server reuses the parent FastAPI's SecurityMiddleware, which accepts both
  `Authorization: Bearer <token>` (TAXII 2.1 standard) and the Argus-native `X-Argus-Token`.

Deferred to a follow-up PR: POST (add-objects) with status endpoint, multiple collections,
subscription webhooks, STIX filtering by match[type] / match[id] / match[spec_version].
"""

from __future__ import annotations

import base64
import threading
import uuid
from collections import OrderedDict
from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException, Query, Request, Response

try:
    import orjson as _json_fast  # faster path when installed; falls back to stdlib json otherwise
except ImportError:
    _json_fast = None
import json

from cyllex_argus.exporters.stix import store_wide_stix
from cyllex_argus.importers.stix import import_stix_envelope
from cyllex_argus.web.deps import open_services

router = APIRouter()

TAXII_MEDIA = "application/taxii+json;version=2.1"
STIX_MEDIA = "application/stix+json;version=2.1"
COLLECTION_ID = "argus"
DEFAULT_LIMIT = 100
MAX_LIMIT = 1000


def _json_response(payload: dict) -> Response:
    """Serialize the TAXII envelope with the standard media type the spec requires."""
    if _json_fast is not None:
        body = _json_fast.dumps(payload)
    else:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return Response(content=body, media_type=TAXII_MEDIA)


def _api_root_url(request: Request) -> str:
    base = str(request.base_url).rstrip("/")
    return f"{base}/taxii2/api1/"


def _collection_descriptor() -> dict:
    return {
        "id": COLLECTION_ID,
        "title": "Argus assessments",
        "description": (
            "Every STIX object this Argus instance's store can emit — SDOs for every entity "
            "except ATT&CK stubs, and Relationships for every assessment. Accepts POSTs of "
            "STIX envelopes which route through Argus's STIX importer."
        ),
        "can_read": True,
        "can_write": True,
        "media_types": [STIX_MEDIA],
    }


# -- Status resource cache --------------------------------------------------------------
# TAXII §4.3 requires the POST to return a status resource that the client can later GET
# via /status/{id}/ to learn how many objects succeeded, failed or are still pending. We
# process synchronously (the status is "complete" by the time we return 202), but the
# resource must stay reachable long enough for a client to poll it. An LRU of ~128
# recent status rows, keyed by uuid, keeps memory bounded. All access is thread-safe —
# uvicorn can serve POSTs concurrently with GETs for the same resource.

_STATUS_CACHE: OrderedDict[str, dict] = OrderedDict()
_STATUS_CACHE_LOCK = threading.Lock()
_STATUS_CACHE_MAX = 128


def _store_status(resource: dict) -> None:
    with _STATUS_CACHE_LOCK:
        _STATUS_CACHE[resource["id"]] = resource
        while len(_STATUS_CACHE) > _STATUS_CACHE_MAX:
            _STATUS_CACHE.popitem(last=False)


def _get_status(status_id: str) -> dict | None:
    with _STATUS_CACHE_LOCK:
        return _STATUS_CACHE.get(status_id)


def _parse_added_after(value: str | None) -> str | None:
    """TAXII expects an RFC 3339 timestamp. The store writes ISO-8601 with a 'Z' suffix for UTC;
    both parse the same way. We keep the operator's string so a sqlite TEXT comparison stays
    exact and does not round-trip through local-time surprises."""
    if value is None:
        return None
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"invalid added_after: {exc}") from exc
    return value


def _encode_cursor(stix_id: str) -> str:
    """Opaque base64url cursor over a STIX id. TAXII clients treat `next` as opaque per §5.5,
    but encoding it (instead of returning the id verbatim) makes it clear that the format can
    change in a future release without a client contract break."""
    return base64.urlsafe_b64encode(stix_id.encode("utf-8")).rstrip(b"=").decode("ascii")


def _decode_cursor(value: str | None) -> str | None:
    """Return the STIX id a client-held cursor refers to, or None for "start from the top".

    Robust to padding differences and junk input — a bad cursor logs itself as 400. We do NOT
    silently fall back on bad cursors because that masks real client bugs (a token truncated
    in a URL log, for instance).
    """
    if value is None or value == "":
        return None
    try:
        padding = "=" * (4 - len(value) % 4)
        return base64.urlsafe_b64decode(value + padding).decode("utf-8")
    except (ValueError, UnicodeDecodeError) as exc:
        raise HTTPException(status_code=400, detail=f"invalid next cursor: {exc}") from exc


@router.get("/taxii2/")
def discovery(request: Request) -> Response:
    """TAXII Discovery: a one-shot handshake that tells a client where the API Roots live."""
    api_root = _api_root_url(request)
    return _json_response({
        "title": "Cyllex Argus",
        "description": "Local-first CTI tool exposing its validated knowledge over TAXII 2.1.",
        "default": api_root,
        "api_roots": [api_root],
    })


@router.get("/taxii2/api1/")
def api_root_info() -> Response:
    """API Root metadata. One root is enough; the single Argus collection lives under it."""
    return _json_response({
        "title": "Argus API Root",
        "description": "Validated assessments from this Argus instance.",
        "versions": [TAXII_MEDIA],
        "max_content_length": 10_485_760,
    })


@router.get("/taxii2/api1/collections/")
def list_collections() -> Response:
    return _json_response({"collections": [_collection_descriptor()]})


@router.get("/taxii2/api1/collections/{collection_id}/")
def get_collection(collection_id: str) -> Response:
    if collection_id != COLLECTION_ID:
        raise HTTPException(status_code=404, detail="unknown collection")
    return _json_response(_collection_descriptor())


def _page(objects: list[dict], cursor_id: str | None, limit: int) -> tuple[list[dict], bool, str | None]:
    """Cursor-based page: start AFTER the object whose id equals `cursor_id`.

    Semantics vs the old offset form:
    - A client at page N holding cursor `C` will not see duplicate rows if an insert lands at
      position < N between page fetches: the cursor is anchored to a specific object id,
      not to a numeric index that can shift.
    - If the object `cursor_id` was deleted between fetches, we restart from the top — that's
      the correct TAXII behaviour (the client has to re-sync in that case).
    - When there is more data, `next` is the base64 of the LAST emitted id. The client echoes
      it back verbatim; the server does not require any particular encoding of the client's
      side.
    """
    start = 0
    if cursor_id:
        for i, obj in enumerate(objects):
            if obj.get("id") == cursor_id:
                start = i + 1
                break
    slice_ = objects[start:start + limit]
    end = start + len(slice_)
    more = end < len(objects)
    nxt = _encode_cursor(slice_[-1]["id"]) if more and slice_ else None
    return slice_, more, nxt


def _apply_match_filters(
    objects: list[dict],
    match_type: str | None,
    match_id: str | None,
    match_spec_version: str | None,
) -> list[dict]:
    """TAXII 2.1 §3.4.1: `match[*]` parameters each take a comma-separated list of values and
    AND together across different keys (an object must satisfy every present key). Within a
    single key the values OR together."""
    results = objects
    if match_type:
        types = {t.strip() for t in match_type.split(",") if t.strip()}
        results = [o for o in results if o.get("type") in types]
    if match_id:
        ids = {i.strip() for i in match_id.split(",") if i.strip()}
        results = [o for o in results if o.get("id") in ids]
    if match_spec_version:
        versions = {v.strip() for v in match_spec_version.split(",") if v.strip()}
        results = [o for o in results if o.get("spec_version") in versions]
    return results


@router.get("/taxii2/api1/collections/{collection_id}/objects/")
def get_objects(
    collection_id: str,
    request: Request,
    limit: int = Query(DEFAULT_LIMIT, ge=1, le=MAX_LIMIT),
    next: str | None = Query(None),
    added_after: str | None = Query(None),
    match_type: str | None = Query(None, alias="match[type]"),
    match_id: str | None = Query(None, alias="match[id]"),
    match_spec_version: str | None = Query(None, alias="match[spec_version]"),
) -> Response:
    """Serve the STIX envelope — the heart of a TAXII server. Each entity emits one SDO; each
    assessment emits one Relationship. ATT&CK entities are referenced but never re-emitted.

    OASIS §3.4 filter parameters: match[type]/match[id]/match[spec_version] take a comma list
    and narrow server-side; added_after filters by assessment updated_at.
    """
    if collection_id != COLLECTION_ID:
        raise HTTPException(status_code=404, detail="unknown collection")
    cursor_id = _decode_cursor(next)
    cutoff = _parse_added_after(added_after)
    now = datetime.now(UTC)
    with open_services(request) as services:
        objects = store_wide_stix(services.store, now, added_after_iso=cutoff)
    objects = _apply_match_filters(objects, match_type, match_id, match_spec_version)
    page, more, nxt = _page(objects, cursor_id, limit)
    return _json_response({"objects": page, "more": more, **({"next": nxt} if nxt else {})})


@router.get("/taxii2/api1/collections/{collection_id}/manifest/")
def get_manifest(
    collection_id: str,
    request: Request,
    limit: int = Query(DEFAULT_LIMIT, ge=1, le=MAX_LIMIT),
    next: str | None = Query(None),
    added_after: str | None = Query(None),
    match_type: str | None = Query(None, alias="match[type]"),
    match_id: str | None = Query(None, alias="match[id]"),
    match_spec_version: str | None = Query(None, alias="match[spec_version]"),
) -> Response:
    """Lighter payload than /objects/: id + date_added + media_type per object, useful for a
    client's incremental sync bookkeeping before it pulls the heavy objects endpoint."""
    if collection_id != COLLECTION_ID:
        raise HTTPException(status_code=404, detail="unknown collection")
    cursor_id = _decode_cursor(next)
    cutoff = _parse_added_after(added_after)
    now = datetime.now(UTC)
    with open_services(request) as services:
        objects = store_wide_stix(services.store, now, added_after_iso=cutoff)
    objects = _apply_match_filters(objects, match_type, match_id, match_spec_version)
    manifest_items = [
        {
            "id": obj["id"],
            "date_added": obj.get("x_argus_updated_at") or obj.get("created") or now.isoformat(),
            "version": obj.get("modified") or obj.get("created") or now.isoformat(),
            "media_type": STIX_MEDIA,
        }
        for obj in objects
    ]
    page, more, nxt = _page(manifest_items, cursor_id, limit)
    return _json_response({"objects": page, "more": more, **({"next": nxt} if nxt else {})})


@router.get("/taxii2/api1/collections/{collection_id}/objects/{object_id}/")
def get_object(collection_id: str, object_id: str, request: Request) -> Response:
    """Fetch one STIX object by id. Returns a one-element envelope per TAXII 2.1 §5.5."""
    if collection_id != COLLECTION_ID:
        raise HTTPException(status_code=404, detail="unknown collection")
    now = datetime.now(UTC)
    with open_services(request) as services:
        for obj in store_wide_stix(services.store, now):
            if obj.get("id") == object_id:
                return _json_response({"objects": [obj], "more": False})
    raise HTTPException(status_code=404, detail="object not found")


# -- Write path (TAXII §5.4) ------------------------------------------------------------


@router.post("/taxii2/api1/collections/{collection_id}/objects/")
async def post_objects(collection_id: str, request: Request) -> Response:
    """Accept a STIX envelope and import it. Returns 202 with a status resource.

    Content type: the TAXII spec requires `application/taxii+json;version=2.1` or
    `application/stix+json;version=2.1`; we accept either, plus the generic `application/json`
    for the convenience of a `curl -d '...'` smoke test. Clients that set a Media-Type
    outside those three get a 415.

    Processing is synchronous — by the time the 202 returns, every object has been fed to
    `import_stix_envelope`, which runs the same pipeline as `argus import-stix`
    (including the assessment recompute pass). The returned status reflects the real
    outcome rather than a 'pending' promise; the client can still poll /status/{id}/
    for a few minutes afterwards to recover the summary if needed.
    """
    if collection_id != COLLECTION_ID:
        raise HTTPException(status_code=404, detail="unknown collection")

    content_type = (request.headers.get("content-type") or "").split(";")[0].strip().lower()
    if content_type not in {
        "application/taxii+json", "application/stix+json", "application/json",
    }:
        raise HTTPException(status_code=415, detail=f"unsupported content-type: {content_type}")

    raw_body = await request.body()
    if not raw_body:
        raise HTTPException(status_code=400, detail="empty body")
    try:
        envelope = json.loads(raw_body)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail=f"invalid JSON: {exc}") from exc
    if not isinstance(envelope, dict) or not isinstance(envelope.get("objects"), list):
        raise HTTPException(status_code=400, detail="envelope must be {\"objects\": [...]}")

    objects = envelope["objects"]
    total = len(objects)
    submitted_ids = [o.get("id") for o in objects if isinstance(o, dict) and o.get("id")]

    status_id = str(uuid.uuid4())
    request_ts = datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")

    try:
        with open_services(request) as services:
            report = import_stix_envelope(services, envelope, source="<taxii post>")
    except ValueError as exc:
        resource = {
            "id": status_id,
            "status": "complete",
            "request_timestamp": request_ts,
            "total_count": total,
            "success_count": 0,
            "failure_count": total,
            "pending_count": 0,
            "successes": [],
            "failures": [{"id": sid, "message": str(exc)} for sid in submitted_ids] or [{"id": "unknown", "message": str(exc)}],
            "pendings": [],
        }
        _store_status(resource)
        return Response(
            content=_dumps(resource), media_type=TAXII_MEDIA, status_code=202,
            headers={"Location": f"{str(request.base_url).rstrip('/')}/taxii2/api1/status/{status_id}/"},
        )

    # The importer counts entity/claim additions, not per-STIX-object. For the status
    # resource we attribute "success" to every submitted id with a stix id and let the
    # importer's `skipped` list surface the rejections we recognise. Objects without an
    # id (malformed input the importer silently ignored) count as neither success nor
    # failure — TAXII leaves this to the implementation.
    skipped_set = set(report.skipped)
    successes = [{"id": sid, "version": request_ts} for sid in submitted_ids if sid not in skipped_set]
    failures = [{"id": sid, "message": "unsupported object or malformed reference"}
                for sid in submitted_ids if sid in skipped_set]

    resource = {
        "id": status_id,
        "status": "complete",
        "request_timestamp": request_ts,
        "total_count": total,
        "success_count": len(successes),
        "failure_count": len(failures),
        "pending_count": 0,
        "successes": successes,
        "failures": failures,
        "pendings": [],
        "x_argus_report": {
            "bundle_id": report.bundle_id,
            "entities_added": report.entities_added,
            "entities_matched": report.entities_matched,
            "aliases_added": report.aliases_added,
            "claims_added": report.claims_added,
            "identities_tagged": report.identities_tagged,
        },
    }
    _store_status(resource)
    return Response(
        content=_dumps(resource), media_type=TAXII_MEDIA, status_code=202,
        headers={"Location": f"{str(request.base_url).rstrip('/')}/taxii2/api1/status/{status_id}/"},
    )


@router.get("/taxii2/api1/status/{status_id}/")
def get_status(status_id: str) -> Response:
    """Return the status resource for a prior POST. 404 once the cache evicts it."""
    resource = _get_status(status_id)
    if resource is None:
        raise HTTPException(status_code=404, detail="status resource not found or expired")
    return Response(content=_dumps(resource), media_type=TAXII_MEDIA)


def _dumps(payload: dict) -> bytes:
    if _json_fast is not None:
        return _json_fast.dumps(payload)
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")
    raise HTTPException(status_code=404, detail="object not found")
