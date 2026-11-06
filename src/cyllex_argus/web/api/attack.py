"""The full Enterprise ATT&CK structure, for the matrix view that highlights what a threat was observed to use."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

from cyllex_argus.knowledge.attack_matrix import TACTICS
from cyllex_argus.web.deps import open_services

router = APIRouter()
_CACHE = {"Cache-Control": "public, max-age=600"}
_TACTIC_NAMES = {tid: name for tid, name in TACTICS}


@router.get("/attack/catalog")
def attack_catalog(request: Request) -> JSONResponse:
    with open_services(request) as services:
        catalog = services.attack_catalog()
        if catalog is None:
            return JSONResponse({"error": "ATT&CK data not loaded"}, status_code=404)
        columns: dict[str, list[dict]] = {tactic_id: [] for tactic_id, _ in TACTICS}
        for tech in sorted(catalog.active_techniques(), key=lambda t: t.technique_id):
            entry = {"id": tech.stix_id, "external_id": tech.technique_id, "name": tech.name, "tactics": tech.tactics}
            for tactic_id in tech.tactics:
                if tactic_id in columns:
                    columns[tactic_id].append(entry)
    body = {"tactics": [{"id": tid, "name": name, "techniques": columns[tid]} for tid, name in TACTICS]}
    return JSONResponse(body, headers=_CACHE)


@router.get("/attack/technique/{external_id}")
def technique_detail(external_id: str, request: Request) -> JSONResponse:
    """Full MITRE metadata for one technique: description, platforms, detection, data sources, etc.

    The matrix only carries the fields it needs to render a cell. The Technique modal calls this
    endpoint to show the long description, which platforms the technique applies to, what logs or
    telemetry detect it, and the permissions it requires. Everything is already in the loaded ATT&CK
    bundle; no network request is made here.
    """
    with open_services(request) as services:
        catalog = services.attack_catalog()
        if catalog is None:
            raise HTTPException(status_code=404, detail="ATT&CK data not loaded")
        tech = catalog.resolve_technique(external_id)
        if tech is None:
            raise HTTPException(status_code=404, detail=f"unknown technique: {external_id}")
    return JSONResponse({
        "external_id": tech.technique_id, "name": tech.name,
        "tactics": [{"id": t, "name": _TACTIC_NAMES.get(t, t)} for t in tech.tactics],
        "is_subtechnique": tech.is_subtechnique,
        "description": tech.description,
        "platforms": tech.platforms,
        "detection": tech.detection,
        "data_sources": tech.data_sources,
        "permissions_required": tech.permissions_required,
    }, headers=_CACHE)
