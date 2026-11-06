"""Sigma detections endpoint for a threat profile.

Returns the IOC rules Argus owns plus a SigmaHQ reference per observed MITRE technique (a link to
the community's vetted rules, not an invented one), and a `.zip` of the rules for a one-click
"download all". The frontend offers the rules for download or copy and the references as links.
"""

from __future__ import annotations

import io
import re
import zipfile

from fastapi import APIRouter, HTTPException, Request, Response

from cyllex_argus.detections.sigma import generate as sigma_generate
from cyllex_argus.detections.sigma import references_markdown, sigmahq_references
from cyllex_argus.knowledge.profile import build_profile
from cyllex_argus.web.deps import open_services

router = APIRouter()


def _entity_and_profile(entity_id: str, request: Request):
    with open_services(request) as services:
        entity = services.store.get_entity(entity_id)
        if entity is None:
            raise HTTPException(status_code=404, detail="entity not found")
        return entity, build_profile(services.store, entity)


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


@router.get("/threats/{entity_id}/detections/sigma")
def sigma_for_threat(entity_id: str, request: Request):
    entity, profile = _entity_and_profile(entity_id, request)
    rules = sigma_generate(profile)
    references = sigmahq_references(profile)
    return {
        "entity": entity.canonical_name,
        "count": len(rules),
        "rules": [
            {
                "id": r.id,
                "title": r.title,
                "level": r.level,
                "tags": list(r.tags),
                "logsource": dict(r.logsource),
                "yaml": r.to_yaml(),
            }
            for r in rules
        ],
        "references": [
            {
                "technique_id": r.technique_id,
                "technique_name": r.technique_name,
                "count": r.count,
                "rules": [{"title": rr.title, "url": rr.url} for rr in r.rules],
                "browse_url": r.browse_url,
            }
            for r in references
        ],
    }


@router.get("/threats/{entity_id}/detections/sigma.zip")
def sigma_zip_for_threat(entity_id: str, request: Request):
    """Every IOC rule as its own .yml, plus SIGMAHQ-REFERENCES.md, in one zip (the 'download all')."""
    entity, profile = _entity_and_profile(entity_id, request)
    rules = sigma_generate(profile)
    references = sigmahq_references(profile)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for rule in rules:
            name = (_slug(rule.title)[:80] or rule.id)
            z.writestr(f"{name}.yml", rule.to_yaml() + "\n")
        md = references_markdown(references)
        if md:
            z.writestr("SIGMAHQ-REFERENCES.md", md)

    filename = f"{_slug(entity.canonical_name) or 'threat'}-sigma.zip"
    return Response(
        content=buf.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
