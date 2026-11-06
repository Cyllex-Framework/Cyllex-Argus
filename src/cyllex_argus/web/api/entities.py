"""Entity-level HTTP API: identity attributes, sector/country queries, and admin merge."""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from cyllex_argus.web.deps import open_services

router = APIRouter()

STIX_TYPES = Literal[
    "intrusion-set", "campaign", "malware", "tool", "attack-pattern",
    "indicator", "vulnerability", "identity", "location",
]


class AttributesUpdate(BaseModel):
    """Open-form attributes merged into the entity's attributes_json.

    None or empty-string values are dropped from the stored dict. Pass only the keys you want
    to change; keys you omit are left alone.
    """
    sector: str | None = Field(default=None, max_length=120)
    country: str | None = Field(default=None, max_length=10)


class MergeBody(BaseModel):
    source: str = Field(..., min_length=1, description="Entity id or alias (merged FROM, deleted).")
    target: str = Field(..., min_length=1, description="Entity id or alias (merged INTO, survives).")


# The retype whitelist mirrors `SQLiteStore._RETYPEABLE`; attack-pattern is excluded on
# purpose (its external_id carries MITRE semantics that would be nonsense on another type).
RETYPEABLE = Literal[
    "intrusion-set", "campaign", "malware", "tool",
    "identity", "location", "indicator", "vulnerability",
]


class RetypeBody(BaseModel):
    to: RETYPEABLE = Field(..., description="New STIX type.")


class RetypeBatchItem(BaseModel):
    entity_id: str = Field(..., min_length=1)
    to: RETYPEABLE


class RetypeBatchBody(BaseModel):
    items: list[RetypeBatchItem] = Field(..., min_length=1, max_length=100)


class SectorMigrationBody(BaseModel):
    """Append this sector-identity's name to each actor's `attributes.sectors` and then
    delete the identity. actor_ids defaults to EVERY actor currently claiming to target
    this identity — the common case; the UI pre-fills it from `actors_targeting_identity`."""
    actor_ids: list[str] = Field(default_factory=list, max_length=100)
    delete: bool = Field(True, description="Delete the identity after tagging; set false to keep it.")


class SectorMigrationBatchBody(BaseModel):
    """Migrate up to 50 sector-named identity entities in one call. Each identity is
    processed with the single-item defaults (actor_ids auto-resolved, delete=true)."""
    identity_ids: list[str] = Field(..., min_length=1, max_length=50)


def _bad(detail: str) -> HTTPException:
    return HTTPException(status_code=400, detail=detail)


@router.get("/entities/{identity_id}/actors-targeting")
def actors_targeting_identity(identity_id: str, request: Request) -> dict:
    """List actor-shaped entities (intrusion-set / campaign / malware / tool) with a
    `targets` assessment pointing at this identity. Used by the sector-migration UI to
    pre-fill the "which actors should inherit this sector tag?" picker."""
    with open_services(request) as services:
        if services.store.get_entity(identity_id) is None:
            raise HTTPException(status_code=404, detail=f"unknown entity: {identity_id}")
        actors = services.store.actors_targeting_identity(identity_id)
    return {
        "actors": [
            {"id": a.id, "stix_type": a.stix_type, "canonical_name": a.canonical_name}
            for a in actors
        ],
    }


@router.post("/entities/migrate-sectors-batch")
def migrate_sectors_batch(body: SectorMigrationBatchBody, request: Request) -> dict:
    """Bulk variant of /entities/{id}/migrate-to-sector-tag. Each identity runs with the
    one-shot defaults: actor_ids auto-resolved via actors_targeting_identity, delete=true.

    Response:
    ```
    {
      "ok": [{identity_id, canonical_name, tagged_actors[], removed_claims}, ...],
      "failed": [{identity_id, reason}, ...]
    }
    ```

    Partial failure is normal — an identity that was already deleted between the operator's
    "see 12 sector-tags" and "fix them all" clicks shows up in `failed` with a 'unknown entity'
    reason while the rest succeed.
    """
    ok: list[dict] = []
    failed: list[dict] = []
    with open_services(request) as services:
        for identity_id in body.identity_ids:
            try:
                identity = services.store.get_entity(identity_id)
                if identity is None:
                    failed.append({"identity_id": identity_id, "reason": "unknown entity"})
                    continue
                actor_ids = [a.id for a in services.store.actors_targeting_identity(identity_id)]
                tagged: list[dict] = []
                for actor_id in actor_ids:
                    actor = services.store.get_entity(actor_id)
                    if actor is None:
                        continue
                    updated = services.store.append_entity_sector(actor_id, identity.canonical_name)
                    tagged.append({
                        "id": updated.id, "canonical_name": updated.canonical_name,
                        "sectors": updated.attributes.get("sectors", []),
                    })
                removed_claims = services.store.delete_entity_cascading(identity_id)
                ok.append({
                    "identity_id": identity_id, "canonical_name": identity.canonical_name,
                    "tagged_actors": tagged, "removed_claims": removed_claims,
                })
            except (KeyError, ValueError) as exc:
                failed.append({"identity_id": identity_id, "reason": str(exc) or "unknown entity"})
    return {"ok": ok, "failed": failed, "total": len(body.identity_ids)}


@router.post("/entities/{identity_id}/migrate-to-sector-tag")
def migrate_sector_identity_to_tag(
    identity_id: str, body: SectorMigrationBody, request: Request,
) -> dict:
    """Convert a sector-named identity entity into a `sectors` tag on its targeting actors.

    The common 0.11-era data shape has the Analyst extract "actor targets identity:healthcare"
    as a first-class SDO. The STIX 2.1-correct shape is `threat-actor.sectors[]`. This
    endpoint migrates one entity's shape to the other:

    1. Reads the identity's canonical_name.
    2. Appends the lowercase name to each `actor_ids`' `attributes.sectors` list.
       If `actor_ids` is empty the endpoint defaults to every actor currently claiming
       to target this identity (that is almost always what the operator wants).
    3. If `delete` is true (the default) the identity entity, its claims, assessments,
       and aliases are cascaded away. Setting `delete=false` is for dry-runs or when the
       operator wants to keep the identity (e.g. the name DOES describe a real org too).

    Returns the actors tagged and the number of claims removed. Partial results are not
    possible — the whole operation is one transaction via the two store methods.
    """
    with open_services(request) as services:
        identity = services.store.get_entity(identity_id)
        if identity is None:
            raise HTTPException(status_code=404, detail=f"unknown entity: {identity_id}")

        actor_ids = body.actor_ids
        if not actor_ids:
            actor_ids = [a.id for a in services.store.actors_targeting_identity(identity_id)]

        tagged: list[dict] = []
        for actor_id in actor_ids:
            actor = services.store.get_entity(actor_id)
            if actor is None:
                continue
            updated = services.store.append_entity_sector(actor_id, identity.canonical_name)
            tagged.append({
                "id": updated.id, "canonical_name": updated.canonical_name,
                "sectors": updated.attributes.get("sectors", []),
            })

        removed_claims = 0
        if body.delete:
            removed_claims = services.store.delete_entity_cascading(identity_id)

    return {
        "identity_canonical_name": identity.canonical_name,
        "tagged_actors": tagged,
        "deleted": body.delete,
        "removed_claims": removed_claims,
    }


@router.post("/entities/retype-batch")
def retype_batch(body: RetypeBatchBody, request: Request) -> dict:
    """Retype up to 100 entities in one call. Each item is processed independently;
    the response reports per-item success / failure with the same shape the single-item
    endpoint returns. Partial failure is normal — a batch of 50 mistyped identities may
    include a handful of ATT&CK-origin entities the Validator rejects.

    Response:
    ```
    {
      "ok": [{entity_id, new_id, stix_type, canonical_name}, ...],
      "failed": [{entity_id, reason}, ...]
    }
    ```
    """
    ok: list[dict] = []
    failed: list[dict] = []
    with open_services(request) as services:
        for item in body.items:
            try:
                existing = services.store.get_entity(item.entity_id)
                if existing is None:
                    failed.append({"entity_id": item.entity_id, "reason": "unknown entity"})
                    continue
                updated = services.store.retype_entity(item.entity_id, item.to)
                ok.append({
                    "entity_id": item.entity_id, "new_id": updated.id,
                    "stix_type": updated.stix_type, "canonical_name": updated.canonical_name,
                })
            except ValueError as exc:
                failed.append({"entity_id": item.entity_id, "reason": str(exc)})
    return {"ok": ok, "failed": failed, "total": len(body.items)}


@router.put("/entities/{entity_id}/retype")
def retype_entity(entity_id: str, body: RetypeBody, request: Request) -> dict:
    """Change an entity's STIX type in place. The response carries the NEW id (the UUID is
    preserved, only the type prefix changes). 400 on identical type or ATT&CK-origin entity.
    """
    with open_services(request) as services:
        entity = services.store.get_entity(entity_id)
        if entity is None:
            raise HTTPException(status_code=404, detail=f"unknown entity: {entity_id}")
        try:
            updated = services.store.retype_entity(entity_id, body.to)
        except ValueError as exc:
            raise _bad(str(exc)) from exc
    return {
        "id": updated.id,
        "stix_type": updated.stix_type,
        "canonical_name": updated.canonical_name,
        "previous_id": entity_id,
    }


@router.put("/entities/{entity_id}/attributes")
def update_attributes(entity_id: str, body: AttributesUpdate, request: Request) -> dict:
    """Set `sector` and/or `country` on an entity (identity entities use this surface)."""
    with open_services(request) as services:
        entity = services.store.get_entity(entity_id)
        if entity is None:
            raise HTTPException(status_code=404, detail=f"unknown entity: {entity_id}")
        updated = services.store.set_entity_attributes(
            entity_id,
            sector=body.sector,
            country=body.country,
        )
    return {"id": updated.id, "attributes": updated.attributes}


@router.get("/query/targets")
def query_targets(request: Request, sector: str = "", country: str = "") -> dict:
    """List actors associated with the given sector/country.

    Two paths are merged into one ranked response:

    - **Direct attribution** (0.13+): actors whose own `attributes.sectors[]` list contains
      the sector string. These show as `source: "sectors"` with `assessment_count: 0` (the
      attribution is on the actor, not from a counted assessment chain).
    - **Identity targeting** (0.11-): actors with `targets` claims against identity entities
      whose `attributes.sector == <sector>` and/or `attributes.country == <country>`. These
      show as `source: "targets-identity"` with the assessment count.

    A single actor present on both paths is deduped; the direct attribution wins and the
    assessment count is kept so the operator sees the full picture.

    `?country=` only applies to the identity path — actors do not carry a country attribute
    (that lives on the identity SDO). `?sector=` applies to both paths.

    At least one of `sector` / `country` must be given; otherwise the response is 400 to
    prevent accidental "all actors" scans.
    """
    sector_q = sector.strip()
    country_q = country.strip()
    if not sector_q and not country_q:
        raise _bad("pass at least one of ?sector= or ?country=")
    with open_services(request) as services:
        identities = services.store.identities_matching(
            sector=sector_q or None, country=country_q or None,
        )
        ranked = services.store.actors_targeting(
            sector=sector_q or None, country=country_q or None,
        )
        direct = services.store.actors_by_sector_attribute(sector_q) if sector_q else []

    results: dict[str, dict] = {}
    for actor in direct:
        results[actor.id] = {
            "entity_id": actor.id, "canonical_name": actor.canonical_name,
            "stix_type": actor.stix_type, "assessment_count": 0,
            "source": "sectors",
        }
    for actor, n in ranked:
        if actor.id in results:
            results[actor.id]["assessment_count"] = n
        else:
            results[actor.id] = {
                "entity_id": actor.id, "canonical_name": actor.canonical_name,
                "stix_type": actor.stix_type, "assessment_count": n,
                "source": "targets-identity",
            }

    # Rank: direct attributions first (they are explicit on-the-actor evidence),
    # then by assessment count desc, then alphabetical.
    sorted_actors = sorted(
        results.values(),
        key=lambda a: (0 if a["source"] == "sectors" else 1, -a["assessment_count"],
                       a["canonical_name"].lower()),
    )
    return {
        "matched_identities": len(identities),
        "matched_by_sectors_attribute": len(direct),
        "actors": sorted_actors,
    }


@router.post("/entities/merge")
def merge_entities(body: MergeBody, request: Request) -> dict:
    """Fuse the SOURCE entity into the TARGET entity (same STIX type), deleting the source.

    Accepts entity ids OR aliases on either side. Refuses self-merge, cross-type merge, and
    unknown ids. On success the Validator recomputes affected assessments and the response
    returns how many were touched.
    """
    with open_services(request) as services:
        src = services.store.get_entity(body.source) or services.store.find_by_alias(body.source)
        if src is None:
            raise HTTPException(status_code=404, detail=f"unknown source: {body.source}")
        tgt = services.store.get_entity(body.target) or services.store.find_by_alias(body.target)
        if tgt is None:
            raise HTTPException(status_code=404, detail=f"unknown target: {body.target}")
        if src.id == tgt.id:
            raise _bad("source and target resolve to the same entity")
        if src.stix_type != tgt.stix_type:
            raise _bad(
                f"cannot merge across stix_type: {src.stix_type!r} into {tgt.stix_type!r}"
            )
        try:
            touched = services.store.merge_entities(src.id, tgt.id)
        except (KeyError, ValueError) as exc:
            raise _bad(str(exc)) from exc
        try:
            validator = services.validator()
            validator.recompute(touched)
            recomputed = len(touched)
        except Exception:   # noqa: BLE001 — ATT&CK missing or similar; the merge is done, surface a warning
            recomputed = 0
    return {"source": src.id, "target": tgt.id, "recomputed": recomputed}
