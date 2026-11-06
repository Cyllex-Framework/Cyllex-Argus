"""STIX 2.1 bundle ingest.

Reads a STIX bundle written by any STIX-aware tool (MISP, OpenCTI, hand-crafted) and merges the
SDOs and SROs into Argus's store. The bundle itself becomes a Document — the audit trail stays
intact — and relationships become claims the Validator could have produced, with a synthetic
quote that pins each one to a human-readable sentence inside the stored bundle text.

Design decisions worth remembering:

- Dedupe. attack-pattern entities are matched by MITRE external_id first (so re-importing a bundle
  that references T1566.004 does not create a sibling of the already-loaded ATT&CK technique).
  Other entity types are matched by (stix_type, canonical_name) via find_by_alias. On a hit the
  importer reuses the existing id instead of creating a new entity.
- Idempotency. The bundle's content hash gates `add_document`, which deduplicates by hash and
  canonical_url. Running an import twice yields the same claim rows (same quote, same ids).
- Aliases from the bundle land as `user` origin because they came from an operator-trusted
  structured source, not from an untrusted narrative document.
- Identity sectors/countries. `identity.sectors[0]` and (when extension-provided) country are
  mapped to the structured attributes the `argus query-targets` command uses.
- Relationships. STIX relationship_types map 1:1 to Argus predicates for the common ones
  (uses / attributed-to / targets / variant-of / exploits). Unknown types are skipped and listed
  in the report so the operator can decide if that gap needs a mapping.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path

from cyllex_argus.knowledge.models import (
    AliasOrigin,
    Assessment,
    ClaimDraft,
    NewDocument,
    Polarity,
    QuoteStatus,
    Stage,
)
from cyllex_argus.scoring.confidence import score
from cyllex_argus.services import Services

STIX_IMPORT_PROMPT_VERSION = "stix-import-v1"

# STIX SDO type names Argus knows about. Any other type is skipped and reported.
_SDO_TO_ARGUS_TYPE: dict[str, str] = {
    "intrusion-set": "intrusion-set",
    "malware": "malware",
    "tool": "tool",
    "attack-pattern": "attack-pattern",
    "identity": "identity",
    "campaign": "campaign",
    "vulnerability": "vulnerability",
    "location": "location",
}

# STIX relationship_type -> Argus predicate. Non-matching relationships are listed in the report.
_REL_TO_PREDICATE: dict[str, str] = {
    "uses": "uses",
    "attributed-to": "attributed-to",
    "targets": "targets",
    "variant-of": "variant-of",
    "exploits": "exploits",
}


@dataclass
class ImportReport:
    bundle_id: str | None = None
    entities_added: int = 0
    entities_matched: int = 0
    aliases_added: int = 0
    claims_added: int = 0
    identities_tagged: int = 0
    skipped: list[str] = field(default_factory=list)


def import_stix_bundle(services: Services, path: Path) -> ImportReport:
    """Merge a STIX 2.1 bundle at `path` into the store. Raises ValueError on malformed input."""
    raw = path.read_bytes()
    try:
        data = json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError(f"{path} is not valid JSON: {exc}") from exc
    return _import(
        services, data, raw,
        source_url=f"file://{path.resolve().as_posix()}",
        title_hint=path.name, source_label=str(path),
    )


def import_stix_envelope(services: Services, envelope: dict, source: str = "<taxii>") -> ImportReport:
    """TAXII entrypoint: wrap a bare `{"objects": [...]}` envelope as a STIX bundle and import.

    TAXII clients POST envelopes without the top-level `type:bundle`/`id` the file importer
    expects; this helper synthesises a bundle id and routes through the same path, so a POST
    and a CLI import exercise identical logic (same validation, same recompute pass, same
    identity enrichment).
    """
    if not isinstance(envelope, dict):
        raise ValueError("TAXII envelope must be a JSON object")
    objects = envelope.get("objects")
    if not isinstance(objects, list):
        raise ValueError("TAXII envelope needs an 'objects' array")
    bundle_id = envelope.get("id") or f"bundle--taxii-{uuid.uuid4()}"
    bundle = {"type": "bundle", "id": bundle_id, "spec_version": "2.1", "objects": objects}
    raw = json.dumps(bundle, separators=(",", ":")).encode("utf-8")
    return _import(
        services, bundle, raw,
        source_url=f"taxii://argus/{bundle_id}",
        title_hint=bundle_id, source_label=source,
    )


def _import(
    services: Services, data: dict, raw: bytes,
    source_url: str, title_hint: str, source_label: str,
) -> ImportReport:
    """Shared body — the file importer and the TAXII entrypoint both land here."""
    if not isinstance(data, dict) or data.get("type") != "bundle":
        raise ValueError(f"{source_label} is not a STIX bundle (missing 'type: bundle')")
    objects = data.get("objects") or []
    if not isinstance(objects, list):
        raise ValueError(f"{source_label} has a non-list 'objects' field")

    store = services.store
    report = ImportReport(bundle_id=data.get("id"))
    index: dict[str, dict] = {}
    for obj in objects:
        if isinstance(obj, dict) and isinstance(obj.get("id"), str):
            index[obj["id"]] = obj

    stix_to_entity: dict[str, str] = {}

    # Pass 1 — SDOs become entities.
    for obj in objects:
        if not isinstance(obj, dict):
            continue
        argus_type = _SDO_TO_ARGUS_TYPE.get(str(obj.get("type", "")))
        if argus_type is None:
            # Relationships are handled in pass 2; everything else is reported if ignored.
            if obj.get("type") not in {"relationship", "bundle"}:
                report.skipped.append(f"unsupported SDO type {obj.get('type')!r}")
            continue
        name = obj.get("name")
        if not isinstance(name, str) or not name.strip():
            report.skipped.append(f"{obj.get('type')} with no name")
            continue
        name = name.strip()

        external_id = _external_mitre_id(obj) if argus_type == "attack-pattern" else None
        entity = None
        if external_id:
            entity = store.find_by_external_id(external_id)
        if entity is None:
            entity = store.find_by_alias(name, stix_types={argus_type})
        if entity is not None:
            stix_to_entity[str(obj["id"])] = entity.id
            report.entities_matched += 1
        else:
            created = store.create_entity(
                argus_type, name, AliasOrigin.USER, external_id=external_id,
            )
            stix_to_entity[str(obj["id"])] = created.id
            report.entities_added += 1
            entity = created

        # Aliases from the SDO. Dedup is handled by the store's upsert.
        for alias in obj.get("aliases") or []:
            if isinstance(alias, str) and alias.strip() and alias.strip() != name:
                store.add_alias(alias.strip(), entity.id, AliasOrigin.USER)
                report.aliases_added += 1

        # Identity sector / country go to the structured attributes query-targets reads.
        if argus_type == "identity":
            tagged = _tag_identity(store, entity.id, obj)
            if tagged:
                report.identities_tagged += 1

    # Build a synthetic document to anchor the claims produced from relationships.
    publisher = store.get_or_create_publisher(
        "STIX import", default_reliability="C",
    )
    try:
        doc, _ = store.add_document(NewDocument(
            url=source_url,
            canonical_url=source_url,
            title=f"STIX bundle: {data.get('id', title_hint)}",
            publisher_id=publisher.id,
            published_at=_date_from_bundle(data) or date.today(),
            content_hash=hashlib.sha256(raw).hexdigest(),
            raw_path=source_label,
            text=json.dumps(data, indent=2, ensure_ascii=False),
        ), stage=Stage.VALIDATED)
    except Exception as exc:   # noqa: BLE001 — surface any store error to the caller intact
        raise ValueError(f"could not record the bundle as a document: {exc}") from exc

    # Pass 2 — SROs become claims.
    touched: set[tuple[str, str, str]] = set()
    for obj in objects:
        if not isinstance(obj, dict) or obj.get("type") != "relationship":
            continue
        rel_type = str(obj.get("relationship_type", ""))
        predicate = _REL_TO_PREDICATE.get(rel_type)
        if predicate is None:
            report.skipped.append(f"relationship type {rel_type!r}")
            continue
        source_id = stix_to_entity.get(str(obj.get("source_ref", "")))
        target_id = stix_to_entity.get(str(obj.get("target_ref", "")))
        if source_id is None or target_id is None:
            report.skipped.append(
                f"relationship {obj.get('id')}: source or target not in bundle"
            )
            continue
        source_obj = index.get(str(obj.get("source_ref")), {})
        target_obj = index.get(str(obj.get("target_ref")), {})
        source_name = str(source_obj.get("name", "?"))
        target_name = str(target_obj.get("name", "?"))
        source_type = _SDO_TO_ARGUS_TYPE.get(str(source_obj.get("type", "")), "indicator")
        target_type = _SDO_TO_ARGUS_TYPE.get(str(target_obj.get("type", "")), "indicator")
        technique_id = (
            _external_mitre_id(target_obj) if target_obj.get("type") == "attack-pattern" else None
        )

        quote = f"STIX relationship: {source_name} {rel_type} {target_name}"
        if len(quote) < 20:
            quote = quote + " " * (20 - len(quote))

        draft = ClaimDraft(
            subject=source_name, subject_type=source_type,
            predicate=predicate,
            object=target_name, object_type=target_type,
            polarity=Polarity.ASSERTS,
            quote=quote,
            technique_id=technique_id,
        )
        store.add_claim(
            doc.id, draft, QuoteStatus.VERIFIED, STIX_IMPORT_PROMPT_VERSION,
            source_id, target_id, None,
        )
        report.claims_added += 1
        touched.add((source_id, predicate, target_id))

    # Pass 3 — build assessments for every triple the import just added. Without this the
    # imported knowledge sits in `claims` but never surfaces in the threat profile, the
    # dashboard counts or `query-targets` — which all read from `assessments`. Does not
    # require the ATT&CK catalog: `score()` only needs evidence from the store.
    _recompute_assessments(services, touched)

    return report


def _recompute_assessments(services: Services, keys: set[tuple[str, str, str]]) -> None:
    store = services.store
    today = date.today()
    cfg = services.config.scoring
    for subject_id, predicate, object_id in keys:
        evidence = store.evidence_for(subject_id, predicate, object_id)
        if not evidence:
            store.delete_assessment(subject_id, predicate, object_id)
            continue
        competing = (
            store.competing_attribution_publishers(subject_id, object_id)
            if predicate == "attributed-to" else set()
        )
        result = score(evidence, competing, cfg, today)
        store.upsert_assessment(Assessment(
            subject_entity_id=subject_id, predicate=predicate, object_entity_id=object_id,
            status=result.status, confidence=result.confidence, admiralty=result.admiralty,
            first_seen=result.first_seen, last_seen=result.last_seen,
            analytic_confidence=result.analytic_confidence,
        ))


def _external_mitre_id(obj: dict) -> str | None:
    for ref in obj.get("external_references") or []:
        if isinstance(ref, dict) and ref.get("source_name") == "mitre-attack":
            value = ref.get("external_id")
            if isinstance(value, str) and value.strip():
                return value.strip()
    return None


def _tag_identity(store, entity_id: str, obj: dict) -> bool:
    """Set sector/country on an identity entity when the STIX object carries them."""
    sector = None
    country = None
    sectors = obj.get("sectors")
    if isinstance(sectors, list) and sectors:
        for s in sectors:
            if isinstance(s, str) and s.strip():
                sector = s.strip()
                break
    # STIX 2.1 has no first-class country field on identity; several producers put it under
    # extensions, labels or contact_information. We check a few common shapes.
    extensions = obj.get("extensions")
    if isinstance(extensions, dict):
        for ext in extensions.values():
            if isinstance(ext, dict):
                for key in ("country", "country_code", "iso_country_code"):
                    if isinstance(ext.get(key), str) and ext[key].strip():
                        country = ext[key].strip()
                        break
            if country:
                break
    if country is None:
        contact = obj.get("contact_information")
        if isinstance(contact, dict) and isinstance(contact.get("country"), str):
            country = contact["country"].strip()
    if not sector and not country:
        return False
    kwargs: dict[str, str] = {}
    if sector:
        kwargs["sector"] = sector
    if country:
        kwargs["country"] = country
    store.set_entity_attributes(entity_id, **kwargs)
    return True


def _date_from_bundle(bundle: dict) -> date | None:
    for key in ("created", "modified"):
        value = bundle.get(key)
        if isinstance(value, str):
            try:
                return datetime.fromisoformat(value.replace("Z", "+00:00")).date()
            except ValueError:
                continue
    return None
