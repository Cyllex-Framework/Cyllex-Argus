"""STIX 2.1 bundle: entities as SDOs, assessments as relationships with x_argus_* evidence.

Objects that come from the MITRE ATT&CK catalog are never re-emitted (a consumer that holds ATT&CK
would otherwise replace the real objects with our stubs): relationships reference their ids and carry
their names in x_argus_source_name / x_argus_target_name instead. Relationship ids are derived from
source, type and target, so exporting the same assessment twice yields the same id.
"""

from __future__ import annotations

import ipaddress
import json
import re
import uuid
from collections.abc import Callable
from datetime import datetime

import stix2

from cyllex_argus.knowledge.models import TLP, TLP_ORDER
from cyllex_argus.knowledge.profile import EntityRef, FactView, Profile

# TLP 2.0 marking-definition ids published by OASIS CTI TC. Reproduced verbatim because a STIX
# consumer that recognises the standard looks for these exact ids; a generated UUID per export
# would make the markings invisible to downstream tooling.
TLP_MARKING_IDS: dict[str, str] = {
    "clear":        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "green":        "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
    "amber":        "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
    "amber-strict": "marking-definition--826578e1-40ad-459f-bc73-ede076f81f37",
    "red":          "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
}

_HASHES = ((64, "SHA-256"), (40, "SHA-1"), (32, "MD5"))
_HEX = re.compile(r"^[a-fA-F0-9]+$")
_DOMAIN = re.compile(r"^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$", re.I)
_DEFANGED_SCHEME = re.compile(r"^hxxp(s?)(?=:)", re.I)
_DEFANGED_DOTS = ("[.]", "(.)", "{.}")
_WITH_ALIASES = ("intrusion-set", "campaign", "malware", "tool")


def _refang(value: str) -> str:
    """Undo the usual defanging of indicators in reports: hxxp, [.] (.) {.} and [:]."""
    text = value.strip()
    for mark in _DEFANGED_DOTS:
        text = text.replace(mark, ".")
    text = text.replace("[:]", ":")
    return _DEFANGED_SCHEME.sub(lambda match: "http" + match.group(1).lower(), text)


def _ip_address(raw: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        address = ipaddress.ip_address(raw)
    except ValueError:
        return None
    return None if getattr(address, "scope_id", None) else address


def indicator_pattern(value: str) -> str | None:
    raw = _refang(value)
    escaped = raw.replace("\\", "\\\\").replace("'", "\\'")
    address = _ip_address(raw)
    if address is not None:
        kind = "ipv4-addr" if address.version == 4 else "ipv6-addr"
        return f"[{kind}:value = '{address}']"
    if _HEX.match(raw):
        for length, name in _HASHES:
            if len(raw) == length:
                return f"[file:hashes.'{name}' = '{escaped.lower()}']"
    if raw.lower().startswith(("http://", "https://")):
        return f"[url:value = '{escaped}']"
    if _DOMAIN.match(raw):
        return f"[domain-name:value = '{escaped.lower()}']"
    return None


def _carries_custom_attributes(ref: EntityRef) -> bool:
    """True when an ATT&CK-origin entity has Argus-specific attributes a consumer would
    miss if we only referenced it. Today that is `sectors[]`; the function is a hook for
    future custom properties that a downstream reader can't recover from ATT&CK alone."""
    if not isinstance(ref.attributes, dict):
        return False
    sectors = ref.attributes.get("sectors")
    return isinstance(sectors, list) and bool(sectors)


def _sdo(ref: EntityRef, now: datetime, aliases: list[str] | None = None):
    common = {"id": ref.id, "name": ref.name, "created": now, "modified": now, "allow_custom": True}
    kind = ref.stix_type
    if aliases and kind in _WITH_ALIASES:
        common["aliases"] = aliases

    # Carry the actor's sectors[] attribute through to the SDO. STIX 2.1 defines
    # `threat-actor.sectors` and `identity.sectors`; `intrusion-set` has no native sectors
    # field, so there we add it as the custom property `x_argus_sectors` — stix2's
    # allow_custom=True keeps the bundle valid. Downstream tooling that doesn't know the
    # custom key just ignores it, so this is a widen-not-break change.
    attrs = ref.attributes if isinstance(ref.attributes, dict) else {}
    sectors = attrs.get("sectors")
    sectors_list = sectors if isinstance(sectors, list) else None

    # MITRE ATT&CK external_references — groups (G####), campaigns (C####), software
    # (S####). Lets a TAXII subscriber map Argus's actor id to the catalog shape they
    # already hold without having to resolve by name.
    def _attack_refs() -> list[dict] | None:
        if ref.external_id:
            return [{"source_name": "mitre-attack", "external_id": ref.external_id}]
        return None

    if kind == "intrusion-set":
        refs = _attack_refs()
        if refs:
            common["external_references"] = refs
        if sectors_list:
            common["x_argus_sectors"] = sectors_list
        return stix2.IntrusionSet(**common)
    if kind == "campaign":
        refs = _attack_refs()
        if refs:
            common["external_references"] = refs
        if sectors_list:
            common["x_argus_sectors"] = sectors_list
        return stix2.Campaign(**common)
    if kind == "malware":
        refs = _attack_refs()
        if refs:
            common["external_references"] = refs
        if sectors_list:
            common["x_argus_sectors"] = sectors_list
        return stix2.Malware(is_family=True, **common)
    if kind == "tool":
        refs = _attack_refs()
        if refs:
            common["external_references"] = refs
        if sectors_list:
            common["x_argus_sectors"] = sectors_list
        return stix2.Tool(**common)
    if kind == "attack-pattern":
        refs = [{"source_name": "mitre-attack", "external_id": ref.external_id}] if ref.external_id else None
        return stix2.AttackPattern(external_references=refs, **common)
    if kind == "vulnerability":
        return stix2.Vulnerability(**common)
    if kind == "identity":
        # Identity SDO defines `sectors[]` natively AND can carry a single sector + country
        # through the pre-0.13 shape. Prefer the list if the entity has it, fall back to
        # the single-string legacy keys.
        sector_single = attrs.get("sector")
        if sectors_list:
            common["sectors"] = sectors_list
        elif isinstance(sector_single, str) and sector_single:
            common["sectors"] = [sector_single]
        country = attrs.get("country")
        if isinstance(country, str) and country:
            # Identity SDO uses `contact_information` for free-form; keep it simple with a
            # custom property so a reader that queries by country can find it uniformly.
            common["x_argus_country"] = country
        return stix2.Identity(**common)
    if kind == "location":
        return stix2.Location(region=ref.name, **common)
    if kind == "indicator":
        pattern = indicator_pattern(ref.name)
        if pattern is None:
            return None
        return stix2.Indicator(pattern=pattern, pattern_type="stix", valid_from=now, **common)
    return None


def _relationship(fact: FactView, now: datetime, tlp_names: set[str] | None = None) -> stix2.Relationship:
    evidence = []
    references = []
    seen_urls: set[str] = set()
    for citation in fact.citations:
        item = {
            "quote": citation.quote, "quote_status": citation.quote_status.value,
            "polarity": citation.polarity.value, "publisher": citation.publisher,
            "document": citation.document_title, "location": citation.location,
            "published_at": citation.published_at.isoformat() if citation.published_at else None,
        }
        evidence.append({k: v for k, v in item.items() if v is not None})
        url = citation.location or ""
        if url.startswith(("http://", "https://")) and url not in seen_urls:
            seen_urls.add(url)
            references.append({"source_name": citation.publisher, "url": url, "description": citation.document_title})
    key = f"{fact.subject.id}|{fact.predicate}|{fact.object.id}"
    marking_refs = [TLP_MARKING_IDS[name] for name in (tlp_names or ())]
    return stix2.Relationship(
        id="relationship--" + str(uuid.uuid5(uuid.NAMESPACE_URL, key)),
        created=now,
        modified=now,
        source_ref=fact.subject.id,
        target_ref=fact.object.id,
        relationship_type=fact.predicate,
        confidence=fact.confidence,
        external_references=references or None,
        object_marking_refs=marking_refs or None,
        allow_custom=True,
        x_argus_source_name=fact.subject.label,
        x_argus_target_name=fact.object.label,
        x_argus_target_external_id=fact.object.external_id,
        x_argus_status=fact.status.value,
        x_argus_admiralty=fact.admiralty,
        x_argus_first_seen=fact.first_seen.isoformat() if fact.first_seen else None,
        x_argus_last_seen=fact.last_seen.isoformat() if fact.last_seen else None,
        x_argus_evidence=evidence,
    )


def to_stix_bundle(
    profile: Profile, now: datetime, on_skip: Callable[[FactView], None] | None = None,
    tlp_cap: TLP | None = None,
) -> dict:
    """Build the bundle. A fact whose endpoint has no STIX object is skipped and reported to `on_skip`.

    When `tlp_cap` is set, citations whose publisher TLP exceeds the cap are stripped from the
    exported relationship evidence; facts left with no evidence are omitted entirely. The bundle
    also carries the OASIS TLP 2.0 marking-definition objects for each distinct TLP that appears
    in the kept citations, and every relationship attaches those marking-definition ids via
    `object_marking_refs` so a STIX-aware consumer sees the restriction.
    """
    if tlp_cap is not None:
        profile = _apply_tlp_cap_to_profile(profile, tlp_cap)
    objects: list = []
    referable: dict[str, bool] = {}

    def register(ref: EntityRef, aliases: list[str] | None = None) -> None:
        if ref.id in referable:
            return
        if ref.attack and not _carries_custom_attributes(ref):
            # Reference-only when the ATT&CK entity has nothing Argus-specific to add.
            # Consumers already hold the ATT&CK catalog; re-emitting the stub is wasted
            # bytes AND would overwrite their canonical copy on `created`/`modified`.
            referable[ref.id] = True
            return
        sdo = _sdo(ref, now, aliases)
        referable[ref.id] = sdo is not None
        if sdo is not None:
            objects.append(sdo)

    register(profile.entity, profile.aliases)
    relationships = []
    tlp_markings_needed: set[str] = set()
    for fact in profile.facts:
        register(fact.subject)
        register(fact.object)
        if not (referable[fact.subject.id] and referable[fact.object.id]):
            if on_skip is not None:
                on_skip(fact)
            continue
        fact_markings = {c.publisher_tlp for c in fact.citations if c.publisher_tlp} & TLP_MARKING_IDS.keys()
        tlp_markings_needed |= fact_markings
        relationships.append(_relationship(fact, now, fact_markings))
    # Emit the marking-definition objects the relationships point at.
    marking_objects = [
        stix2.MarkingDefinition(
            id=TLP_MARKING_IDS[name],
            definition_type="statement",
            definition={"statement": f"TLP:{name.upper()}"},
            created=now,
            allow_custom=True,
            name=f"TLP:{name.upper()}",
        )
        for name in sorted(tlp_markings_needed, key=lambda t: TLP_ORDER[t])
    ]
    bundle = stix2.Bundle(objects=marking_objects + objects + relationships, allow_custom=True)
    return json.loads(bundle.serialize())


def _apply_tlp_cap_to_profile(profile: Profile, cap: TLP) -> Profile:
    cap_rank = TLP_ORDER[cap.value]
    kept = []
    for fact in profile.facts:
        cites = [
            c for c in fact.citations
            if c.publisher_tlp is None or TLP_ORDER.get(c.publisher_tlp, -1) <= cap_rank
        ]
        if cites:
            kept.append(fact.model_copy(update={"citations": cites}))
    return profile.model_copy(update={"facts": kept})


def store_wide_stix(
    store, now: datetime, added_after_iso: str | None = None,
) -> list[dict]:
    """Materialise every STIX object the store knows about, for the TAXII server.

    Entities that come from the MITRE ATT&CK catalog are referenced by their stix id but never
    re-emitted (a consumer that already holds ATT&CK must not have our stubs overwrite it).
    `added_after_iso` filters assessments by their stored `updated_at`; entities whose only
    assessments were filtered out are not emitted either.
    """
    conn = store.connection
    if added_after_iso:
        rows = conn.execute(
            "SELECT subject_entity_id, predicate, object_entity_id, status, confidence, "
            "admiralty, first_seen, last_seen, updated_at "
            "FROM assessments WHERE updated_at > ? ORDER BY updated_at, id",
            (added_after_iso,),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT subject_entity_id, predicate, object_entity_id, status, confidence, "
            "admiralty, first_seen, last_seen, updated_at "
            "FROM assessments ORDER BY updated_at, id"
        ).fetchall()

    entity_ids: set[str] = set()
    for r in rows:
        entity_ids.add(r["subject_entity_id"])
        entity_ids.add(r["object_entity_id"])
    entities = store.get_entities(entity_ids)
    attack_ids = store.attack_entity_ids(list(entity_ids))

    objects: list[dict] = []
    seen: set[str] = set()

    for entity_id, entity in entities.items():
        if entity_id in seen:
            continue
        ref = EntityRef(
            id=entity.id, stix_type=entity.stix_type, name=entity.canonical_name,
            external_id=entity.external_id, attack=entity_id in attack_ids,
            attributes=dict(entity.attributes),
        )
        # Pure-ATT&CK entities stay reference-only (consumers hold the catalog).
        # ATT&CK entities carrying Argus-specific attributes re-emit so the sectors[]
        # attribution survives the TAXII subscription chain.
        if entity_id in attack_ids and not _carries_custom_attributes(ref):
            continue
        aliases = store.aliases_for(entity.id)
        sdo = _sdo(ref, now, aliases=aliases)
        if sdo is None:
            continue
        objects.append(json.loads(sdo.serialize()))
        seen.add(entity_id)

    for r in rows:
        subj_id, pred, obj_id = r["subject_entity_id"], r["predicate"], r["object_entity_id"]
        if subj_id not in seen and subj_id not in attack_ids:
            continue
        if obj_id not in seen and obj_id not in attack_ids:
            continue
        key = f"{subj_id}|{pred}|{obj_id}"
        rel_id = "relationship--" + str(uuid.uuid5(uuid.NAMESPACE_URL, key))
        objects.append({
            "type": "relationship",
            "spec_version": "2.1",
            "id": rel_id,
            "created": now.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "modified": now.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "relationship_type": pred,
            "source_ref": subj_id,
            "target_ref": obj_id,
            "confidence": r["confidence"],
            "x_argus_status": r["status"],
            "x_argus_admiralty": r["admiralty"],
            "x_argus_first_seen": r["first_seen"],
            "x_argus_last_seen": r["last_seen"],
            "x_argus_updated_at": r["updated_at"],
        })
    return objects
