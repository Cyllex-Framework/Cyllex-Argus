"""MITRE ATT&CK Enterprise reference data: techniques, groups and software."""

from __future__ import annotations

import json
import re
from pathlib import Path

import httpx
from pydantic import BaseModel

from cyllex_argus.knowledge.models import AliasOrigin
from cyllex_argus.knowledge.sqlite_store import SQLiteStore

ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)
_TECHNIQUE_ID = re.compile(r"^T\d{4}(\.\d{3})?$")
_MAX_REVOCATION_HOPS = 5


def normalize_technique_id(value: str) -> str | None:
    candidate = value.strip().upper().replace("/", ".")
    return candidate if _TECHNIQUE_ID.match(candidate) else None


class Technique(BaseModel):
    stix_id: str
    technique_id: str
    name: str
    revoked: bool = False
    deprecated: bool = False
    tactics: list[str] = []
    # Full MITRE metadata. Everything beyond `tactics` is optional and only populated when the bundle
    # carries it; the matrix columns use just id/name/tactics, the detail view surfaces the rest.
    description: str = ""
    platforms: list[str] = []
    detection: str = ""
    data_sources: list[str] = []
    permissions_required: list[str] = []
    is_subtechnique: bool = False


class AttackEntity(BaseModel):
    stix_id: str
    stix_type: str
    name: str
    aliases: list[str]
    # The MITRE catalog id — G1015 for intrusion-sets, S0190 for software, C0027 for
    # campaigns. Captured from the raw STIX object's external_references at parse time
    # so the ingest path can set entities.external_id. 0.14 and earlier lost this on
    # groups and software (only techniques and campaigns got it), which left the Threat
    # Profile header without the G/S badge that a CTI reader expects.
    external_id: str | None = None


def _external_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


class AttackCatalog:
    def __init__(self, bundle: dict) -> None:
        self._by_tid: dict[str, Technique] = {}
        self._by_stix: dict[str, Technique] = {}
        self._revoked_by: dict[str, str] = {}
        self._groups: list[AttackEntity] = []
        self._software: list[AttackEntity] = []
        self._campaigns: list[AttackEntity] = []
        for obj in bundle.get("objects", []):
            kind = obj.get("type")
            if kind == "attack-pattern":
                tid = _external_id(obj)
                if not tid:
                    continue
                tech = Technique(
                    stix_id=obj["id"], technique_id=tid, name=obj.get("name", ""),
                    revoked=bool(obj.get("revoked")), deprecated=bool(obj.get("x_mitre_deprecated")),
                    tactics=[
                        phase["phase_name"] for phase in obj.get("kill_chain_phases") or []
                        if phase.get("kill_chain_name") == "mitre-attack" and phase.get("phase_name")
                    ],
                    description=str(obj.get("description") or ""),
                    platforms=list(obj.get("x_mitre_platforms") or []),
                    detection=str(obj.get("x_mitre_detection") or ""),
                    data_sources=list(obj.get("x_mitre_data_sources") or []),
                    permissions_required=list(obj.get("x_mitre_permissions_required") or []),
                    is_subtechnique=bool(obj.get("x_mitre_is_subtechnique")),
                )
                self._by_tid[tid] = tech
                self._by_stix[tech.stix_id] = tech
            elif kind == "relationship" and obj.get("relationship_type") == "revoked-by":
                self._revoked_by[obj["source_ref"]] = obj["target_ref"]
            elif kind in ("intrusion-set", "malware", "tool", "campaign"):
                if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                    continue
                # Groups and campaigns use `aliases`; malware and tools use `x_mitre_aliases`.
                if kind in ("intrusion-set", "campaign"):
                    names = obj.get("aliases")
                else:
                    names = obj.get("x_mitre_aliases")
                entity = AttackEntity(
                    stix_id=obj["id"], stix_type=kind, name=obj["name"],
                    aliases=list(dict.fromkeys([obj["name"], *(names or [])])),
                    external_id=_external_id(obj),
                )
                if kind == "intrusion-set":
                    self._groups.append(entity)
                elif kind == "campaign":
                    self._campaigns.append(entity)
                else:
                    self._software.append(entity)

    @classmethod
    def from_file(cls, path: Path) -> AttackCatalog:
        return cls(json.loads(path.read_text(encoding="utf-8")))

    @property
    def groups(self) -> list[AttackEntity]:
        return list(self._groups)

    @property
    def software(self) -> list[AttackEntity]:
        return list(self._software)

    @property
    def campaigns(self) -> list[AttackEntity]:
        return list(self._campaigns)

    def active_techniques(self) -> list[Technique]:
        return [t for t in self._by_tid.values() if not t.revoked and not t.deprecated]

    def resolve_technique(self, technique_id: str) -> Technique | None:
        tid = normalize_technique_id(technique_id)
        return self._follow_revocations(self._by_tid.get(tid) if tid else None)

    def resolve_by_stix_id(self, stix_id: str) -> Technique | None:
        return self._follow_revocations(self._by_stix.get(stix_id))

    def _follow_revocations(self, tech: Technique | None) -> Technique | None:
        for _ in range(_MAX_REVOCATION_HOPS):
            if tech is None:
                return None
            if tech.revoked:
                target = self._revoked_by.get(tech.stix_id)
                tech = self._by_stix.get(target) if target else None
                continue
            return None if tech.deprecated else tech
        return None


def download_attack(dest: Path, client: httpx.Client, url: str = ATTACK_URL) -> Path:
    response = client.get(url)
    response.raise_for_status()
    data = json.loads(response.text)  # refuse to store anything that is not JSON...
    objects = data.get("objects") if isinstance(data, dict) else None
    if not isinstance(objects, list) or not any(
        isinstance(obj, dict) and obj.get("type") == "attack-pattern" for obj in objects
    ):
        raise ValueError("not an ATT&CK bundle")  # ...or that would replace a good bundle with junk
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(".tmp")
    tmp.write_text(response.text, encoding="utf-8")
    tmp.replace(dest)
    return dest


def load_catalog_into_store(catalog: AttackCatalog, store: SQLiteStore) -> int:
    """Create ATT&CK groups, software, campaigns and active techniques as entities.
    Campaigns carry their MITRE external_id (C0027, C0033, …) so later lookups by id resolve
    to the official catalog entity rather than creating a document-origin duplicate.
    Returns how many entities were new in this call."""
    created = 0
    for entity in [*catalog.groups, *catalog.software, *catalog.campaigns]:
        existing = store.get_entity(entity.stix_id)
        if existing is None:
            store.create_entity(
                entity.stix_type, entity.name, AliasOrigin.ATTACK,
                external_id=entity.external_id or _mitre_id_for(catalog, entity.stix_id),
                entity_id=entity.stix_id,
            )
            created += 1
        elif existing.external_id is None and entity.external_id:
            # Backfill: 0.14 and earlier created groups/software without external_id.
            # Patching the row keeps the ATT&CK badge visible without forcing a full
            # DB rebuild. Non-ATT&CK entities are untouched (their id has no attack
            # origin to backfill from).
            store.set_entity_external_id(entity.stix_id, entity.external_id)
        for alias in entity.aliases:
            store.add_alias(alias, entity.stix_id, AliasOrigin.ATTACK)
    for tech in catalog.active_techniques():
        if store.get_entity(tech.stix_id) is None:
            store.create_entity(
                "attack-pattern", tech.name, AliasOrigin.ATTACK,
                external_id=tech.technique_id, entity_id=tech.stix_id,
            )
            created += 1
    return created


def _mitre_id_for(catalog: AttackCatalog, stix_id: str) -> str | None:
    """Resolve a campaign's MITRE external id (C0027, …) from the parsed bundle object."""
    # The AttackEntity stripped it; re-derive from the raw bundle via the stix_id lookup. The
    # catalog does not keep the raw object around, so we scan — campaigns are a small list.
    for camp in catalog.campaigns:
        if camp.stix_id == stix_id:
            # The MITRE naming convention is C0001..C9999 and shows up as the canonical name
            # when and only when the bundle has no human-readable alias; use the alias list.
            for alias in [camp.name, *camp.aliases]:
                if _looks_like_mitre_campaign_id(alias):
                    return alias
    return None


_CAMPAIGN_ID = re.compile(r"^C\d{4}$")


def _looks_like_mitre_campaign_id(value: str) -> bool:
    return bool(_CAMPAIGN_ID.match(value))


# A full Enterprise catalog carries well over a hundred intrusion-sets. Thirty is a floor no
# partial or interrupted load reaches — used only by the startup refresh heuristic, never as a
# prerequisite gate: a trimmed catalog is sparse on purpose and perfectly usable.
MIN_LOADED_GROUPS = 30

# Catalog rows are identified by alias ORIGIN, the same way `browse.attack_counts` does it.
# Counting `stix_type = 'intrusion-set'` instead would count document-origin ghosts, and a store
# full of ghosts with no catalog is exactly the state these checks exist to catch.
_LOADED_GROUPS = (
    "SELECT COUNT(*) AS n FROM entities WHERE stix_type = 'intrusion-set' "
    "AND id IN (SELECT DISTINCT entity_id FROM aliases WHERE origin = 'attack')"
)


def _loaded_groups(conn) -> int:
    try:
        row = conn.execute(_LOADED_GROUPS).fetchone()
    except Exception:  # noqa: BLE001 — a store too young to have the tables is simply not loaded
        return 0
    return row["n"] if hasattr(row, "keys") else row[0]


def catalog_loaded(conn) -> bool:
    """True when the ATT&CK catalog is in the STORE, not merely on disk.

    The question every prerequisite gate wants. The file and the loaded rows fail independently:
    `argus attack update` does both, and wiping the database undoes only the second — which does
    not break the pipeline loudly. It makes it resolve nothing, so the Analyst writes a
    document-origin entity for every group name it reads, one "Midnight Blizzard" per paper, with
    no alias tying any of them to APT29.

    Deliberately "any rows at all": a deliberately trimmed catalog is sparse and usable, and
    refusing to run against it would be wrong.
    """
    return _loaded_groups(conn) > 0


def catalog_looks_complete(conn, minimum: int = MIN_LOADED_GROUPS) -> bool:
    """True when the loaded catalog is big enough to look like a full Enterprise download.

    Used by `argus serve` startup to decide whether to auto-submit a refresh, where a false
    negative costs one redundant job and a false positive leaves the operator with a
    half-installed catalog. Not a prerequisite gate — see `catalog_loaded`.
    """
    return _loaded_groups(conn) >= minimum
