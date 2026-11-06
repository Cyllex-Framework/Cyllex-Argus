"""Discover document-origin ghost entities that can be merged into their MITRE-catalog
counterparts.

Background: when an operator ran investigations BEFORE a complete `attack update`, the
Analyst stage created `intrusion-set` entities for every group name it extracted from a
paper — one entity for "Midnight Blizzard", one for "Nobelium", one for "APT29", etc.
Each is a separate row with its own claims, assessments and aliases. Later, when `attack
update` populates the MITRE catalog, the real G0016 "APT29" entity (with all its aliases
including "Midnight Blizzard", "Nobelium", "Cozy Bear", "The Dukes") lives alongside the
ghosts. The alias lookup resolves future queries to the MITRE entity correctly, but the
historical facts stay attached to the ghosts and never show up in the Threat profile for
G0016 — the operator sees an APT29 page with partial data.

This module provides the DISCOVERY half of the fix: for each ghost whose aliases overlap
with exactly ONE MITRE-catalog entity, list it as mergeable. The ACTUAL merge is handled
by `SQLiteStore.merge_entities(source, target)`, which has existed since 0.9. The CLI
`argus entity-merge-ghosts` ties the two together: discover candidates here, confirm with
the operator, loop merge_entities + validator.recompute, done.

Ambiguous ghosts (aliases match 2+ catalog entities) are left alone — automatic merge is
only safe when the mapping is 1:1. Operators can disambiguate those manually with
`argus entity-merge <ghost> <chosen-canonical>`.

Scope: intrusion-sets only in this first cut. The same shape applies to malware / tools
and will extend trivially once this one is validated.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class MergeCandidate:
    """A ghost entity that can be merged into exactly one catalog entity."""
    ghost_id: str
    ghost_name: str
    canonical_id: str
    canonical_name: str
    canonical_external_id: str
    shared_aliases: tuple[str, ...]  # the normalized aliases that caused the match


def find_mergeable(conn, stix_type: str = "intrusion-set") -> list[MergeCandidate]:
    """List every ghost entity that has an unambiguous MITRE-catalog match.

    An entity is a "ghost" if its external_id is NULL (no MITRE G-code, S-code, etc.).
    A ghost matches a catalog entity when they share at least one normalized alias AND
    they have the same stix_type. A ghost with 2+ catalog candidates is skipped — the
    merge is only safe when the mapping is 1:1.
    """
    rows = conn.execute(
        """SELECT g.id AS ghost_id, g.canonical_name AS ghost_name,
                  a_g.normalized_alias AS alias,
                  c.id AS canonical_id, c.canonical_name AS canonical_name,
                  c.external_id AS canonical_external_id
             FROM entities g
             JOIN aliases a_g ON a_g.entity_id = g.id
             JOIN aliases a_c ON a_c.normalized_alias = a_g.normalized_alias
             JOIN entities c ON c.id = a_c.entity_id
            WHERE g.stix_type = ?
              AND c.stix_type = ?
              AND g.external_id IS NULL
              AND c.external_id IS NOT NULL
              AND g.id != c.id""",
        (stix_type, stix_type),
    ).fetchall()
    # Group hits by ghost_id so we can detect ambiguity (one ghost → multiple catalog entities).
    by_ghost: dict[str, dict[str, dict]] = {}
    for row in rows:
        ghost_id = row["ghost_id"]
        canonical_id = row["canonical_id"]
        bucket = by_ghost.setdefault(ghost_id, {})
        canon_bucket = bucket.setdefault(canonical_id, {
            "ghost_name": row["ghost_name"],
            "canonical_name": row["canonical_name"],
            "canonical_external_id": row["canonical_external_id"],
            "aliases": set(),
        })
        canon_bucket["aliases"].add(row["alias"])
    candidates: list[MergeCandidate] = []
    for ghost_id, canonicals in by_ghost.items():
        if len(canonicals) != 1:
            # Ambiguous: this ghost's aliases overlap with 2+ catalog entities. Skip —
            # merging would silently pick one. The operator can disambiguate manually.
            continue
        [canonical_id] = canonicals.keys()
        data = canonicals[canonical_id]
        candidates.append(MergeCandidate(
            ghost_id=ghost_id, ghost_name=data["ghost_name"],
            canonical_id=canonical_id, canonical_name=data["canonical_name"],
            canonical_external_id=data["canonical_external_id"],
            shared_aliases=tuple(sorted(data["aliases"])),
        ))
    # Deterministic order: group by canonical name, then by ghost name.
    candidates.sort(key=lambda c: (c.canonical_name.casefold(), c.ghost_name.casefold()))
    return candidates

