"""The ATT&CK matrix of the techniques Argus has observed for one entity."""

from __future__ import annotations

import sqlite3

from cyllex_argus.attack.catalog import AttackCatalog
from cyllex_argus.knowledge.models import QuoteStatus
from cyllex_argus.knowledge.scope import investigation_claim_filter

_REJECTED = QuoteStatus.REJECTED.value

TACTICS: list[tuple[str, str]] = [
    ("reconnaissance", "Reconnaissance"),
    ("resource-development", "Resource Development"),
    ("initial-access", "Initial Access"),
    ("execution", "Execution"),
    ("persistence", "Persistence"),
    ("privilege-escalation", "Privilege Escalation"),
    ("defense-evasion", "Defense Evasion"),
    ("credential-access", "Credential Access"),
    ("discovery", "Discovery"),
    ("lateral-movement", "Lateral Movement"),
    ("collection", "Collection"),
    ("command-and-control", "Command and Control"),
    ("exfiltration", "Exfiltration"),
    ("impact", "Impact"),
]


def build_matrix(
    conn: sqlite3.Connection, catalog: AttackCatalog, entity_id: str, scope_investigation_id: int | None = None,
) -> list[dict]:
    """One column per MITRE tactic, each holding the entity's `uses` techniques that belong to it.

    A technique with several tactics appears under each; one without tactics is left out.
    `sources` counts distinct publishers behind the assessment, ignoring rejected claims.
    With `scope_investigation_id`, only the techniques that investigation's own claims support are kept.
    """
    scope_sql, scope_params = (
        investigation_claim_filter(scope_investigation_id) if scope_investigation_id is not None else ("", ())
    )
    rows = conn.execute(
        f"""SELECT a.object_entity_id, a.status, a.confidence, a.admiralty,
                  (SELECT COUNT(DISTINCT COALESCE(d.primary_publisher_id, d.publisher_id))
                   FROM claims c JOIN documents d ON d.id = c.document_id
                   WHERE c.subject_entity_id = a.subject_entity_id AND c.predicate = a.predicate
                     AND c.object_entity_id = a.object_entity_id AND c.quote_status != ?) AS sources
           FROM assessments a JOIN entities e ON e.id = a.object_entity_id
           WHERE a.subject_entity_id = ? AND a.predicate = 'uses' AND e.stix_type = 'attack-pattern'
             {scope_sql}""",
        (QuoteStatus.REJECTED.value, entity_id, *scope_params),
    ).fetchall()
    columns: dict[str, dict[str, dict]] = {tactic_id: {} for tactic_id, _ in TACTICS}
    for row in rows:
        tech = catalog.resolve_by_stix_id(row[0])
        if tech is None:
            continue
        entry = {
            "id": row[0], "external_id": tech.technique_id, "name": tech.name,
            "status": row[1], "confidence": row[2], "admiralty": row[3], "sources": row[4],
        }
        for tactic_id in tech.tactics:
            column = columns.get(tactic_id)
            if column is None:
                continue
            kept = column.get(tech.technique_id)
            if kept is None or entry["confidence"] > kept["confidence"]:
                column[tech.technique_id] = entry
    return [
        {"id": tactic_id, "name": name,
         "techniques": sorted(columns[tactic_id].values(), key=lambda t: t["external_id"])}
        for tactic_id, name in TACTICS
    ]


def build_campaign_matrix(conn: sqlite3.Connection, catalog: AttackCatalog, campaign_id: str) -> list[dict]:
    """ATT&CK matrix of the techniques a campaign is linked to, directly or through its attributed actor.

    Analyst usually puts ``uses`` on the actor, not on the campaign, so a strict direct-only matrix
    would be empty for most campaigns. Union with techniques reachable in two hops
    (``campaign attributed-to actor uses attack-pattern``) so the UI shows the campaign's effective
    kill-chain. When a technique arrives from both paths, the entry's status, confidence and admiralty
    come from whichever assessment is more confident; sources add up across the two paths.
    """
    rows = conn.execute(
        """SELECT a.object_entity_id, a.status, a.confidence, a.admiralty,
                   (SELECT COUNT(DISTINCT COALESCE(d.primary_publisher_id, d.publisher_id))
                    FROM claims c JOIN documents d ON d.id = c.document_id
                    WHERE c.subject_entity_id = a.subject_entity_id AND c.predicate = a.predicate
                      AND c.object_entity_id = a.object_entity_id AND c.quote_status != ?) AS sources
            FROM assessments a JOIN entities e ON e.id = a.object_entity_id
            WHERE a.predicate = 'uses' AND e.stix_type = 'attack-pattern'
              AND (
                a.subject_entity_id = ?
                OR a.subject_entity_id IN (
                    SELECT ar.object_entity_id FROM assessments ar
                    WHERE ar.subject_entity_id = ? AND ar.predicate = 'attributed-to'
                )
              )""",
        (_REJECTED, campaign_id, campaign_id),
    ).fetchall()
    columns: dict[str, dict[str, dict]] = {tactic_id: {} for tactic_id, _ in TACTICS}
    for row in rows:
        tech = catalog.resolve_by_stix_id(row[0])
        if tech is None:
            continue
        entry = {
            "id": row[0], "external_id": tech.technique_id, "name": tech.name,
            "status": row[1], "confidence": row[2], "admiralty": row[3], "sources": row[4],
        }
        for tactic_id in tech.tactics:
            column = columns.get(tactic_id)
            if column is None:
                continue
            kept = column.get(tech.technique_id)
            if kept is None or entry["confidence"] > kept["confidence"]:
                column[tech.technique_id] = entry
    return [
        {"id": tactic_id, "name": name,
         "techniques": sorted(columns[tactic_id].values(), key=lambda t: t["external_id"])}
        for tactic_id, name in TACTICS
    ]
