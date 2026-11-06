"""Read-only queries for the web interface. Uses its own SQLite connection (one per request/thread)."""

from __future__ import annotations

import sqlite3
from datetime import date
from pathlib import Path, PureWindowsPath

from cyllex_argus.attack.catalog import AttackCatalog
from cyllex_argus.knowledge.attack_matrix import TACTICS, build_matrix
from cyllex_argus.knowledge.dates import parse_loose_date
from cyllex_argus.knowledge.indicators import freshness_for, indicator_kind, sector_hint
from cyllex_argus.knowledge.models import QuoteStatus
from cyllex_argus.knowledge.names import normalize_name
from cyllex_argus.knowledge.scope import investigation_claim_filter as _investigation_claim_filter
from cyllex_argus.knowledge.trace import SQLiteTraceRecorder
from cyllex_argus.pipeline.quotes import QuoteLocator

_LOCATABLE = frozenset({QuoteStatus.VERIFIED, QuoteStatus.VERIFIED_FUZZY})  # a rejected quote is never highlighted
_ATTACK_ALIAS = "SELECT DISTINCT entity_id FROM aliases WHERE origin = 'attack'"
_MAX_GRAPH_EDGES = 200
_MAX_GRAPH_NODES = 500  # keeps the IN (...) lists far below SQLite's bound-variable limit


def _label(name: str, external_id: str | None) -> str:
    return f"{name} ({external_id})" if external_id else name


class BrowseQueries:
    def __init__(self, db_path: Path | str, fuzzy_threshold: float = 95) -> None:
        self._conn = sqlite3.connect(str(db_path))
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA query_only = ON")
        self._fuzzy_threshold = fuzzy_threshold

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> BrowseQueries:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- overview ------------------------------------------------------------------

    def _scalar(self, sql: str) -> int:
        return self._conn.execute(sql).fetchone()[0]

    def overview(self) -> dict:
        documents = {r[0]: r[1] for r in self._conn.execute(
            "SELECT stage, COUNT(*) FROM documents GROUP BY stage ORDER BY stage")}
        assessments = {r[0]: r[1] for r in self._conn.execute(
            "SELECT status, COUNT(*) FROM assessments GROUP BY status ORDER BY status")}
        recent = [self._investigation_row(r) for r in self._conn.execute(
            "SELECT * FROM investigations ORDER BY id DESC LIMIT 5")]
        unrated = [{"id": r["id"], "name": r["name"]} for r in self._conn.execute(
            "SELECT id, name FROM publishers WHERE reliability = 'F' ORDER BY name COLLATE NOCASE")]
        return {
            "counts": {
                "threats": self._scalar("SELECT COUNT(DISTINCT subject_entity_id) FROM assessments"),
                "documents": documents,
                "assessments": assessments,
                "investigations": self._scalar("SELECT COUNT(*) FROM investigations"),
            },
            "recent_investigations": recent,
            "unrated_publishers": unrated,
        }

    def _stage_counts(self, investigation_id: int) -> dict[str, int]:
        rows = self._conn.execute(
            """SELECT d.stage, COUNT(*) FROM documents d
               JOIN investigation_documents l ON l.document_id = d.id
               WHERE l.investigation_id = ? GROUP BY d.stage ORDER BY d.stage""",
            (investigation_id,),
        )
        return {r[0]: r[1] for r in rows}

    def _started_by(self, row: sqlite3.Row) -> str:
        """The username that started this run, or "system" for a scheduler/CLI run. Resolves even
        a tombstoned user so attribution survives a delete."""
        created_by = row["created_by"] if "created_by" in row.keys() else None
        if created_by is None:
            return "system"
        found = self._conn.execute("SELECT username FROM users WHERE id = ?", (created_by,)).fetchone()
        return found["username"] if found else "system"

    def _investigation_row(self, row: sqlite3.Row) -> dict:
        # The `token_usage.total` block is the only piece small enough to inline in a listing row;
        # the per-stage breakdown is heavier and lives on the dashboard payload.
        return {
            "id": row["id"], "target": row["target"], "state": row["state"],
            "resolved_entity_id": row["resolved_entity_id"],
            "started_at": row["started_at"], "finished_at": row["finished_at"],
            "collected": bool(row["collected"]), "stage_counts": self._stage_counts(row["id"]),
            "started_by": self._started_by(row),
            "token_usage": self.token_usage(row["id"])["total"],
            # None for operator-paused rows (that is the baseline case; the UI treats null as
            # "nothing to say about why"); a sentence for recovery-paused rows.
            "paused_reason": row["paused_reason"] if "paused_reason" in row.keys() else None,
        }

    # -- threats -------------------------------------------------------------------

    def _attack_ids(self, entity_ids: list[str]) -> set[str]:
        if not entity_ids:
            return set()
        marks = ",".join("?" for _ in entity_ids)
        rows = self._conn.execute(f"{_ATTACK_ALIAS} AND entity_id IN ({marks})", entity_ids)
        return {r[0] for r in rows}

    def list_threats(self, q: str = "", stix_type: str = "", include_catalog: bool = False,
                     limit: int = 50) -> list[dict]:
        needle = normalize_name(q)
        rows = self._conn.execute(
            """WITH fact_counts AS (
                   SELECT entity_id, COUNT(*) AS n FROM (
                       SELECT subject_entity_id AS entity_id FROM assessments
                       UNION ALL
                       SELECT object_entity_id FROM assessments WHERE object_entity_id <> subject_entity_id)
                   GROUP BY entity_id)
               SELECT * FROM (
                   SELECT e.id, e.stix_type, e.canonical_name, e.external_id, COALESCE(fc.n, 0) AS facts
                   FROM entities e LEFT JOIN fact_counts fc ON fc.entity_id = e.id
                   WHERE (? = '' OR EXISTS (SELECT 1 FROM aliases al
                                            WHERE al.entity_id = e.id AND al.normalized_alias LIKE ?))
                     AND (? = '' OR e.stix_type = ?)
               ) WHERE (? = 1 OR facts > 0)
               ORDER BY facts DESC, canonical_name COLLATE NOCASE, id LIMIT ?""",
            (needle, f"%{needle}%", stix_type, stix_type, 1 if include_catalog else 0, max(1, min(limit, 500))),
        ).fetchall()
        attack = self._attack_ids([r["id"] for r in rows])
        return [
            {
                "id": r["id"], "stix_type": r["stix_type"], "name": r["canonical_name"],
                "external_id": r["external_id"], "label": _label(r["canonical_name"], r["external_id"]),
                "facts": r["facts"], "attack": r["id"] in attack,
            }
            for r in rows
        ]

    def aliases_with_origin(self, entity_id: str) -> list[dict]:
        rows = self._conn.execute(
            "SELECT alias, origin FROM aliases WHERE entity_id = ? ORDER BY alias COLLATE NOCASE", (entity_id,))
        return [{"alias": r["alias"], "origin": r["origin"]} for r in rows]

    def _last_seen(self, entity_id: str) -> date | None:
        """The latest `last_seen` across every assessment the entity appears in, as subject or object."""
        row = self._conn.execute(
            """SELECT MAX(last_seen) FROM assessments
               WHERE (subject_entity_id = ? OR object_entity_id = ?) AND last_seen IS NOT NULL""",
            (entity_id, entity_id)).fetchone()
        return parse_loose_date(row[0])

    def entity_detail(self, entity_id: str, today: date | None = None) -> dict | None:
        """The per-type `detail` block of an entity, or None when its type has none (or nothing is known)."""
        row = self._conn.execute(
            "SELECT stix_type, canonical_name, external_id FROM entities WHERE id = ?", (entity_id,)).fetchone()
        if row is None:
            return None
        kind = row["stix_type"]
        if kind == "indicator":
            last_seen = self._last_seen(entity_id)
            return {
                "kind": indicator_kind(row["canonical_name"]), "value": row["canonical_name"],
                "freshness": freshness_for(last_seen, today),
                "last_seen": last_seen.isoformat() if last_seen else None,
            }
        if kind == "identity":
            names = [row["canonical_name"], *(a["alias"] for a in self.aliases_with_origin(entity_id))]
            hint = sector_hint(names)
            return {"sector_hint": hint} if hint else None
        if kind == "vulnerability" and row["external_id"]:
            return {"cve_id": row["external_id"]}
        return None

    def graph(self, entity_id: str, depth: int = 1, max_nodes: int = 150, limit: int = 60,
              scope_investigation_id: int | None = None, today: date | None = None,
              catalog: AttackCatalog | None = None) -> dict:
        if self._conn.execute("SELECT 1 FROM entities WHERE id = ?", (entity_id,)).fetchone() is None:
            return {"nodes": [], "edges": [], "truncated": False}
        limit = max(1, min(limit, _MAX_GRAPH_EDGES))
        max_nodes = max(1, min(max_nodes, _MAX_GRAPH_NODES))
        scope_sql, scope_params = (
            _investigation_claim_filter(scope_investigation_id, "assessments")
            if scope_investigation_id is not None else ("", ())
        )
        order = [entity_id]
        seen = {entity_id}
        edges: dict[str, dict] = {}
        frontier = [entity_id]
        for _ in range(max(1, min(depth, 3))):
            next_frontier: list[str] = []
            for node in frontier:
                rows = self._conn.execute(
                    f"SELECT * FROM assessments WHERE (subject_entity_id = ? OR object_entity_id = ?) {scope_sql}",
                    (node, node, *scope_params))
                for row in rows:
                    source, target = row["subject_entity_id"], row["object_entity_id"]
                    other = target if source == node else source
                    if other not in seen:
                        if len(order) >= max_nodes:
                            continue
                        seen.add(other)
                        order.append(other)
                        next_frontier.append(other)
                    edge_id = f"{source}|{row['predicate']}|{target}"
                    edges[edge_id] = {
                        "id": edge_id, "source": source, "target": target, "predicate": row["predicate"],
                        "status": row["status"], "confidence": row["confidence"],
                    }
            frontier = next_frontier
        marks = ",".join("?" for _ in order)
        info = {r["id"]: r for r in self._conn.execute(
            f"SELECT id, stix_type, canonical_name, external_id FROM entities WHERE id IN ({marks})", order)}
        attack = self._attack_ids(order)
        nodes = [
            {"id": node_id, "label": _label(info[node_id]["canonical_name"], info[node_id]["external_id"]),
             "type": info[node_id]["stix_type"], "attack": node_id in attack}
            for node_id in order if node_id in info
        ]
        for node in nodes:  # only indicators carry a freshness; the key is absent on every other type
            if node["type"] == "indicator":
                node["freshness"] = freshness_for(self._last_seen(node["id"]), today)
            # Attack-pattern nodes carry their first MITRE tactic when the catalog is available: the kill-chain
            # layout uses it to place each technique in the right column. Missing catalog → no tactic key.
            if node["type"] == "attack-pattern" and catalog is not None:
                tech = catalog.resolve_by_stix_id(node["id"])
                if tech is not None and tech.tactics:
                    node["tactic"] = tech.tactics[0]
        kept = {n["id"] for n in nodes}
        kept_edges = [e for e in edges.values() if e["source"] in kept and e["target"] in kept]
        truncated = len(kept_edges) > limit
        if truncated:  # keep the first `limit` edges, then only the nodes they reference (and the root)
            kept_edges = kept_edges[:limit]
            referenced = {entity_id} | {e["source"] for e in kept_edges} | {e["target"] for e in kept_edges}
            nodes = [n for n in nodes if n["id"] in referenced]
        return {"nodes": nodes, "edges": kept_edges, "truncated": truncated}

    # -- campaigns ----------------------------------------------------------------

    def campaigns_for(self, entity_id: str, scope_investigation_id: int | None = None) -> list[dict]:
        """Campaigns linked to this entity via assessments, with their technique count and date range.

        Returned sorted by technique count DESC then name. Each row carries ``techniques`` (how many
        distinct attack-patterns the campaign is linked to via ``uses``) so the UI can tell apart a
        campaign Argus knows well from one it has barely scraped. ``first_seen``/``last_seen`` come
        from the strongest assessment that ties the entity to the campaign.
        """
        scope_sql, scope_params = (
            _investigation_claim_filter(scope_investigation_id, "a")
            if scope_investigation_id is not None else ("", ())
        )
        # `first_seen` is not always populated; the UI falls back to `last_seen` and vice versa, so
        # we coalesce. The MIN/MAX subqueries scope to every assessment the campaign is a party to,
        # so the date range reflects the campaign's own activity window, not just when it was attributed.
        #
        # `techniques` counts distinct attack-patterns reachable from the campaign in two ways:
        #   1. Direct (campaign uses technique) — rare in practice: Analyst usually attaches `uses` to
        #      the attributed actor, not the campaign itself.
        #   2. Via the attributed intrusion-set (campaign attributed-to group, group uses technique).
        # Union+DISTINCT so a TTP attached both ways only counts once.
        rows = self._conn.execute(
            f"""SELECT DISTINCT e.id, e.canonical_name AS name, e.external_id,
                       (SELECT MIN(COALESCE(first_seen, last_seen)) FROM assessments ax
                        WHERE ax.subject_entity_id = e.id OR ax.object_entity_id = e.id) AS first_seen,
                       (SELECT MAX(COALESCE(last_seen, first_seen)) FROM assessments ax
                        WHERE ax.subject_entity_id = e.id OR ax.object_entity_id = e.id) AS last_seen,
                       (SELECT COUNT(*) FROM (
                            SELECT at.object_entity_id AS ap FROM assessments at
                            JOIN entities te ON te.id = at.object_entity_id
                            WHERE at.subject_entity_id = e.id AND at.predicate = 'uses'
                              AND te.stix_type = 'attack-pattern'
                            UNION
                            SELECT at2.object_entity_id AS ap FROM assessments ar
                            JOIN assessments at2 ON at2.subject_entity_id = ar.object_entity_id
                            JOIN entities te2 ON te2.id = at2.object_entity_id
                            WHERE ar.subject_entity_id = e.id AND ar.predicate = 'attributed-to'
                              AND at2.predicate = 'uses' AND te2.stix_type = 'attack-pattern'
                       )) AS techniques
                FROM entities e JOIN assessments a
                  ON (a.subject_entity_id = e.id OR a.object_entity_id = e.id)
                WHERE e.stix_type = 'campaign'
                  AND (a.subject_entity_id = ? OR a.object_entity_id = ?)
                  AND e.id <> ?
                  {scope_sql}
                ORDER BY techniques DESC, name COLLATE NOCASE""",
            (entity_id, entity_id, entity_id, *scope_params),
        ).fetchall()
        return [
            {
                "id": r["id"], "name": r["name"], "external_id": r["external_id"],
                "label": _label(r["name"], r["external_id"]),
                "first_seen": r["first_seen"], "last_seen": r["last_seen"],
                "techniques": r["techniques"] or 0,
            }
            for r in rows
        ]

    # -- reference data and sources ------------------------------------------------

    def attack_counts(self) -> dict:
        rows = self._conn.execute(
            f"SELECT stix_type, COUNT(*) FROM entities WHERE id IN ({_ATTACK_ALIAS}) GROUP BY stix_type")
        by_type = {r[0]: r[1] for r in rows}
        return {
            "techniques": by_type.get("attack-pattern", 0),
            "groups": by_type.get("intrusion-set", 0),
            "software": by_type.get("malware", 0) + by_type.get("tool", 0),
        }

    def list_sources(self) -> list[dict]:
        rows = self._conn.execute(
            """SELECT p.id, p.name, p.domain, p.reliability,
                      (SELECT COUNT(*) FROM documents d
                       WHERE d.publisher_id = p.id OR d.primary_publisher_id = p.id) AS documents
               FROM publishers p ORDER BY p.name COLLATE NOCASE""")
        return [dict(r) for r in rows]

    # -- documents -----------------------------------------------------------------

    _DOCUMENT_COLUMNS = """d.id, d.title, p.name AS publisher, d.stage, d.published_at, d.retrieved_at,
                           d.failure_reason, d.url, d.local_path"""

    @staticmethod
    def _document_row(row: sqlite3.Row) -> dict:
        # PureWindowsPath splits on both separators on any OS: a path ingested on Windows is browsed on POSIX too.
        location = row["url"] or (PureWindowsPath(row["local_path"]).name if row["local_path"] else None)
        return {
            "id": row["id"], "title": row["title"], "publisher": row["publisher"], "stage": row["stage"],
            "published_at": row["published_at"], "retrieved_at": row["retrieved_at"],
            "failure_reason": row["failure_reason"], "location": location,
        }

    def list_documents(self, stage: str = "", q: str = "", limit: int = 100) -> list[dict]:
        rows = self._conn.execute(
            f"""SELECT {self._DOCUMENT_COLUMNS} FROM documents d
                JOIN publishers p ON p.id = d.publisher_id
                WHERE (? = '' OR d.stage = ?)
                  AND (? = '' OR instr(lower(d.title), lower(?)) > 0 OR instr(lower(p.name), lower(?)) > 0
                       OR instr(lower(COALESCE(d.url, '')), lower(?)) > 0)
                ORDER BY d.id DESC LIMIT ?""",
            (stage, stage, q, q, q, q, max(1, min(limit, 1000))),
        )
        return [self._document_row(r) for r in rows]

    def document_detail(self, document_id: int) -> dict | None:
        row = self._conn.execute(
            f"""SELECT {self._DOCUMENT_COLUMNS}, d.text FROM documents d
                JOIN publishers p ON p.id = d.publisher_id WHERE d.id = ?""",
            (document_id,),
        ).fetchone()
        if row is None:
            return None
        text = row["text"]
        claim_rows = self._conn.execute(
            "SELECT * FROM claims WHERE document_id = ? ORDER BY id", (document_id,)).fetchall()
        # One locator per document: building it costs about 0.5 s per MB of text, and only verified quotes use it.
        locator = QuoteLocator(text) if any(c["quote_status"] in _LOCATABLE for c in claim_rows) else None
        claims = []
        for c in claim_rows:
            span = None
            if locator is not None and c["quote_status"] in _LOCATABLE:
                span = locator.locate(c["quote"], self._fuzzy_threshold)
            claims.append({
                "id": c["id"], "subject": c["subject_ref"], "predicate": c["predicate"], "object": c["object_ref"],
                "quote": c["quote"], "quote_status": c["quote_status"], "polarity": c["polarity"],
                "span": list(span) if span else None,
            })
        return {**self._document_row(row), "text": text, "claims": claims}

    # -- token usage ---------------------------------------------------------------

    def token_usage(self, investigation_id: int) -> dict:
        """LLM input/output tokens, cost and call count aggregated per stage, plus a `total`.

        Rows missing a model (purely deterministic events, like most Validator work) do not contribute
        and are not counted as calls. Cost is `cost_usd` as recorded; local-model events (``ollama/*``)
        contribute tokens but 0 cost, which the UI shows as "free".
        """
        rows = self._conn.execute(
            """SELECT stage, COUNT(*) AS calls,
                      COALESCE(SUM(input_tokens), 0) AS input_tokens,
                      COALESCE(SUM(output_tokens), 0) AS output_tokens,
                      COALESCE(SUM(cost_usd), 0) AS cost_usd
               FROM pipeline_events WHERE investigation_id = ? AND model IS NOT NULL
               GROUP BY stage ORDER BY stage""",
            (investigation_id,),
        ).fetchall()
        by_stage = {
            r["stage"]: {
                "calls": r["calls"], "input_tokens": r["input_tokens"], "output_tokens": r["output_tokens"],
                "total_tokens": r["input_tokens"] + r["output_tokens"], "cost_usd": round(r["cost_usd"], 6),
            }
            for r in rows
        }
        total = {
            "calls": sum(s["calls"] for s in by_stage.values()),
            "input_tokens": sum(s["input_tokens"] for s in by_stage.values()),
            "output_tokens": sum(s["output_tokens"] for s in by_stage.values()),
            "total_tokens": sum(s["total_tokens"] for s in by_stage.values()),
            "cost_usd": round(sum(s["cost_usd"] for s in by_stage.values()), 6),
        }
        return {"by_stage": by_stage, "total": total}

    # -- investigations ------------------------------------------------------------

    def list_investigations(self, limit: int = 50) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM investigations ORDER BY id DESC LIMIT ?", (max(1, min(limit, 500)),))
        return [self._investigation_row(r) for r in rows]

    def investigation_detail(self, investigation_id: int) -> dict | None:
        row = self._conn.execute("SELECT * FROM investigations WHERE id = ?", (investigation_id,)).fetchone()
        if row is None:
            return None
        documents = [self._document_row(r) for r in self._conn.execute(
            f"""SELECT {self._DOCUMENT_COLUMNS} FROM documents d
                JOIN publishers p ON p.id = d.publisher_id
                JOIN investigation_documents l ON l.document_id = d.id
                WHERE l.investigation_id = ? ORDER BY d.id""",
            (investigation_id,))]
        failures = [{"title": d["title"], "reason": d["failure_reason"] or ""}
                    for d in documents if d["stage"] == "failed"]
        return {**self._investigation_row(row), "documents": documents, "failures": failures}

    def _entity_block(self, entity_id: str) -> dict | None:
        row = self._conn.execute(
            "SELECT id, stix_type, canonical_name, external_id FROM entities WHERE id = ?", (entity_id,)).fetchone()
        if row is None:
            return None
        return {
            "id": row["id"], "stix_type": row["stix_type"], "name": row["canonical_name"],
            "external_id": row["external_id"], "attack": bool(self._attack_ids([row["id"]])),
            "aliases": self.aliases_with_origin(row["id"]),
        }

    def investigation_dashboard(self, investigation_id: int, catalog: AttackCatalog | None,
                                failure_reason: str | None = None,
                                scope_investigation_id: int | None = None) -> dict | None:
        """The dashboard payload: header, resolved entity and ATT&CK matrix. None for an unknown investigation.

        `failure_reason` is not stored in the database; the caller supplies it when it knows one.
        With `scope_investigation_id` the matrix keeps only what that investigation's own claims support.
        """
        row = self._conn.execute("SELECT * FROM investigations WHERE id = ?", (investigation_id,)).fetchone()
        if row is None:
            return None
        entity = self._entity_block(row["resolved_entity_id"]) if row["resolved_entity_id"] else None
        if entity is not None and catalog is not None:
            tactics = build_matrix(self._conn, catalog, entity["id"], scope_investigation_id)
        else:
            tactics = [{"id": tid, "name": name, "techniques": []} for tid, name in TACTICS]
        return {
            "investigation": {
                "id": row["id"], "target": row["target"], "state": row["state"],
                "started_at": row["started_at"], "finished_at": row["finished_at"],
                "failure_reason": failure_reason, "counts": self._stage_counts(row["id"]),
                "token_usage": self.token_usage(row["id"]),
                "paused_reason": row["paused_reason"] if "paused_reason" in row.keys() else None,
            },
            "entity": entity,
            "attack_matrix": {"tactics": tactics},
            "scope": "everything" if scope_investigation_id is None else f"investigation:{scope_investigation_id}",
        }

    def investigation_exists(self, investigation_id: int) -> bool:
        return self._conn.execute("SELECT 1 FROM investigations WHERE id = ?", (investigation_id,)).fetchone() is not None

    # -- pipeline trace ------------------------------------------------------------

    def trace_summary(self, investigation_id: int, raw_allowed: bool = True) -> dict | None:
        """The trace payload of an investigation, or None when it does not exist.

        `raw_allowed` is the current `retain_raw_llm` flag: with it off, `has_raw` is forced false because the raw
        endpoint would answer 404.
        """
        if self._conn.execute("SELECT 1 FROM investigations WHERE id = ?", (investigation_id,)).fetchone() is None:
            return None
        with_raw = {r[0] for r in self._conn.execute(
            "SELECT id FROM pipeline_events WHERE investigation_id = ? AND raw_response IS NOT NULL",
            (investigation_id,))}
        events = SQLiteTraceRecorder(self._conn, retain_raw=False).list_events(investigation_id)
        llm = [e for e in events if e.usage is not None]
        cost = None
        if llm:
            cost = {
                "input_tokens": sum(e.usage.input_tokens for e in llm),
                "output_tokens": sum(e.usage.output_tokens for e in llm),
                "usd": sum(e.cost_usd or 0.0 for e in llm),
                "duration_ms": sum(e.duration_ms or 0 for e in llm),
            }
        doc_ids = sorted({e.document_id for e in events if e.document_id is not None})
        documents = [
            {"id": r[0], "title": r[1]}
            for r in self._conn.execute(
                f"SELECT id, title FROM documents WHERE id IN ({','.join('?' * len(doc_ids))}) ORDER BY id", doc_ids)
        ] if doc_ids else []
        return {
            "cost": cost,
            "documents": documents,
            "events": [
                {
                    "id": e.id, "document_id": e.document_id, "stage": e.stage, "decision": e.decision,
                    "reason": e.reason, "created_at": e.created_at.isoformat(), "duration_ms": e.duration_ms,
                    "usage": e.usage.model_dump() if e.usage else None,
                    "has_raw": raw_allowed and e.id in with_raw,
                }
                for e in events
            ],
        }

    def recent_events(
        self, limit: int = 100, kind_filter: str | None = None, since: str | None = None,
        per_stage_limit: int | None = None,
    ) -> list[dict]:
        """Pipeline events across all investigations, newest first.

        `kind_filter` selects one stage (collector, triage, analyst, validator, pipeline); `since` is an ISO timestamp
        in UTC, compared as text against `created_at`, which is stored the same way. `per_stage_limit`, when set,
        returns up to that many events per stage so a chatty validator does not crowd out quieter stages — the overall
        result is still sorted newest-first and capped at `limit`.
        """
        if per_stage_limit is not None:
            stages = ("collector", "triage", "analyst", "validator", "pipeline")
            merged: list[dict] = []
            for stage in stages:
                merged.extend(self.recent_events(per_stage_limit, kind_filter=stage, since=since))
            merged.sort(key=lambda event: (event["created_at"], event["id"]), reverse=True)
            return merged[:limit]
        clauses, params = [], []
        if kind_filter:
            clauses.append("e.stage = ?")
            params.append(kind_filter)
        if since:
            clauses.append("e.created_at >= ?")
            params.append(since)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = self._conn.execute(
            "SELECT e.id, e.investigation_id, i.target, e.document_id, d.title, e.stage, e.decision, e.reason,"
            " e.created_at, e.duration_ms, e.input_tokens, e.output_tokens, e.cost_usd"
            " FROM pipeline_events e JOIN investigations i ON i.id = e.investigation_id"
            " LEFT JOIN documents d ON d.id = e.document_id"
            f"{where} ORDER BY e.created_at DESC, e.id DESC LIMIT ?",
            (*params, max(0, limit)),
        ).fetchall()
        keys = ("id", "investigation_id", "investigation_target", "document_id", "document_title", "stage", "decision",
                "reason", "created_at", "duration_ms", "input_tokens", "output_tokens", "cost_usd")
        return [dict(zip(keys, row, strict=False)) for row in rows]

    def trace_raw(self, investigation_id: int, event_id: int) -> tuple[str, str] | None:
        """The raw prompt and response of one event of this investigation, when stored."""
        row = self._conn.execute(
            "SELECT raw_prompt, raw_response FROM pipeline_events WHERE id = ? AND investigation_id = ?",
            (event_id, investigation_id),
        ).fetchone()
        if row is None or row[0] is None or row[1] is None:
            return None
        return row[0], row[1]
