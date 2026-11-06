"""SQLite implementation of the knowledge store.

Its public methods are the KnowledgeStore interface used by the pipeline, CLI and exporters.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from collections.abc import Collection, Iterator
from contextlib import contextmanager
from datetime import UTC, date, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

from cyllex_argus.knowledge.models import (
    TLP,
    TLP_ORDER,
    AliasOrigin,
    AnalyticConfidence,
    Assessment,
    AssessmentStatus,
    Citation,
    Claim,
    ClaimDraft,
    Document,
    DocumentCoverage,
    Entity,
    Evidence,
    Investigation,
    InvestigationState,
    NewDocument,
    Polarity,
    Publisher,
    QuoteStatus,
    Role,
    Stage,
    User,
)
from cyllex_argus.knowledge.names import normalize_name
from cyllex_argus.knowledge.publisher_identity import organisation_key
from cyllex_argus.knowledge.schema import MIGRATIONS
from cyllex_argus.knowledge.scope import investigation_claim_filter
from cyllex_argus.knowledge.summaries import StoredSummary

if TYPE_CHECKING:  # imported lazily at runtime inside the schedule methods
    from cyllex_argus.knowledge.models import ScheduledInvestigation, Watcher, WatcherChange

_ORIGIN_PRIORITY = "CASE a.origin WHEN 'attack' THEN 0 WHEN 'user' THEN 1 ELSE 2 END"
_EFFECTIVE_PUBLISHER_JOIN = """
    JOIN documents d ON d.id = c.document_id
    JOIN publishers p ON p.id = COALESCE(d.primary_publisher_id, d.publisher_id)
"""


def _iso(value: date | datetime | None) -> str | None:
    return value.isoformat() if value else None


def _date(value: str | None) -> date | None:
    return date.fromisoformat(value) if value else None


def _datetime(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


def _now() -> datetime:
    return datetime.now(UTC)


class _Rows:
    """A cursor's result, read inside the store lock.

    Quacks like the `sqlite3.Cursor` the callers used to get for everything they do with it:
    `fetchone`, `fetchall`, `fetchmany`, iteration, `lastrowid`, `rowcount` and `description`.
    The rows are already in hand, so fetching from it after the lock is released is safe.
    """

    __slots__ = ("_rows", "_index", "lastrowid", "rowcount", "description")

    def __init__(self, cursor: sqlite3.Cursor) -> None:
        # fetchall() runs while the caller still holds the lock (see _LockedConnection.execute).
        # A non-SELECT statement yields [], which is what its cursor would have given anyway.
        self._rows: list = cursor.fetchall()
        self._index = 0
        self.lastrowid = cursor.lastrowid
        self.rowcount = cursor.rowcount
        self.description = cursor.description

    def fetchone(self):
        if self._index >= len(self._rows):
            return None
        row = self._rows[self._index]
        self._index += 1
        return row

    def fetchall(self) -> list:
        rows = self._rows[self._index:]
        self._index = len(self._rows)
        return rows

    def fetchmany(self, size: int = 1) -> list:
        rows = self._rows[self._index:self._index + size]
        self._index += len(rows)
        return rows

    def __iter__(self):
        return iter(self.fetchall())

    # Deliberately no __len__: a real sqlite3.Cursor has none, so defining one here would make
    # `if store.connection.execute(...)` mean "has rows" on this object and "always true" on a
    # bare connection. Callers ask with fetchone()/fetchall().


class _LockedConnection:
    """Wraps a sqlite3.Connection with a reentrant lock so threads do not step on each other.

    `sqlite3.connect(..., check_same_thread=False)` suppresses the thread check, but a
    concurrent write between two threads still trips `InterfaceError: bad parameter or
    other API misuse` because the underlying connection is not thread-safe. The fix is a
    `threading.RLock` held around every mutating entry point: `execute`, `executemany`,
    `executescript`, `commit`, `rollback`, `close`, and the transaction context manager.
    SQLite's internal engine then serialises writes, which is exactly what we want for
    the pipeline — the real speedup lives in the parallel LLM calls (seconds), not in
    the millisecond writes they produce. The reentrant lock lets callers nest (a `with
    conn:` block that itself issues `conn.execute(...)` is normal and expected).

    Reads hold the lock across `execute` AND the fetch, and hand back the rows already
    materialised (`_Rows`). Holding it around `execute` alone was not enough: a cursor from a
    shared connection is not independent of that connection, so another thread's `execute`
    landing between this thread's `execute` and its `fetchone()` left the fetch returning None
    for a row that exists. The pipeline believed it — `get_document` raised `KeyError` for a
    document it had just collected, and claims were stored with no subject and no object
    because their lookups "found nothing". See tests/knowledge/test_store_threads.py.

    The cost is that a result set is read into memory in full rather than streamed. Every
    caller here already ended in `fetchone()`/`fetchall()`, and the few that iterate do so
    over bounded queries, so nothing changes in practice — but a new caller that wants to
    stream a large table should take `atomic()` and work with the raw connection instead.
    """

    __slots__ = ("_conn", "_lock")

    def __init__(self, conn: sqlite3.Connection, lock: threading.RLock) -> None:
        self._conn = conn
        self._lock = lock

    def execute(self, *args, **kwargs):
        with self._lock:
            return _Rows(self._conn.execute(*args, **kwargs))

    def executemany(self, *args, **kwargs):
        with self._lock:
            return _Rows(self._conn.executemany(*args, **kwargs))

    def executescript(self, *args, **kwargs):
        with self._lock:
            return _Rows(self._conn.executescript(*args, **kwargs))

    def commit(self) -> None:
        with self._lock:
            self._conn.commit()

    def rollback(self) -> None:
        with self._lock:
            self._conn.rollback()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def __enter__(self) -> _LockedConnection:
        self._lock.acquire()
        try:
            self._conn.__enter__()
        except BaseException:
            self._lock.release()
            raise
        return self

    def __exit__(self, exc_type, exc, tb) -> bool | None:
        try:
            return self._conn.__exit__(exc_type, exc, tb)
        finally:
            self._lock.release()

    @property
    def row_factory(self):
        return self._conn.row_factory

    @row_factory.setter
    def row_factory(self, value) -> None:
        self._conn.row_factory = value

    @property
    def in_transaction(self) -> bool:
        return self._conn.in_transaction

    @property
    def total_changes(self) -> int:
        return self._conn.total_changes


class SQLiteStore:
    def __init__(self, db_path: Path | str) -> None:
        # `check_same_thread=False` lets a single connection be used from multiple threads,
        # which the pipeline's thread-pool parallelism (opt-in via `--concurrency`) relies on.
        # The connection itself is NOT thread-safe out of the box (a concurrent write between
        # two threads trips `InterfaceError`); the `_LockedConnection` wrapper above serialises
        # every mutating entry point so SQLite sees one caller at a time. The reentrant lock
        # keeps `with conn:` + nested `conn.execute(...)` patterns valid.
        raw_conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._lock: threading.RLock = threading.RLock()
        self._conn = _LockedConnection(raw_conn, self._lock)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.execute("PRAGMA journal_mode = WAL")
        self._conn.execute("PRAGMA synchronous = NORMAL")
        try:
            self._migrate()
        except Exception:
            self._conn.close()
            raise

    # -- lifecycle -----------------------------------------------------------------

    @property
    def connection(self) -> sqlite3.Connection:
        return self._conn

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> SQLiteStore:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _migrate(self) -> None:
        self._conn.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)")
        current = self.schema_version()
        for version, sql in enumerate(MIGRATIONS, start=1):
            if version > current:
                try:
                    self._conn.executescript(f"BEGIN;\n{sql}\nINSERT INTO schema_version (version) VALUES ({version});\nCOMMIT;")
                except Exception:
                    self._conn.rollback()
                    raise

    @contextmanager
    def atomic(self) -> Iterator[None]:
        """Hold the store's lock across several statements.

        `_LockedConnection` serialises each individual statement, which keeps SQLite from
        tripping `InterfaceError`, but it does NOT make a read-then-write pair atomic: two
        threads can both read "this row does not exist" and both insert it. Every find-or-create
        on this store runs inside this block.

        The lock is the same `threading.RLock` the connection wrapper uses and it is reentrant,
        so nesting this around calls that lock internally is safe. Never `await`, call an LLM or
        touch the network inside it — it is for store work only, which is microseconds.
        """
        with self._lock:
            yield

    def schema_version(self) -> int:
        row = self._conn.execute("SELECT MAX(version) FROM schema_version").fetchone()
        return row[0] or 0

    # -- publishers ----------------------------------------------------------------

    @staticmethod
    def _publisher(row: sqlite3.Row) -> Publisher:
        keys = row.keys()
        tlp_raw = row["tlp"] if "tlp" in keys else None
        return Publisher(
            id=row["id"], name=row["name"], domain=row["domain"], reliability=row["reliability"],
            tlp=TLP(tlp_raw) if tlp_raw else None,
            org_key=row["org_key"] if "org_key" in keys else None,
        )

    def get_or_create_publisher(
        self, name: str, domain: str | None = None, default_reliability: str = "F"
    ) -> Publisher:
        """Find (or create) the row for one ORGANISATION, and record the byline it was seen under.

        Resolution is domain first, byline second. `organisation_key` answers "does this domain
        stand for a single organisation?", and only when it does not — a bare name, a blogging
        platform — does the byline decide identity. That ordering is what keeps "CISA" and
        "Cybersecurity and Infrastructure Security Agency" from becoming two independent sources
        that corroborate each other, because `scoring.score` counts independence by publisher row.

        Atomic: the Analyst reports a document's primary publisher from the thread pool, so two
        documents from the same publisher used to be able to create two publisher rows — and
        publisher identity is what independent-source counting, and therefore corroboration,
        is computed from.
        """
        key = normalize_name(name) or normalize_name(domain or "") or "unknown"
        org_key = organisation_key(domain)
        with self.atomic():
            row = None
            if org_key is not None:
                # Lowest id wins, deterministically: a store written before this resolution
                # existed can still hold several rows per organisation, and keeps them until the
                # operator runs `argus sources merge-duplicates`.
                row = self._conn.execute(
                    "SELECT * FROM publishers WHERE org_key = ? ORDER BY id LIMIT 1", (org_key,)
                ).fetchone()
            if row is None:
                row = self._conn.execute(
                    """SELECT p.* FROM publishers p
                         LEFT JOIN publisher_names n ON n.publisher_id = p.id
                        WHERE p.name_key = ? OR n.name_key = ?
                        ORDER BY p.id LIMIT 1""",
                    (key, key),
                ).fetchone()
            if row is not None:
                publisher_id = row["id"]
                # Backfill, both directions: a row written before migration 15 has no org_key,
                # and a row first created from a bare byline earns one the day a document
                # arrives carrying its domain. Neither overwrites a value already there.
                if org_key is not None and not row["org_key"]:
                    self._conn.execute(
                        "UPDATE publishers SET org_key = ? WHERE id = ?", (org_key, publisher_id)
                    )
                if domain and not row["domain"]:
                    self._conn.execute(
                        "UPDATE publishers SET domain = ? WHERE id = ?", (domain, publisher_id)
                    )
                self._register_publisher_name(publisher_id, key, name)
                self._conn.commit()
                return self.get_publisher(publisher_id)
            cur = self._conn.execute(
                "INSERT INTO publishers (name, name_key, domain, reliability, org_key)"
                " VALUES (?, ?, ?, ?, ?)",
                (name.strip() or key, key, domain, default_reliability, org_key),
            )
            self._register_publisher_name(cur.lastrowid, key, name)
            self._conn.commit()
            return self.get_publisher(cur.lastrowid)

    def _register_publisher_name(self, publisher_id: int, name_key: str, name: str) -> None:
        """Remember that this organisation published under this byline. Caller holds the lock.

        `OR IGNORE`, so the first row to claim a byline keeps it: a name that already resolves
        to another publisher is never silently re-pointed, which would move a document's
        apparent source without anyone asking.
        """
        self._conn.execute(
            "INSERT OR IGNORE INTO publisher_names (name_key, publisher_id, name) VALUES (?, ?, ?)",
            (name_key, publisher_id, name.strip() or name_key),
        )

    def get_publisher(self, publisher_id: int) -> Publisher:
        row = self._conn.execute("SELECT * FROM publishers WHERE id = ?", (publisher_id,)).fetchone()
        if row is None:
            raise KeyError(publisher_id)
        return self._publisher(row)

    def list_publishers(self) -> list[Publisher]:
        rows = self._conn.execute("SELECT * FROM publishers ORDER BY name COLLATE NOCASE").fetchall()
        return [self._publisher(r) for r in rows]

    def publisher_names(self, publisher_id: int) -> list[str]:
        """Every byline seen for this publisher, alphabetically.

        A merged row covers several bylines, and which ones matters: the row is the unit of
        independence, so an operator rating it needs to see whose reporting it speaks for.
        """
        rows = self._conn.execute(
            "SELECT name FROM publisher_names WHERE publisher_id = ? ORDER BY name COLLATE NOCASE",
            (publisher_id,),
        ).fetchall()
        return [row["name"] for row in rows]

    def publisher_id_by_name(self, name: str) -> int:
        """Resolve a publisher by any byline it has ever published under.

        Not only the row's current name: after a merge the operator still reads the old byline
        in a document, and `argus sources set-reliability "<that byline>"` has to keep working.
        """
        key = normalize_name(name)
        row = self._conn.execute(
            """SELECT p.id AS id FROM publishers p
                 LEFT JOIN publisher_names n ON n.publisher_id = p.id
                WHERE p.name_key = ? OR n.name_key = ?
                ORDER BY p.id LIMIT 1""",
            (key, key),
        ).fetchone()
        if row is None:
            raise KeyError(name)
        return row["id"]

    def backfill_publisher_org_keys(self) -> int:
        """Persist the derived organisation of every row that has none yet. Returns rows updated.

        The derivation itself lives in `publisher_merge.organisation_keys`, which is read-only and
        is what discovery and the health endpoint use. Storing it is an optimisation and a record
        of what the merge decided — never a prerequisite for finding duplicates.
        """
        from cyllex_argus.knowledge.publisher_merge import organisation_keys
        with self.atomic():
            keys = organisation_keys(self._conn)
            rows = self._conn.execute("SELECT id FROM publishers WHERE org_key IS NULL").fetchall()
            updated = 0
            for row in rows:
                key = keys.get(row["id"])
                if key is None:
                    continue
                self._conn.execute("UPDATE publishers SET org_key = ? WHERE id = ?", (key, row["id"]))
                updated += 1
            self._conn.commit()
            return updated

    def merge_publishers(self, keep_id: int, drop_ids: Collection[int]) -> int:
        """Fold `drop_ids` into `keep_id`. Returns the number of document references repointed.

        Does NOT recompute assessments — callers do. A merge changes how many independent
        sources a fact has, so every assessment that cited any of these rows has to be rescored,
        and the store does not own the Validator.

        Where the rows disagree the merged row takes the answer a human most likely meant: the
        strongest reliability in the group, because a letter other than the default F was set
        deliberately and resetting it would discard that judgement, and the most restrictive TLP,
        because that is the safe direction for an export filter. Every byline survives in
        `publisher_names`, so the merge loses no evidence about who reported what.
        """
        drop = [i for i in dict.fromkeys(drop_ids) if i != keep_id]
        if not drop:
            return 0
        placeholders = ",".join("?" * len(drop))
        with self.atomic():
            keep = self._conn.execute("SELECT * FROM publishers WHERE id = ?", (keep_id,)).fetchone()
            if keep is None:
                raise KeyError(keep_id)
            others = self._conn.execute(
                f"SELECT * FROM publishers WHERE id IN ({placeholders})", tuple(drop)
            ).fetchall()
            if len(others) != len(drop):
                missing = sorted(set(drop) - {row["id"] for row in others})
                raise KeyError(missing[0])
            group = [keep, *others]
            reliability = min((row["reliability"] for row in group), key="ABCDEF".index)
            labels = [row["tlp"] for row in group if row["tlp"]]
            tlp = max(labels, key=lambda value: TLP_ORDER.get(value, -1)) if labels else None
            domain = keep["domain"] or next((row["domain"] for row in others if row["domain"]), None)
            org_key = keep["org_key"] or next((row["org_key"] for row in others if row["org_key"]), None)

            moved = 0
            for column in ("publisher_id", "primary_publisher_id"):
                cursor = self._conn.execute(
                    f"UPDATE documents SET {column} = ? WHERE {column} IN ({placeholders})",
                    (keep_id, *drop),
                )
                moved += cursor.rowcount or 0
            self._conn.execute(
                f"UPDATE publisher_names SET publisher_id = ? WHERE publisher_id IN ({placeholders})",
                (keep_id, *drop),
            )
            self._conn.execute(
                "UPDATE publishers SET reliability = ?, tlp = ?, domain = ?, org_key = ? WHERE id = ?",
                (reliability, tlp, domain, org_key, keep_id),
            )
            self._conn.execute(f"DELETE FROM publishers WHERE id IN ({placeholders})", tuple(drop))
            self._conn.commit()
            return moved

    def set_publisher_reliability(self, name: str, reliability: str) -> Publisher:
        """Grade the publisher that publishes under this byline."""
        return self.grade_publisher(self.publisher_id_by_name(name), reliability)

    def grade_publisher(self, publisher_id: int, reliability: str) -> Publisher:
        """Grade a publisher by id, for callers that already hold the row.

        The byline path is right for an operator typing a name and wrong for a loop over
        `list_publishers`, where resolving a name back to a row can only lose.
        """
        self._conn.execute(
            "UPDATE publishers SET reliability = ? WHERE id = ?", (reliability, publisher_id)
        )
        self._conn.commit()
        return self.get_publisher(publisher_id)

    def set_publisher_tlp(self, name: str, tlp: TLP | None) -> Publisher:
        """Attach (or clear) a TLP label on a publisher. Pass `None` to clear."""
        publisher_id = self.publisher_id_by_name(name)
        self._conn.execute(
            "UPDATE publishers SET tlp = ? WHERE id = ?",
            (tlp.value if tlp is not None else None, publisher_id),
        )
        self._conn.commit()
        return self.get_publisher(publisher_id)

    def claim_publisher_ids_above_tlp(self, cap: TLP) -> set[int]:
        """Publisher ids whose TLP is strictly higher than `cap`. Used by `argus export --tlp-cap`
        to decide which claims to drop. Publishers with no TLP (NULL) are not above anything —
        callers decide separately how to handle unclassified sources."""
        rows = self._conn.execute(
            "SELECT id, tlp FROM publishers WHERE tlp IS NOT NULL",
        ).fetchall()
        cap_rank = TLP_ORDER[cap.value]
        return {row["id"] for row in rows if TLP_ORDER.get(row["tlp"], -1) > cap_rank}

    # -- documents -----------------------------------------------------------------

    @staticmethod
    def _document(row: sqlite3.Row) -> Document:
        return Document(
            id=row["id"],
            url=row["url"],
            local_path=row["local_path"],
            canonical_url=row["canonical_url"],
            title=row["title"],
            publisher_id=row["publisher_id"],
            primary_publisher_id=row["primary_publisher_id"],
            published_at=_date(row["published_at"]),
            retrieved_at=_datetime(row["retrieved_at"]),
            content_hash=row["content_hash"],
            raw_path=row["raw_path"],
            text=row["text"],
            stage=Stage(row["stage"]),
            failure_reason=row["failure_reason"],
            analyzed_prompt_version=row["analyzed_prompt_version"],
        )

    def add_document(
        self, new: NewDocument, stage: Stage = Stage.COLLECTED, failure_reason: str | None = None
    ) -> tuple[Document, bool]:
        row = self._conn.execute(
            "SELECT * FROM documents WHERE content_hash = ? OR (canonical_url IS NOT NULL AND canonical_url = ?)",
            (new.content_hash, new.canonical_url),
        ).fetchone()
        if row:
            return self._document(row), False
        cur = self._conn.execute(
            """INSERT INTO documents (url, local_path, canonical_url, title, publisher_id, published_at,
                   retrieved_at, content_hash, raw_path, text, stage, failure_reason)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                new.url, new.local_path, new.canonical_url, new.title, new.publisher_id,
                _iso(new.published_at), _iso(_now()), new.content_hash, new.raw_path, new.text,
                stage.value, failure_reason,
            ),
        )
        self._conn.commit()
        return self.get_document(cur.lastrowid), True

    def get_document(self, document_id: int) -> Document:
        row = self._conn.execute("SELECT * FROM documents WHERE id = ?", (document_id,)).fetchone()
        if row is None:
            raise KeyError(document_id)
        return self._document(row)

    def find_document_by_canonical_url(self, canonical_url: str) -> Document | None:
        row = self._conn.execute(
            "SELECT * FROM documents WHERE canonical_url = ?", (canonical_url,)
        ).fetchone()
        return self._document(row) if row else None

    def update_document_content(self, document_id: int, new: NewDocument) -> Document:
        """Replace a document's content (for example a failed download that now succeeds) and reset its stage.

        If the new content already belongs to ANOTHER document, that document is returned and nothing changes.
        """
        other = self._conn.execute(
            "SELECT * FROM documents WHERE content_hash = ? AND id != ?", (new.content_hash, document_id)
        ).fetchone()
        if other:
            return self._document(other)
        self._conn.execute(
            """UPDATE documents SET url = ?, title = ?, publisher_id = ?, published_at = ?, retrieved_at = ?,
                   content_hash = ?, raw_path = ?, text = ?, stage = ?, failure_reason = NULL,
                   analyzed_prompt_version = NULL
               WHERE id = ?""",
            (
                new.url, new.title, new.publisher_id, _iso(new.published_at), _iso(_now()),
                new.content_hash, new.raw_path, new.text, Stage.COLLECTED.value, document_id,
            ),
        )
        self._conn.commit()
        return self.get_document(document_id)

    def set_stage(self, document_id: int, stage: Stage, failure_reason: str | None = None) -> None:
        self._conn.execute(
            "UPDATE documents SET stage = ?, failure_reason = ? WHERE id = ?",
            (stage.value, failure_reason, document_id),
        )
        self._conn.commit()

    def set_analysis(self, document_id: int, primary_publisher_id: int, prompt_version: str) -> None:
        self._conn.execute(
            "UPDATE documents SET primary_publisher_id = ?, analyzed_prompt_version = ? WHERE id = ?",
            (primary_publisher_id, prompt_version, document_id),
        )
        self._conn.commit()

    # -- investigations ------------------------------------------------------------

    @staticmethod
    def _investigation(row: sqlite3.Row) -> Investigation:
        return Investigation(
            id=row["id"],
            target=row["target"],
            resolved_entity_id=row["resolved_entity_id"],
            started_at=_datetime(row["started_at"]),
            finished_at=_datetime(row["finished_at"]),
            state=InvestigationState(row["state"]),
            collected=bool(row["collected"]),
            created_by=row["created_by"] if "created_by" in row.keys() else None,
            paused_reason=row["paused_reason"] if "paused_reason" in row.keys() else None,
        )

    def create_investigation(
        self, target: str, resolved_entity_id: str | None = None, *, created_by: int | None = None,
    ) -> Investigation:
        cur = self._conn.execute(
            """INSERT INTO investigations (target, target_key, resolved_entity_id, started_at, state, created_by)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (target, normalize_name(target), resolved_entity_id, _iso(_now()),
             InvestigationState.RUNNING.value, created_by),
        )
        self._conn.commit()
        return self.get_investigation(cur.lastrowid)

    def get_investigation(self, investigation_id: int) -> Investigation:
        row = self._conn.execute(
            "SELECT * FROM investigations WHERE id = ?", (investigation_id,)
        ).fetchone()
        if row is None:
            raise KeyError(investigation_id)
        return self._investigation(row)

    def open_investigation(self, target: str) -> Investigation | None:
        row = self._conn.execute(
            "SELECT * FROM investigations WHERE target_key = ? AND state != ? ORDER BY id DESC LIMIT 1",
            (normalize_name(target), InvestigationState.FINISHED.value),
        ).fetchone()
        return self._investigation(row) if row else None

    def latest_investigation(self) -> Investigation | None:
        row = self._conn.execute("SELECT * FROM investigations ORDER BY id DESC LIMIT 1").fetchone()
        return self._investigation(row) if row else None

    def set_investigation_state(
        self, investigation_id: int, state: InvestigationState, *, reason: str | None = None,
    ) -> None:
        finished = _iso(_now()) if state is InvestigationState.FINISHED else None
        # Transitioning to RUNNING implicitly clears any pending cancel request AND any paused
        # reason — an operator who hits Resume after a Stop (or after orphan recovery) expects
        # the next run to actually run, and the UI banner that explained WHY it was paused is
        # no longer true.
        if state is InvestigationState.RUNNING:
            self._conn.execute(
                "UPDATE investigations SET state = ?, finished_at = ?, cancel_requested = 0, "
                "paused_reason = NULL WHERE id = ?",
                (state.value, finished, investigation_id),
            )
        elif state is InvestigationState.PAUSED and reason is not None:
            self._conn.execute(
                "UPDATE investigations SET state = ?, finished_at = ?, paused_reason = ? WHERE id = ?",
                (state.value, finished, reason, investigation_id),
            )
        else:
            # PAUSED without a reason (operator hit the Stop button) or FINISHED: leave the
            # existing paused_reason alone (NULL on operator-paused, carries the recovery string
            # if the operator later re-stops a recovered run).
            self._conn.execute(
                "UPDATE investigations SET state = ?, finished_at = ? WHERE id = ?",
                (state.value, finished, investigation_id),
            )
        self._conn.commit()

    def request_investigation_cancel(self, investigation_id: int) -> None:
        """Set the cancel flag; the pipeline sees it on its next between-docs check and stops.

        No-op when the investigation does not exist (cancel of a deleted row is harmless;
        the operator may have just hit DELETE on the UI). Idempotent."""
        self._conn.execute(
            "UPDATE investigations SET cancel_requested = 1 WHERE id = ?", (investigation_id,),
        )
        self._conn.commit()

    def is_investigation_cancel_requested(self, investigation_id: int) -> bool:
        """True when a cancel is pending or the investigation row no longer exists.

        Treating a deleted row as 'cancel' is deliberate: it tells the pipeline to stop
        touching stage/claim/trace rows that would otherwise fail their FK, and keeps the
        DELETE endpoint synchronous (DELETE sets the flag, deletes the row; the pipeline
        notices on the next check and exits cleanly)."""
        row = self._conn.execute(
            "SELECT cancel_requested FROM investigations WHERE id = ?", (investigation_id,),
        ).fetchone()
        if row is None:
            return True
        return bool(row["cancel_requested"])

    def mark_collected(self, investigation_id: int) -> None:
        self._conn.execute("UPDATE investigations SET collected = 1 WHERE id = ?", (investigation_id,))
        self._conn.commit()

    def set_investigation_resolved_entity(self, investigation_id: int, entity_id: str | None) -> None:
        """Attach (or clear) the resolved entity of an investigation; useful when the target was learned mid-run."""
        self._conn.execute(
            "UPDATE investigations SET resolved_entity_id = ? WHERE id = ?",
            (entity_id, investigation_id),
        )
        self._conn.commit()

    def link_document(self, investigation_id: int, document_id: int) -> None:
        self._conn.execute(
            "INSERT OR IGNORE INTO investigation_documents (investigation_id, document_id) VALUES (?, ?)",
            (investigation_id, document_id),
        )
        self._conn.commit()

    def investigation_documents(self, investigation_id: int) -> list[Document]:
        rows = self._conn.execute(
            """SELECT d.* FROM documents d
               JOIN investigation_documents l ON l.document_id = d.id
               WHERE l.investigation_id = ? ORDER BY d.id""",
            (investigation_id,),
        ).fetchall()
        return [self._document(r) for r in rows]

    def stage_counts(self, investigation_id: int) -> dict[str, int]:
        rows = self._conn.execute(
            """SELECT d.stage, COUNT(*) AS n FROM documents d
               JOIN investigation_documents l ON l.document_id = d.id
               WHERE l.investigation_id = ? GROUP BY d.stage ORDER BY d.stage""",
            (investigation_id,),
        ).fetchall()
        return {r["stage"]: r["n"] for r in rows}

    def delete_investigation(self, investigation_id: int) -> None:
        """Remove an investigation and its exclusive documents. Knowledge (claims, assessments) survives.

        A document that no other investigation references is deleted with its claims. Claims that came from
        documents still shared with other investigations keep their rows but have their `investigation_id`
        cleared (the `ON DELETE SET NULL` on the column handles this). The investigation's pipeline events
        also cascade away via `ON DELETE CASCADE`. Raises KeyError when the id is unknown.
        """
        if self._conn.execute("SELECT 1 FROM investigations WHERE id = ?", (investigation_id,)).fetchone() is None:
            raise KeyError(investigation_id)
        orphan_ids = [row[0] for row in self._conn.execute(
            """SELECT d.id FROM documents d
               JOIN investigation_documents l ON l.document_id = d.id
               WHERE l.investigation_id = ?
                 AND NOT EXISTS (SELECT 1 FROM investigation_documents o
                                  WHERE o.document_id = d.id AND o.investigation_id <> ?)""",
            (investigation_id, investigation_id),
        )]
        self._conn.execute("DELETE FROM investigation_documents WHERE investigation_id = ?", (investigation_id,))
        if orphan_ids:
            marks = ",".join("?" for _ in orphan_ids)
            self._conn.execute(f"DELETE FROM claims WHERE document_id IN ({marks})", orphan_ids)
            self._conn.execute(f"DELETE FROM documents WHERE id IN ({marks})", orphan_ids)
        self._conn.execute("DELETE FROM investigations WHERE id = ?", (investigation_id,))
        self._conn.commit()

    def failures(self, investigation_id: int) -> list[tuple[str, str]]:
        rows = self._conn.execute(
            """SELECT d.title, d.failure_reason FROM documents d
               JOIN investigation_documents l ON l.document_id = d.id
               WHERE l.investigation_id = ? AND d.stage = ? ORDER BY d.id""",
            (investigation_id, Stage.FAILED.value),
        ).fetchall()
        return [(r["title"], r["failure_reason"] or "") for r in rows]

    def investigations_for_document(self, document_id: int) -> list[int]:
        """Investigations this document is linked to, newest first. Used by `retry_document`
        to pick a target for the triage/analyst re-run; a document ingested outside any
        investigation returns an empty list and gets retried without a target."""
        rows = self._conn.execute(
            """SELECT investigation_id FROM investigation_documents
               WHERE document_id = ? ORDER BY investigation_id DESC""",
            (document_id,),
        ).fetchall()
        return [r["investigation_id"] for r in rows]

    # -- users and sessions --------------------------------------------------------

    @staticmethod
    def _user(row: sqlite3.Row) -> User:
        return User(
            id=row["id"], username=row["username"], role=Role(row["role"]),
            disabled=bool(row["disabled"]), created_at=row["created_at"],
            created_by=row["created_by"], seeded_with_default=bool(row["seeded_with_default"]),
            deleted_at=row["deleted_at"],
        )

    def create_user(
        self, username: str, password_hash: str, role: Role, *,
        created_by: int | None = None, seeded_with_default: bool = False,
    ) -> User:
        key = username.strip().casefold()
        if not key:
            raise ValueError("username must not be empty")
        with self.atomic():
            cur = self._conn.execute(
                """INSERT INTO users (username_key, username, password_hash, role, created_at,
                                      created_by, seeded_with_default)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (key, username.strip(), password_hash, role.value, _iso(_now()), created_by,
                 1 if seeded_with_default else 0),
            )
            self._conn.commit()
            return self.get_user(cur.lastrowid)

    def get_user(self, user_id: int) -> User | None:
        row = self._conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return self._user(row) if row else None

    def get_user_by_username(self, username: str) -> User | None:
        row = self._conn.execute(
            "SELECT * FROM users WHERE username_key = ? AND deleted_at IS NULL",
            (username.strip().casefold(),),
        ).fetchone()
        return self._user(row) if row else None

    def list_users(self) -> list[User]:
        rows = self._conn.execute(
            "SELECT * FROM users WHERE deleted_at IS NULL ORDER BY id"
        ).fetchall()
        return [self._user(r) for r in rows]

    def set_user_role(self, user_id: int, role: Role) -> None:
        self._conn.execute("UPDATE users SET role = ? WHERE id = ?", (role.value, user_id))
        self._conn.commit()

    def set_user_disabled(self, user_id: int, disabled: bool) -> None:
        self._conn.execute(
            "UPDATE users SET disabled = ? WHERE id = ?", (1 if disabled else 0, user_id),
        )
        if disabled:  # a disabled user's live sessions die at once
            self._conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        self._conn.commit()

    def set_user_password(self, user_id: int, password_hash: str, *, clear_default: bool = True) -> None:
        if clear_default:
            self._conn.execute(
                "UPDATE users SET password_hash = ?, seeded_with_default = 0 WHERE id = ?",
                (password_hash, user_id),
            )
        else:
            self._conn.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?", (password_hash, user_id),
            )
        self._conn.commit()

    def user_password_hash(self, user_id: int) -> str | None:
        row = self._conn.execute(
            "SELECT password_hash FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        return row["password_hash"] if row else None

    def delete_user(self, user_id: int) -> None:
        """Tombstone the user (keep the row for attribution; free the name) and drop its sessions."""
        with self.atomic():
            self._conn.execute(
                "UPDATE users SET deleted_at = ?, disabled = 1 WHERE id = ?", (_iso(_now()), user_id),
            )
            self._conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
            self._conn.commit()

    def count_enabled_admins(self) -> int:
        row = self._conn.execute(
            "SELECT COUNT(*) FROM users WHERE role = ? AND disabled = 0 AND deleted_at IS NULL",
            (Role.ADMIN.value,),
        ).fetchone()
        return row[0]

    def create_session(self, user_id: int, token_hash: str, expires_at: datetime) -> None:
        now = _iso(_now())
        self._conn.execute(
            """INSERT INTO sessions (token_hash, user_id, created_at, last_seen_at, expires_at)
               VALUES (?, ?, ?, ?, ?)""",
            (token_hash, user_id, now, now, _iso(expires_at)),
        )
        self._conn.commit()

    def session_user(self, token_hash: str) -> User | None:
        """Resolve a session token hash to its user, refreshing `last_seen_at`. Returns None when
        the session is unknown, expired, or its user is disabled/deleted."""
        now = _iso(_now())
        with self.atomic():
            row = self._conn.execute(
                """SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id
                   WHERE s.token_hash = ? AND s.expires_at > ?
                     AND u.disabled = 0 AND u.deleted_at IS NULL""",
                (token_hash, now),
            ).fetchone()
            if row is None:
                return None
            self._conn.execute(
                "UPDATE sessions SET last_seen_at = ? WHERE token_hash = ?", (now, token_hash),
            )
            self._conn.commit()
            return self._user(row)

    def delete_session(self, token_hash: str) -> None:
        self._conn.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
        self._conn.commit()

    def delete_user_sessions(self, user_id: int, *, except_token_hash: str | None = None) -> None:
        """Revoke a user's sessions. With `except_token_hash`, keep that one (so a user who changes
        their own password stays logged in on the current device but is logged out everywhere else)."""
        if except_token_hash is None:
            self._conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        else:
            self._conn.execute(
                "DELETE FROM sessions WHERE user_id = ? AND token_hash != ?", (user_id, except_token_hash),
            )
        self._conn.commit()

    def purge_expired_sessions(self) -> None:
        self._conn.execute("DELETE FROM sessions WHERE expires_at <= ?", (_iso(_now()),))
        self._conn.commit()

    # -- entities and aliases ------------------------------------------------------

    @staticmethod
    def _entity(row: sqlite3.Row) -> Entity:
        raw = row["attributes_json"] if "attributes_json" in row.keys() else "{}"
        try:
            parsed = json.loads(raw or "{}")
        except (json.JSONDecodeError, TypeError):
            parsed = {}
        # Preserve lists (used by `sectors`) and strings (used by `sector`, `country`, …).
        # Anything else gets stringified so a corrupt row cannot crash the reader.
        attributes: dict[str, str | list[str]] = {}
        if isinstance(parsed, dict):
            for k, v in parsed.items():
                if isinstance(v, list):
                    attributes[str(k)] = [str(item) for item in v]
                else:
                    attributes[str(k)] = str(v)
        return Entity(
            id=row["id"], stix_type=row["stix_type"], canonical_name=row["canonical_name"],
            external_id=row["external_id"], attributes=attributes,
        )

    def create_entity(
        self,
        stix_type: str,
        name: str,
        origin: AliasOrigin,
        external_id: str | None = None,
        entity_id: str | None = None,
        investigation_id: int | None = None,
    ) -> Entity:
        eid = entity_id or f"{stix_type}--{uuid.uuid4()}"
        self._conn.execute(
            "INSERT INTO entities (id, stix_type, canonical_name, external_id) VALUES (?, ?, ?, ?)",
            (eid, stix_type, name.strip(), external_id),
        )
        self._conn.commit()
        self.add_alias(name, eid, origin, investigation_id=investigation_id)
        return self.get_entity(eid)

    def get_entity(self, entity_id: str) -> Entity | None:
        row = self._conn.execute("SELECT * FROM entities WHERE id = ?", (entity_id,)).fetchone()
        return self._entity(row) if row else None

    def find_by_external_id(self, external_id: str) -> Entity | None:
        row = self._conn.execute(
            "SELECT * FROM entities WHERE external_id = ?", (external_id,)
        ).fetchone()
        return self._entity(row) if row else None

    def find_or_create_entity(
        self, name: str, stix_type: str, origin: AliasOrigin, *,
        stix_types: Collection[str] | None = None,
        scope_investigation_id: int | None = None,
        investigation_id: int | None = None,
    ) -> Entity:
        """Resolve a name to an entity, creating it when nothing matches — atomically.

        This is the pair the Validator used to run as two separate calls, which raced under
        `--concurrency > 1`: both workers read "not found" for the same actor and both created
        it, so the two documents that corroborate each other ended up on two different entities
        and a corroborated assessment was stored as two single-source ones. Measured at ~4 in 25
        runs at concurrency=3 before this method existed.

        `stix_types` widens the lookup to the compatible types the caller accepts (an
        intrusion-set claim may legitimately resolve to a known campaign, see
        `validator._COMPATIBLE_TYPES`); the row is created as `stix_type` when nothing matches.
        """
        with self.atomic():
            found = self.find_by_alias(
                name, stix_types=stix_types if stix_types is not None else {stix_type},
                scope_investigation_id=scope_investigation_id,
            )
            if found is not None:
                return found
            return self.create_entity(stix_type, name, origin, investigation_id=investigation_id)

    def find_by_alias(
        self, name: str, stix_types: Collection[str] | None = None,
        scope_investigation_id: int | None = None,
    ) -> Entity | None:
        """Resolve a name to an entity. When `scope_investigation_id` is given, DOCUMENT-origin
        aliases tagged with a *different* investigation are ignored — this prevents an alias learned
        from one investigation's documents from steering another investigation's claim validation.
        ATTACK and USER aliases, and DOCUMENT aliases with no investigation, remain globally visible.
        """
        if scope_investigation_id is None:
            where = "a.normalized_alias = ?"
            params: tuple = (normalize_name(name),)
        else:
            where = (
                "a.normalized_alias = ? AND "
                "(a.origin != 'document' OR a.investigation_id IS NULL OR a.investigation_id = ?)"
            )
            params = (normalize_name(name), scope_investigation_id)
        rows = self._conn.execute(
            f"""SELECT e.* FROM aliases a JOIN entities e ON e.id = a.entity_id
                WHERE {where} ORDER BY {_ORIGIN_PRIORITY}, e.rowid""",
            params,
        ).fetchall()
        for row in rows:
            if stix_types is None or row["stix_type"] in stix_types:
                return self._entity(row)
        return None

    def add_alias(
        self, alias: str, entity_id: str, origin: AliasOrigin,
        evidence_claim_id: int | None = None,
        investigation_id: int | None = None,
    ) -> None:
        key = normalize_name(alias)
        if not key:
            return
        origin_priority = {"attack": 0, "user": 1, "document": 2}[origin.value]
        # Only DOCUMENT aliases carry an investigation scope; higher-priority origins are global.
        inv_id = investigation_id if origin is AliasOrigin.DOCUMENT else None
        self._conn.execute(
            f"""INSERT INTO aliases (normalized_alias, alias, entity_id, origin, evidence_claim_id, investigation_id)
               VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT (normalized_alias, entity_id) DO UPDATE SET
                   origin = CASE
                       WHEN {origin_priority} < CASE origin WHEN 'attack' THEN 0 WHEN 'user' THEN 1 ELSE 2 END
                       THEN ?
                       ELSE origin
                   END,
                   evidence_claim_id = CASE
                       WHEN {origin_priority} < CASE origin WHEN 'attack' THEN 0 WHEN 'user' THEN 1 ELSE 2 END
                       THEN ?
                       ELSE evidence_claim_id
                   END,
                   investigation_id = CASE
                       WHEN {origin_priority} < CASE origin WHEN 'attack' THEN 0 WHEN 'user' THEN 1 ELSE 2 END
                       THEN NULL
                       ELSE investigation_id
                   END""",
            (key, alias.strip(), entity_id, origin.value, evidence_claim_id, inv_id,
             origin.value, evidence_claim_id),
        )
        self._conn.commit()

    def attack_entity_ids(self, entity_ids: Collection[str]) -> set[str]:
        """The given ids that come from the MITRE ATT&CK catalog (they have an alias of origin 'attack')."""
        ids = list(entity_ids)
        if not ids:
            return set()
        placeholders = ", ".join("?" for _ in ids)
        rows = self._conn.execute(
            f"SELECT DISTINCT entity_id FROM aliases WHERE origin = 'attack' AND entity_id IN ({placeholders})",
            ids,
        ).fetchall()
        return {row["entity_id"] for row in rows}

    def merge_entities(self, source_id: str, target_id: str) -> set[tuple[str, str, str]]:
        """Fuse `source` into `target`: move every claim and alias, delete source, return the
        set of (subject, predicate, object) assessment keys the caller must `recompute`.

        Classic use case: a document extracted "C0027" as a document-origin campaign entity
        BEFORE `argus attack update` loaded the ATT&CK Enterprise campaigns. Running an attack
        update then creates the official C0027 as a separate entity; `merge_entities` moves the
        existing claim pointing at the duplicate so the real-world object has one row again.

        Refusals: self-merge, cross-stix-type merge, unknown ids.
        """
        if source_id == target_id:
            raise ValueError("source and target must differ")
        src = self.get_entity(source_id)
        if src is None:
            raise KeyError(source_id)
        tgt = self.get_entity(target_id)
        if tgt is None:
            raise KeyError(target_id)
        if src.stix_type != tgt.stix_type:
            raise ValueError(
                f"cannot merge across stix_type: {src.stix_type!r} into {tgt.stix_type!r}"
            )
        with self._conn:
            # Collect assessment keys the caller must recompute: every (subject, predicate,
            # object) triple that touches `source` in either the assessments or the claims
            # table. Rewriting the ids to the target gives us the keys as they will look
            # AFTER the move — ready to feed straight into `Validator.recompute`.
            touched: set[tuple[str, str, str]] = set()
            for row in self._conn.execute(
                "SELECT subject_entity_id, predicate, object_entity_id FROM assessments "
                "WHERE subject_entity_id = ? OR object_entity_id = ?",
                (source_id, source_id),
            ):
                subj = target_id if row[0] == source_id else row[0]
                obj = target_id if row[2] == source_id else row[2]
                touched.add((subj, row[1], obj))
            for row in self._conn.execute(
                "SELECT subject_entity_id, predicate, object_entity_id FROM claims "
                "WHERE (subject_entity_id = ? OR object_entity_id = ?) AND quote_status != ? "
                "AND subject_entity_id IS NOT NULL AND object_entity_id IS NOT NULL",
                (source_id, source_id, QuoteStatus.REJECTED.value),
            ):
                subj = target_id if row[0] == source_id else row[0]
                obj = target_id if row[2] == source_id else row[2]
                touched.add((subj, row[1], obj))
            # Move claim references. A composite move to target may create (target, pred, target)
            # self-claims — rare and harmless; the Validator never emits them.
            self._conn.execute(
                "UPDATE claims SET subject_entity_id = ? WHERE subject_entity_id = ?",
                (target_id, source_id),
            )
            self._conn.execute(
                "UPDATE claims SET object_entity_id = ? WHERE object_entity_id = ?",
                (target_id, source_id),
            )
            # Delete stale assessments; they will be rebuilt from the re-pointed claims by the
            # caller's `recompute(touched)` pass.
            self._conn.execute(
                "DELETE FROM assessments WHERE subject_entity_id = ? OR object_entity_id = ?",
                (source_id, source_id),
            )
            # Move aliases that don't already exist on the target (dedupe by normalized_alias).
            self._conn.execute(
                "INSERT OR IGNORE INTO aliases "
                "(normalized_alias, alias, entity_id, origin, evidence_claim_id, investigation_id) "
                "SELECT normalized_alias, alias, ?, origin, evidence_claim_id, investigation_id "
                "FROM aliases WHERE entity_id = ?",
                (target_id, source_id),
            )
            self._conn.execute("DELETE FROM aliases WHERE entity_id = ?", (source_id,))
            self._conn.execute("DELETE FROM entities WHERE id = ?", (source_id,))
        return touched

    _RETYPEABLE: ClassVar[frozenset[str]] = frozenset({
        # STIX 2.1 SDOs Argus emits. attack-pattern is deliberately excluded: it carries
        # an ATT&CK external_id whose semantics would be nonsense on another type.
        "intrusion-set", "campaign", "malware", "tool",
        "identity", "location", "indicator", "vulnerability",
    })

    def retype_entity(self, entity_id: str, new_stix_type: str) -> Entity:
        """Change an entity's STIX type (and regenerate its typed id) in one transaction.

        The common case: the LLM typed a technology ("AWS", "ADFS") as an `identity` SDO
        during extraction. Those are not organisations; they are tools / infrastructure.
        Rather than deleting + re-creating + losing every alias and claim pointing at them,
        this swaps the type in place.

        The entity's UUID is preserved — only the type prefix of the id changes:
        `identity--<uuid>` → `tool--<uuid>`. Every foreign key that points at the old id
        is rewritten to the new one in the same transaction (claims subject/object,
        assessments subject/object, aliases, investigation resolved_entity_id).

        Refusals:
        - unknown entity id (KeyError).
        - identical type (ValueError — no-op).
        - type not in the retype whitelist (ValueError). `attack-pattern` is excluded
          because its external_id carries ATT&CK semantics the retype would strip.
        - the entity is a MITRE ATT&CK entity (its alias from the ATT&CK bundle would be
          mislabelled next sync). Caller must detach from ATT&CK first.
        """
        if new_stix_type not in self._RETYPEABLE:
            raise ValueError(
                f"stix_type {new_stix_type!r} is not retype-able (one of: {sorted(self._RETYPEABLE)})"
            )
        existing = self.get_entity(entity_id)
        if existing is None:
            raise KeyError(entity_id)
        if existing.stix_type == new_stix_type:
            raise ValueError(f"entity {entity_id} is already {new_stix_type!r}")
        attack_origin = self._conn.execute(
            "SELECT 1 FROM aliases WHERE entity_id = ? AND origin = 'attack' LIMIT 1", (entity_id,),
        ).fetchone()
        if attack_origin is not None:
            raise ValueError(
                f"entity {entity_id} has ATT&CK-origin aliases — detach from ATT&CK before retyping"
            )
        # Keep the UUID; change the prefix. Old ids look like `<old_type>--<uuid>` — preserve
        # exactly whatever comes after the first `--` so a non-UUID suffix (external imports)
        # still works.
        if "--" not in entity_id:
            raise ValueError(f"malformed entity id {entity_id!r} (no '--' separator)")
        suffix = entity_id.split("--", 1)[1]
        new_id = f"{new_stix_type}--{suffix}"
        if self._conn.execute("SELECT 1 FROM entities WHERE id = ?", (new_id,)).fetchone():
            raise ValueError(f"retype would collide with existing entity {new_id!r}")

        with self._conn:
            # Insert the new row first so every FK UPDATE below has a valid target. The
            # original row's attributes (canonical_name, external_id, attributes_json)
            # survive the retype — only the type and id change.
            self._conn.execute(
                "INSERT INTO entities (id, stix_type, canonical_name, external_id, attributes_json) "
                "SELECT ?, ?, canonical_name, external_id, attributes_json FROM entities WHERE id = ?",
                (new_id, new_stix_type, entity_id),
            )
            # Repoint every FK. The columns involved are small enough to enumerate.
            for sql in (
                "UPDATE claims SET subject_entity_id = ? WHERE subject_entity_id = ?",
                "UPDATE claims SET object_entity_id = ? WHERE object_entity_id = ?",
                "UPDATE assessments SET subject_entity_id = ? WHERE subject_entity_id = ?",
                "UPDATE assessments SET object_entity_id = ? WHERE object_entity_id = ?",
                "UPDATE aliases SET entity_id = ? WHERE entity_id = ?",
                "UPDATE investigations SET resolved_entity_id = ? WHERE resolved_entity_id = ?",
            ):
                self._conn.execute(sql, (new_id, entity_id))
            # Delete the old row only after every reference has moved.
            self._conn.execute("DELETE FROM entities WHERE id = ?", (entity_id,))

        return self.get_entity(new_id)  # type: ignore[return-value]

    def set_entity_attributes(self, entity_id: str, **attrs: str | None) -> Entity:
        """Merge keys into the entity's attributes_json. Pass a key = None to drop that key.

        Used by `argus identity-set` to tag an identity entity with its sector and/or country, but
        the method is generic — any entity type can carry open-form attributes. Values are coerced
        to stripped strings; empty strings are treated like None (dropped) so a stray empty flag
        does not litter the store.
        """
        row = self._conn.execute(
            "SELECT attributes_json FROM entities WHERE id = ?", (entity_id,),
        ).fetchone()
        if row is None:
            raise KeyError(entity_id)
        try:
            current = json.loads(row["attributes_json"] or "{}")
        except (json.JSONDecodeError, TypeError):
            current = {}
        if not isinstance(current, dict):
            current = {}
        for key, value in attrs.items():
            if value is None:
                current.pop(key, None)
                continue
            cleaned = str(value).strip()
            if not cleaned:
                current.pop(key, None)
            else:
                current[key] = cleaned
        self._conn.execute(
            "UPDATE entities SET attributes_json = ? WHERE id = ?",
            (json.dumps(current, ensure_ascii=False, sort_keys=True), entity_id),
        )
        self._conn.commit()
        return self.get_entity(entity_id)

    def append_entity_sector(self, entity_id: str, sector: str) -> Entity:
        """Append a sector label to the entity's `attributes.sectors` list (deduped,
        case-insensitive). Creates the list on first call.

        This is the primary way to attribute an actor to one or more industries — the
        STIX 2.1 `threat-actor.sectors[]` shape. Replaces the common 0.11-era pattern of
        creating a sector-named identity SDO and connecting it with a `targets` claim,
        which the Validator now rejects anyway (see `knowledge.mistype`).
        """
        row = self._conn.execute(
            "SELECT attributes_json FROM entities WHERE id = ?", (entity_id,),
        ).fetchone()
        if row is None:
            raise KeyError(entity_id)
        try:
            current = json.loads(row["attributes_json"] or "{}")
        except (json.JSONDecodeError, TypeError):
            current = {}
        if not isinstance(current, dict):
            current = {}
        raw = current.get("sectors")
        sectors: list[str] = list(raw) if isinstance(raw, list) else []
        normalized = sector.strip().lower()
        if normalized and normalized not in {s.lower() for s in sectors}:
            sectors.append(normalized)
        current["sectors"] = sectors
        self._conn.execute(
            "UPDATE entities SET attributes_json = ? WHERE id = ?",
            (json.dumps(current, ensure_ascii=False, sort_keys=True), entity_id),
        )
        self._conn.commit()
        return self.get_entity(entity_id)

    def actors_targeting_identity(self, identity_id: str) -> list[Entity]:
        """Every actor-shaped entity (intrusion-set / campaign / malware / tool) that has
        a `targets` assessment pointing at `identity_id`. Returned by the sector-migration
        endpoint so the UI can offer them as candidate recipients for the sector tag.

        Named `_identity` to disambiguate from `actors_targeting(sector=…, country=…)`
        which answers a different question (actors with claims against identities
        MATCHING a sector/country filter, with counts)."""
        rows = self._conn.execute(
            """SELECT DISTINCT e.id, e.stix_type, e.canonical_name, e.external_id, e.attributes_json
               FROM entities e
               JOIN assessments a ON a.subject_entity_id = e.id
               WHERE a.predicate = 'targets' AND a.object_entity_id = ?
                 AND e.stix_type IN ('intrusion-set', 'campaign', 'malware', 'tool')
               ORDER BY e.canonical_name""",
            (identity_id,),
        ).fetchall()
        return [self._entity(r) for r in rows]

    def delete_entity_cascading(self, entity_id: str) -> int:
        """Delete an entity along with every claim/assessment/alias pointing at it.
        Returns the number of claims removed (the operation's observable blast radius).

        Used by the sector-migration path: after the entity's sector label has been
        appended to each actor's `attributes.sectors`, the identity entity itself has
        no reason to survive. Different from `merge_entities` which moves pointers;
        here we delete the pointers too, because the sector label is no longer a
        first-class SDO.
        """
        if self._conn.execute("SELECT 1 FROM entities WHERE id = ?", (entity_id,)).fetchone() is None:
            raise KeyError(entity_id)
        with self._conn:
            claim_rows = self._conn.execute(
                "DELETE FROM claims WHERE subject_entity_id = ? OR object_entity_id = ?",
                (entity_id, entity_id),
            )
            removed = claim_rows.rowcount
            self._conn.execute(
                "DELETE FROM assessments WHERE subject_entity_id = ? OR object_entity_id = ?",
                (entity_id, entity_id),
            )
            self._conn.execute("DELETE FROM aliases WHERE entity_id = ?", (entity_id,))
            self._conn.execute(
                "UPDATE investigations SET resolved_entity_id = NULL WHERE resolved_entity_id = ?",
                (entity_id,),
            )
            self._conn.execute("DELETE FROM entities WHERE id = ?", (entity_id,))
        return removed

    def identities_matching(
        self, sector: str | None = None, country: str | None = None,
    ) -> list[Entity]:
        """Identity entities whose attributes match the requested sector and/or country.
        Match is case-insensitive. Pass no filter to list every tagged identity."""
        conditions = ["stix_type = 'identity'"]
        params: list = []
        if sector:
            conditions.append("LOWER(COALESCE(json_extract(attributes_json, '$.sector'), '')) = LOWER(?)")
            params.append(sector.strip())
        if country:
            conditions.append("UPPER(COALESCE(json_extract(attributes_json, '$.country'), '')) = UPPER(?)")
            params.append(country.strip())
        where = " AND ".join(conditions)
        rows = self._conn.execute(
            f"SELECT * FROM entities WHERE {where} ORDER BY canonical_name COLLATE NOCASE",
            params,
        ).fetchall()
        return [self._entity(row) for row in rows]

    def set_entity_external_id(self, entity_id: str, external_id: str) -> None:
        """Backfill the external_id on an existing entity. Used by the ATT&CK loader to
        patch rows created before 0.15 where groups and software never got their G/S
        MITRE id. Non-destructive — only writes when the current value is NULL."""
        self._conn.execute(
            "UPDATE entities SET external_id = ? "
            "WHERE id = ? AND (external_id IS NULL OR external_id = '')",
            (external_id, entity_id),
        )
        self._conn.commit()

    def actors_by_sector_attribute(self, sector: str) -> list[Entity]:
        """Actors whose own `attributes.sectors[]` list contains `sector` (case-insensitive).

        0.13+ captures sector attribution directly on the actor via `append_entity_sector`;
        this method surfaces those actors without needing an identity-targeting chain. Used
        by `/api/query/targets` to merge with the identity-based path so pre-0.13 and post-0.13
        data both show up.

        The LIKE pattern is intentionally loose — a JSON scan over 500 entities on SQLite
        is tiny — because the alternative (JSON1 extension's json_each) is not uniformly
        available on every SQLite build Argus ships against.
        """
        key = sector.strip().lower()
        if not key:
            return []
        pattern = f'%"{key}"%'
        rows = self._conn.execute(
            """SELECT id, stix_type, canonical_name, external_id, attributes_json
               FROM entities
               WHERE stix_type IN ('intrusion-set', 'campaign', 'malware', 'tool')
                 AND LOWER(attributes_json) LIKE ?
               ORDER BY canonical_name COLLATE NOCASE""",
            (pattern,),
        ).fetchall()
        # Second-pass filter: parse the JSON and confirm `sector` is really in the list.
        # The LIKE pass can false-positive on names that happen to contain the sector string.
        matched: list[Entity] = []
        for row in rows:
            entity = self._entity(row)
            sectors = entity.attributes.get("sectors") or []
            if isinstance(sectors, list) and key in {s.lower() for s in sectors}:
                matched.append(entity)
        return matched

    def actors_targeting(
        self, sector: str | None = None, country: str | None = None,
    ) -> list[tuple[Entity, int]]:
        """Actors (intrusion-set, campaign, malware) with at least one `targets` assessment
        against an identity matching the given sector/country. Returns (actor, count), ranked
        by count then name."""
        identities = self.identities_matching(sector=sector, country=country)
        if not identities:
            return []
        identity_ids = [i.id for i in identities]
        placeholders = ", ".join("?" for _ in identity_ids)
        rows = self._conn.execute(
            f"""SELECT e.*, COUNT(a.id) AS n
                FROM assessments a
                JOIN entities e ON e.id = a.subject_entity_id
                WHERE a.predicate = 'targets' AND a.object_entity_id IN ({placeholders})
                GROUP BY e.id
                ORDER BY n DESC, e.canonical_name COLLATE NOCASE""",
            identity_ids,
        ).fetchall()
        return [(self._entity(row), int(row["n"])) for row in rows]

    def aliases_for(self, entity_id: str, origins: Collection[str] | None = None) -> list[str]:
        """Every alias of the entity, or only those whose origin is in `origins` (e.g. 'attack', 'user')."""
        wanted = None if origins is None else [str(origin) for origin in origins]
        if wanted == []:
            return []
        origin_filter = "" if wanted is None else f" AND origin IN ({', '.join('?' for _ in wanted)})"
        rows = self._conn.execute(
            f"SELECT alias FROM aliases WHERE entity_id = ?{origin_filter} ORDER BY alias COLLATE NOCASE",
            (entity_id, *(wanted or [])),
        ).fetchall()
        return [r["alias"] for r in rows]

    # -- claims --------------------------------------------------------------------

    @staticmethod
    def _claim(row: sqlite3.Row) -> Claim:
        return Claim(
            id=row["id"], document_id=row["document_id"], subject_ref=row["subject_ref"],
            subject_type=row["subject_type"], predicate=row["predicate"],
            object_ref=row["object_ref"], object_type=row["object_type"],
            technique_id=row["technique_id"], polarity=Polarity(row["polarity"]),
            quote=row["quote"], quote_status=QuoteStatus(row["quote_status"]),
            observed_at=_date(row["observed_at"]), prompt_version=row["prompt_version"],
            subject_entity_id=row["subject_entity_id"], object_entity_id=row["object_entity_id"],
            investigation_id=row["investigation_id"],
        )

    def add_claim(
        self,
        document_id: int,
        draft: ClaimDraft,
        quote_status: QuoteStatus,
        prompt_version: str,
        subject_entity_id: str | None,
        object_entity_id: str | None,
        investigation_id: int | None = None,
    ) -> Claim:
        cur = self._conn.execute(
            """INSERT INTO claims (document_id, subject_ref, subject_type, predicate, object_ref,
                   object_type, technique_id, polarity, quote, quote_status, observed_at,
                   prompt_version, subject_entity_id, object_entity_id, investigation_id)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                document_id, draft.subject, draft.subject_type, draft.predicate, draft.object,
                draft.object_type, draft.technique_id, draft.polarity.value, draft.quote,
                quote_status.value, _iso(draft.observed_at), prompt_version,
                subject_entity_id, object_entity_id, investigation_id,
            ),
        )
        self._conn.commit()
        row = self._conn.execute("SELECT * FROM claims WHERE id = ?", (cur.lastrowid,)).fetchone()
        return self._claim(row)

    def claims_for_document(self, document_id: int) -> list[Claim]:
        rows = self._conn.execute(
            "SELECT * FROM claims WHERE document_id = ? ORDER BY id", (document_id,)
        ).fetchall()
        return [self._claim(r) for r in rows]

    def delete_claims_for_document(self, document_id: int) -> set[tuple[str, str, str]]:
        rows = self._conn.execute(
            """SELECT DISTINCT subject_entity_id, predicate, object_entity_id FROM claims
               WHERE document_id = ? AND quote_status != ? AND predicate != 'alias-of'
                 AND subject_entity_id IS NOT NULL AND object_entity_id IS NOT NULL""",
            (document_id, QuoteStatus.REJECTED.value),
        ).fetchall()
        touched = {(r[0], r[1], r[2]) for r in rows}

        # Get all aliases with origin='document' that have evidence_claim_id from this document
        doc_aliases = self._conn.execute(
            """SELECT normalized_alias, entity_id, evidence_claim_id
               FROM aliases
               WHERE origin = ? AND evidence_claim_id IN (SELECT id FROM claims WHERE document_id = ?)""",
            (AliasOrigin.DOCUMENT.value, document_id),
        ).fetchall()

        # For each document-origin alias, check if there's another supporting claim
        for alias_row in doc_aliases:
            normalized_alias = alias_row["normalized_alias"]
            entity_id = alias_row["entity_id"]

            # Look for another alias-of claim in a different document that supports (asserts) this alias
            supporting_claims = self._conn.execute(
                """SELECT c.id, c.subject_ref FROM claims c
                   WHERE c.predicate = ? AND c.quote_status != ? AND c.polarity = ?
                     AND c.object_entity_id = ? AND c.document_id != ?
                     AND c.id NOT IN (SELECT id FROM claims WHERE document_id = ?)""",
                (
                    "alias-of", QuoteStatus.REJECTED.value, Polarity.ASSERTS.value, entity_id,
                    document_id, document_id,
                ),
            ).fetchall()

            # Check if any of the supporting claims normalize to the same alias
            found_supporting_claim = None
            for claim_row in supporting_claims:
                if normalize_name(claim_row["subject_ref"]) == normalized_alias:
                    found_supporting_claim = claim_row["id"]
                    break

            if found_supporting_claim:
                # Update the alias to reference the new supporting claim
                self._conn.execute(
                    "UPDATE aliases SET evidence_claim_id = ? WHERE normalized_alias = ? AND entity_id = ?",
                    (found_supporting_claim, normalized_alias, entity_id),
                )
            else:
                # Delete the alias if no other claim supports it
                self._conn.execute(
                    "DELETE FROM aliases WHERE normalized_alias = ? AND entity_id = ?",
                    (normalized_alias, entity_id),
                )

        self._conn.execute("DELETE FROM claims WHERE document_id = ?", (document_id,))
        self._conn.commit()
        return touched

    def evidence_for(self, subject_id: str, predicate: str, object_id: str) -> list[Evidence]:
        rows = self._conn.execute(
            # reliability is the effective (primary) publisher's letter; document_reliability is the
            # letter of the publisher that actually hosts the document. scoring() weighs the weaker
            # of the two, so a low-reliability page cannot borrow a vendor's weight by citing it.
            f"""SELECT c.id, c.polarity, c.observed_at, d.published_at, p.id AS pid,
                       p.reliability, dp.reliability AS document_reliability
                FROM claims c {_EFFECTIVE_PUBLISHER_JOIN}
                JOIN publishers dp ON dp.id = d.publisher_id
                WHERE c.subject_entity_id = ? AND c.predicate = ? AND c.object_entity_id = ?
                  AND c.quote_status != ? ORDER BY c.id""",
            (subject_id, predicate, object_id, QuoteStatus.REJECTED.value),
        ).fetchall()
        return [
            Evidence(
                claim_id=r["id"], publisher_id=r["pid"], reliability=r["reliability"],
                polarity=Polarity(r["polarity"]), published_at=_date(r["published_at"]),
                observed_at=_date(r["observed_at"]), document_reliability=r["document_reliability"],
            )
            for r in rows
        ]

    def competing_attribution_publishers(self, subject_id: str, object_id: str) -> set[int]:
        rows = self._conn.execute(
            f"""SELECT DISTINCT p.id FROM claims c {_EFFECTIVE_PUBLISHER_JOIN}
                WHERE c.subject_entity_id = ? AND c.predicate = 'attributed-to'
                  AND c.object_entity_id != ? AND c.polarity = ? AND c.quote_status != ?""",
            (subject_id, object_id, Polarity.ASSERTS.value, QuoteStatus.REJECTED.value),
        ).fetchall()
        return {r[0] for r in rows}

    def object_ids_for(self, subject_id: str, predicate: str) -> set[str]:
        rows = self._conn.execute(
            """SELECT DISTINCT object_entity_id FROM claims
               WHERE subject_entity_id = ? AND predicate = ? AND quote_status != ?
                 AND object_entity_id IS NOT NULL""",
            (subject_id, predicate, QuoteStatus.REJECTED.value),
        ).fetchall()
        return {r[0] for r in rows}

    def citations(
        self, subject_id: str, predicate: str, object_id: str, investigation_id: int | None = None,
    ) -> list[Citation]:
        """The non-rejected claims behind a fact; with `investigation_id`, only that investigation's own."""
        rows = self._conn.execute(
            f"""SELECT c.id, c.quote, c.quote_status, c.polarity, d.title,
                       COALESCE(d.url, d.local_path) AS location, p.name, p.tlp AS publisher_tlp,
                       d.published_at
                FROM claims c {_EFFECTIVE_PUBLISHER_JOIN}
                WHERE c.subject_entity_id = ? AND c.predicate = ? AND c.object_entity_id = ?
                  AND c.quote_status != ? {'AND c.investigation_id = ?' if investigation_id is not None else ''}
                ORDER BY d.published_at DESC, c.id""",
            (subject_id, predicate, object_id, QuoteStatus.REJECTED.value,
             *(() if investigation_id is None else (investigation_id,))),
        ).fetchall()
        return [
            Citation(
                claim_id=r["id"], quote=r["quote"], quote_status=QuoteStatus(r["quote_status"]),
                polarity=Polarity(r["polarity"]), document_title=r["title"], location=r["location"],
                publisher=r["name"], published_at=_date(r["published_at"]),
                publisher_tlp=r["publisher_tlp"],
            )
            for r in rows
        ]

    def citations_batch(
        self, triples: Collection[tuple[str, str, str]], investigation_id: int | None = None,
    ) -> dict[tuple[str, str, str], list[Citation]]:
        """Fetch citations for many `(subject, predicate, object)` triples in a single query.
        Avoids the per-fact N+1 that build_profile would otherwise do when a threat has many assessments.
        """
        triples = list(triples)
        if not triples:
            return {}
        or_clauses = " OR ".join(
            "(c.subject_entity_id = ? AND c.predicate = ? AND c.object_entity_id = ?)" for _ in triples
        )
        params: list = [val for triple in triples for val in triple]
        params.append(QuoteStatus.REJECTED.value)
        inv_clause = ""
        if investigation_id is not None:
            inv_clause = " AND c.investigation_id = ?"
            params.append(investigation_id)
        rows = self._conn.execute(
            f"""SELECT c.subject_entity_id, c.predicate, c.object_entity_id,
                       c.id, c.quote, c.quote_status, c.polarity, d.title,
                       COALESCE(d.url, d.local_path) AS location, p.name, p.tlp AS publisher_tlp,
                       d.published_at
                FROM claims c {_EFFECTIVE_PUBLISHER_JOIN}
                WHERE ({or_clauses}) AND c.quote_status != ?{inv_clause}
                ORDER BY d.published_at DESC, c.id""",
            params,
        ).fetchall()
        grouped: dict[tuple[str, str, str], list[Citation]] = {t: [] for t in triples}
        for r in rows:
            key = (r["subject_entity_id"], r["predicate"], r["object_entity_id"])
            grouped[key].append(Citation(
                claim_id=r["id"], quote=r["quote"], quote_status=QuoteStatus(r["quote_status"]),
                polarity=Polarity(r["polarity"]), document_title=r["title"], location=r["location"],
                publisher=r["name"], published_at=_date(r["published_at"]),
                publisher_tlp=r["publisher_tlp"],
            ))
        return grouped

    def get_entities(self, ids: Collection[str]) -> dict[str, Entity]:
        """Fetch many entities in a single query. Caller does not need to dedupe `ids`."""
        unique = list(set(ids))
        if not unique:
            return {}
        placeholders = ",".join("?" for _ in unique)
        rows = self._conn.execute(
            f"SELECT * FROM entities WHERE id IN ({placeholders})", unique,
        ).fetchall()
        return {row["id"]: self._entity(row) for row in rows}

    # -- assessments ---------------------------------------------------------------

    @staticmethod
    def _assessment(row: sqlite3.Row) -> Assessment:
        try:
            analytic = row["analytic_confidence"]
            rationale = row["confidence_rationale"]
        except (KeyError, IndexError):
            # Row came from a pre-ICD-203 shape (migration-in-progress tests) — treat as absent.
            analytic = None
            rationale = None
        return Assessment(
            id=row["id"], subject_entity_id=row["subject_entity_id"], predicate=row["predicate"],
            object_entity_id=row["object_entity_id"], status=AssessmentStatus(row["status"]),
            confidence=row["confidence"], admiralty=row["admiralty"],
            first_seen=_date(row["first_seen"]), last_seen=_date(row["last_seen"]),
            updated_at=_datetime(row["updated_at"]),
            analytic_confidence=AnalyticConfidence(analytic) if analytic else None,
            confidence_rationale=rationale,
        )

    def upsert_assessment(self, assessment: Assessment) -> Assessment:
        """Upsert without touching the operator's analytic-confidence override.

        The recompute pipeline (scoring + importer) writes `analytic_confidence=None` in the
        Assessment it passes here, meaning "derive from scores". If the operator has previously
        set a manual override via `set_analytic_confidence`, this upsert must preserve it rather
        than silently blanking it on the next recompute. The COALESCE in the UPDATE clause does
        exactly that: when the new row has NULL for `analytic_confidence`, keep the stored one.
        """
        a = assessment
        analytic_value = a.analytic_confidence.value if a.analytic_confidence else None
        self._conn.execute(
            """INSERT INTO assessments (subject_entity_id, predicate, object_entity_id, status,
                   confidence, admiralty, first_seen, last_seen, updated_at,
                   analytic_confidence, confidence_rationale)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT (subject_entity_id, predicate, object_entity_id) DO UPDATE SET
                   status = excluded.status, confidence = excluded.confidence,
                   admiralty = excluded.admiralty, first_seen = excluded.first_seen,
                   last_seen = excluded.last_seen, updated_at = excluded.updated_at,
                   analytic_confidence = COALESCE(excluded.analytic_confidence, analytic_confidence),
                   confidence_rationale = COALESCE(excluded.confidence_rationale, confidence_rationale)""",
            (
                a.subject_entity_id, a.predicate, a.object_entity_id, a.status.value, a.confidence,
                a.admiralty, _iso(a.first_seen), _iso(a.last_seen), _iso(_now()),
                analytic_value, a.confidence_rationale,
            ),
        )
        self._conn.commit()
        row = self._conn.execute(
            """SELECT * FROM assessments
               WHERE subject_entity_id = ? AND predicate = ? AND object_entity_id = ?""",
            (a.subject_entity_id, a.predicate, a.object_entity_id),
        ).fetchone()
        return self._assessment(row)

    def set_analytic_confidence(
        self, assessment_id: int, level: AnalyticConfidence | None, rationale: str | None,
    ) -> Assessment | None:
        """Explicit operator override. `None` level clears the override and lets the next
        recompute pick the derived value back up."""
        value = level.value if level else None
        self._conn.execute(
            "UPDATE assessments SET analytic_confidence = ?, confidence_rationale = ? WHERE id = ?",
            (value, rationale, assessment_id),
        )
        self._conn.commit()
        row = self._conn.execute(
            "SELECT * FROM assessments WHERE id = ?", (assessment_id,),
        ).fetchone()
        return self._assessment(row) if row else None

    def delete_assessment(self, subject_id: str, predicate: str, object_id: str) -> None:
        self._conn.execute(
            """DELETE FROM assessments
               WHERE subject_entity_id = ? AND predicate = ? AND object_entity_id = ?""",
            (subject_id, predicate, object_id),
        )
        self._conn.commit()

    def assessments_involving(self, entity_id: str, investigation_id: int | None = None) -> list[Assessment]:
        scope_sql, scope_params = (
            investigation_claim_filter(investigation_id, "assessments") if investigation_id is not None else ("", ())
        )
        rows = self._conn.execute(
            f"""SELECT * FROM assessments WHERE (subject_entity_id = ? OR object_entity_id = ?) {scope_sql}
               ORDER BY predicate, confidence DESC, id""",
            (entity_id, entity_id, *scope_params),
        ).fetchall()
        return [self._assessment(r) for r in rows]

    # -- scheduled investigations ---------------------------------------------------

    @staticmethod
    def _schedule(row: sqlite3.Row) -> ScheduledInvestigation:
        from cyllex_argus.knowledge.models import ScheduledInvestigation
        return ScheduledInvestigation(
            id=row["id"], target=row["target"], cron_expr=row["cron_expr"],
            max_docs=row["max_docs"], concurrency=row["concurrency"],
            enabled=bool(row["enabled"]),
            last_run_at=_datetime(row["last_run_at"]),
            last_job_id=row["last_job_id"],
            next_run_at=_datetime(row["next_run_at"]) or _now(),
            created_at=_datetime(row["created_at"]) or _now(),
            created_by=row["created_by"],
        )

    def create_schedule(
        self, *, target: str, cron_expr: str, max_docs: int | None, concurrency: int, next_run_at: datetime,
    ) -> ScheduledInvestigation:
        now = _iso(_now())
        cursor = self._conn.execute(
            """INSERT INTO scheduled_investigations
               (target, cron_expr, max_docs, concurrency, enabled, next_run_at, created_at)
               VALUES (?, ?, ?, ?, 1, ?, ?)""",
            (target, cron_expr, max_docs, concurrency, _iso(next_run_at), now),
        )
        self._conn.commit()
        row = self._conn.execute(
            "SELECT * FROM scheduled_investigations WHERE id = ?", (cursor.lastrowid,),
        ).fetchone()
        return self._schedule(row)

    def list_schedules(self) -> list[ScheduledInvestigation]:
        rows = self._conn.execute(
            "SELECT * FROM scheduled_investigations ORDER BY enabled DESC, next_run_at",
        ).fetchall()
        return [self._schedule(r) for r in rows]

    def get_schedule(self, schedule_id: int) -> ScheduledInvestigation | None:
        row = self._conn.execute(
            "SELECT * FROM scheduled_investigations WHERE id = ?", (schedule_id,),
        ).fetchone()
        return self._schedule(row) if row else None

    def delete_schedule(self, schedule_id: int) -> bool:
        cur = self._conn.execute(
            "DELETE FROM scheduled_investigations WHERE id = ?", (schedule_id,),
        )
        self._conn.commit()
        return cur.rowcount > 0

    def set_schedule_enabled(self, schedule_id: int, enabled: bool) -> None:
        self._conn.execute(
            "UPDATE scheduled_investigations SET enabled = ? WHERE id = ?",
            (1 if enabled else 0, schedule_id),
        )
        self._conn.commit()

    def mark_schedule_fired(
        self, schedule_id: int, *, job_id: str, fired_at: datetime, next_run_at: datetime,
    ) -> None:
        self._conn.execute(
            """UPDATE scheduled_investigations
               SET last_run_at = ?, last_job_id = ?, next_run_at = ?
               WHERE id = ?""",
            (_iso(fired_at), job_id, _iso(next_run_at), schedule_id),
        )
        self._conn.commit()

    def due_schedules(self, now: datetime) -> list[ScheduledInvestigation]:
        """Enabled schedules whose `next_run_at` is in the past. Called by the scheduler tick."""
        rows = self._conn.execute(
            "SELECT * FROM scheduled_investigations WHERE enabled = 1 AND next_run_at <= ?",
            (_iso(now),),
        ).fetchall()
        return [self._schedule(r) for r in rows]

    # -- watchers ------------------------------------------------------------------
    # A watcher IS a scheduled_investigations row with an owner (created_by). `entity_id` and
    # `unseen_count` are not stored on the row; the read path fills them (resolution / per-user).

    @staticmethod
    def _watcher(row: sqlite3.Row) -> Watcher:
        from cyllex_argus.knowledge.models import Watcher
        return Watcher(
            id=row["id"], target=row["target"], cron_expr=row["cron_expr"],
            enabled=bool(row["enabled"]), created_by=row["created_by"],
            max_docs=row["max_docs"], concurrency=row["concurrency"],
            last_run_at=_datetime(row["last_run_at"]),
            next_run_at=_datetime(row["next_run_at"]) or _now(),
            created_at=_datetime(row["created_at"]) or _now(),
        )

    def create_watcher(
        self, *, target: str, cron_expr: str, created_by: int | None, next_run_at: datetime,
        max_docs: int | None = None, concurrency: int = 1,
    ) -> Watcher:
        """Create a watcher, or return the existing one for this target (idempotent: one per
        target). The find-or-create runs in `atomic()` so two callers cannot both insert."""
        with self.atomic():
            existing = self._conn.execute(
                "SELECT * FROM scheduled_investigations WHERE target = ?", (target,),
            ).fetchone()
            if existing is not None:
                return self._watcher(existing)
            cursor = self._conn.execute(
                """INSERT INTO scheduled_investigations
                   (target, cron_expr, max_docs, concurrency, enabled, created_by, next_run_at, created_at)
                   VALUES (?, ?, ?, ?, 1, ?, ?, ?)""",
                (target, cron_expr, max_docs, concurrency, created_by, _iso(next_run_at), _iso(_now())),
            )
            self._conn.commit()
            row = self._conn.execute(
                "SELECT * FROM scheduled_investigations WHERE id = ?", (cursor.lastrowid,),
            ).fetchone()
            return self._watcher(row)

    def get_watcher(self, watcher_id: int) -> Watcher | None:
        row = self._conn.execute(
            "SELECT * FROM scheduled_investigations WHERE id = ?", (watcher_id,),
        ).fetchone()
        return self._watcher(row) if row else None

    def list_watchers(self) -> list[Watcher]:
        rows = self._conn.execute(
            "SELECT * FROM scheduled_investigations ORDER BY enabled DESC, next_run_at",
        ).fetchall()
        return [self._watcher(r) for r in rows]

    def set_watcher_enabled(self, watcher_id: int, enabled: bool) -> None:
        self._conn.execute(
            "UPDATE scheduled_investigations SET enabled = ? WHERE id = ?",
            (1 if enabled else 0, watcher_id),
        )
        self._conn.commit()

    def delete_watcher(self, watcher_id: int) -> bool:
        """Delete the watcher and its own rows (changes, snapshots, per-user seen). Never touches
        the knowledge the watcher's runs produced."""
        with self.atomic():
            for table in ("watcher_changes", "watcher_snapshots", "watcher_seen"):
                self._conn.execute(f"DELETE FROM {table} WHERE watcher_id = ?", (watcher_id,))
            cur = self._conn.execute(
                "DELETE FROM scheduled_investigations WHERE id = ?", (watcher_id,),
            )
            self._conn.commit()
            return cur.rowcount > 0

    def watcher_owner(self, watcher_id: int) -> int | None:
        row = self._conn.execute(
            "SELECT created_by FROM scheduled_investigations WHERE id = ?", (watcher_id,),
        ).fetchone()
        return row["created_by"] if row else None

    def watcher_for_target(self, target: str) -> Watcher | None:
        """The watcher monitoring this target, if any. Watchers are one-per-target."""
        row = self._conn.execute(
            "SELECT * FROM scheduled_investigations WHERE target = ?", (target,),
        ).fetchone()
        return self._watcher(row) if row else None

    def watcher_for_entity(self, entity_id: str) -> Watcher | None:
        """The watcher whose target resolves to this entity, matched by the entity's canonical
        name or any of its aliases (normalized). This is what lets a manual run under a different
        spelling / alias advance the right watcher, keyed by the resolved entity, not the string."""
        entity = self.get_entity(entity_id)
        if entity is None:
            return None
        names = {normalize_name(entity.canonical_name)}
        names |= {normalize_name(alias) for alias in self.aliases_for(entity_id)}
        names.discard("")
        if not names:
            return None
        for row in self._conn.execute("SELECT * FROM scheduled_investigations").fetchall():
            if normalize_name(row["target"]) in names:
                return self._watcher(row)
        return None

    def set_investigation_watcher(self, investigation_id: int, watcher_id: int) -> None:
        """Record which watcher fired a run (attribution). Hand-run investigations leave it NULL."""
        self._conn.execute(
            "UPDATE investigations SET watcher_id = ? WHERE id = ?", (watcher_id, investigation_id),
        )
        self._conn.commit()

    # -- watcher snapshots / change events / per-user seen -------------------------

    @staticmethod
    def _watcher_change(row: sqlite3.Row) -> WatcherChange:
        from cyllex_argus.knowledge.models import AssessmentStatus, ChangeKind, Citation, WatcherChange
        citation = Citation.model_validate_json(row["citation_json"]) if row["citation_json"] else None
        return WatcherChange(
            id=row["id"], watcher_id=row["watcher_id"], entity_id=row["entity_id"],
            kind=ChangeKind(row["kind"]), ref_key=row["ref_key"],
            subject=row["subject"], predicate=row["predicate"], object=row["object"],
            from_status=AssessmentStatus(row["from_status"]) if row["from_status"] else None,
            to_status=AssessmentStatus(row["to_status"]) if row["to_status"] else None,
            citation=citation, detected_at=_datetime(row["detected_at"]) or _now(),
            run_job_id=row["run_job_id"],
        )

    def get_snapshot(self, watcher_id: int) -> dict[str, AssessmentStatus]:
        from cyllex_argus.knowledge.models import AssessmentStatus
        rows = self._conn.execute(
            "SELECT ref_key, status FROM watcher_snapshots WHERE watcher_id = ?", (watcher_id,),
        ).fetchall()
        return {r["ref_key"]: AssessmentStatus(r["status"]) for r in rows}

    def replace_snapshot(self, watcher_id: int, entries: dict[str, AssessmentStatus]) -> None:
        """Atomically swap the watcher's snapshot for `entries` (ref_key -> status)."""
        now = _iso(_now())
        with self.atomic():
            self._conn.execute("DELETE FROM watcher_snapshots WHERE watcher_id = ?", (watcher_id,))
            self._conn.executemany(
                "INSERT INTO watcher_snapshots (watcher_id, ref_key, status, updated_at) VALUES (?, ?, ?, ?)",
                [(watcher_id, key, status.value, now) for key, status in entries.items()],
            )
            self._conn.commit()

    def add_changes(self, watcher_id: int, changes: list[WatcherChange]) -> list[int]:
        """Persist change events for a watcher; returns the new row ids. The incoming objects'
        own `id`/`watcher_id` are placeholders — the watcher id comes from the argument."""
        ids: list[int] = []
        with self.atomic():
            for c in changes:
                cur = self._conn.execute(
                    """INSERT INTO watcher_changes
                       (watcher_id, entity_id, kind, ref_key, subject, predicate, object,
                        from_status, to_status, citation_json, detected_at, run_job_id)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (watcher_id, c.entity_id, c.kind.value, c.ref_key, c.subject, c.predicate,
                     c.object, c.from_status.value if c.from_status else None,
                     c.to_status.value if c.to_status else None,
                     c.citation.model_dump_json() if c.citation else None,
                     _iso(c.detected_at), c.run_job_id),
                )
                ids.append(cur.lastrowid)
            self._conn.commit()
        return ids

    def list_changes(
        self, *, watcher_id: int | None = None, limit: int = 100, before_id: int | None = None,
    ) -> list[WatcherChange]:
        clauses: list[str] = []
        params: list[object] = []
        if watcher_id is not None:
            clauses.append("watcher_id = ?")
            params.append(watcher_id)
        if before_id is not None:
            clauses.append("id < ?")
            params.append(before_id)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(limit)
        rows = self._conn.execute(
            f"SELECT * FROM watcher_changes {where} ORDER BY id DESC LIMIT ?", params,
        ).fetchall()
        return [self._watcher_change(r) for r in rows]

    def undelivered_changes(self) -> list[WatcherChange]:
        rows = self._conn.execute(
            "SELECT * FROM watcher_changes WHERE delivered_at IS NULL ORDER BY id",
        ).fetchall()
        return [self._watcher_change(r) for r in rows]

    def mark_delivered(self, change_ids: list[int], channels: list[str]) -> None:
        if not change_ids:
            return
        now, encoded = _iso(_now()), json.dumps(channels)
        with self.atomic():
            for cid in change_ids:
                self._conn.execute(
                    "UPDATE watcher_changes SET delivered_at = ?, delivered_channels = ? WHERE id = ?",
                    (now, encoded, cid),
                )
            self._conn.commit()

    def set_seen(self, user_id: int, watcher_id: int, last_change_id: int) -> None:
        self._conn.execute(
            """INSERT INTO watcher_seen (user_id, watcher_id, last_seen_change_id) VALUES (?, ?, ?)
               ON CONFLICT(user_id, watcher_id)
               DO UPDATE SET last_seen_change_id = excluded.last_seen_change_id""",
            (user_id, watcher_id, last_change_id),
        )
        self._conn.commit()

    def unseen_count(self, user_id: int, watcher_id: int) -> int:
        row = self._conn.execute(
            """SELECT COUNT(*) FROM watcher_changes
               WHERE watcher_id = ? AND id > COALESCE(
                   (SELECT last_seen_change_id FROM watcher_seen WHERE user_id = ? AND watcher_id = ?), 0)""",
            (watcher_id, user_id, watcher_id),
        ).fetchone()
        return row[0]

    def unseen_counts(self, user_id: int) -> dict[int, int]:
        rows = self._conn.execute(
            """SELECT wc.watcher_id AS wid, COUNT(*) AS n FROM watcher_changes wc
               WHERE wc.id > COALESCE(
                   (SELECT last_seen_change_id FROM watcher_seen ws
                    WHERE ws.user_id = ? AND ws.watcher_id = wc.watcher_id), 0)
               GROUP BY wc.watcher_id""",
            (user_id,),
        ).fetchall()
        return {r["wid"]: r["n"] for r in rows}

    def history_batch(self, entity_id: str, since: datetime) -> dict[str, Any]:
        """Everything an operator needs to see "what changed about this threat since `since`".

        Returns a dict with four buckets, each a plain list the API layer can serialise:

        - `investigations`: investigations relevant to this entity (by resolved_entity_id OR by a
          `target_key` that matches a known alias of the entity) whose `started_at` > since.
          The timeline strip at the top of /threats/<id>/history renders these.
        - `new_assessments`: (subject, predicate, object) triples that didn't exist before `since`.
          Filter is `assessments.first_seen > since` on rows where the entity is subject or object.
        - `touched_assessments`: triples that EXISTED before `since` (first_seen <= since) but got
          an update after it (updated_at > since). This is where "new corroborating source arrived"
          surfaces, without needing a status-history table — the operator sees "this assessment
          was touched" and clicks through to see the current citations.
        - `new_aliases`: aliases.origin='document' learned in a run newer than `since`
          (join via `investigations.started_at > since`).

        Note on time comparison: SQLite compares TEXT lexicographically, and we store all
        timestamps as ISO-8601 UTC, so string comparison IS a time comparison for our rows.
        """
        iso_since = _iso(since)
        investigations = self._conn.execute(
            """SELECT i.* FROM investigations i
               LEFT JOIN aliases a ON a.entity_id = ?
               WHERE i.started_at > ?
                 AND (i.resolved_entity_id = ?
                      OR i.target_key IN (SELECT normalized_alias FROM aliases WHERE entity_id = ?))
               GROUP BY i.id
               ORDER BY i.started_at DESC""",
            (entity_id, iso_since, entity_id, entity_id),
        ).fetchall()
        new_assessments = self._conn.execute(
            """SELECT * FROM assessments
               WHERE (subject_entity_id = ? OR object_entity_id = ?)
                 AND first_seen > ?
               ORDER BY first_seen DESC, id""",
            (entity_id, entity_id, iso_since),
        ).fetchall()
        touched_assessments = self._conn.execute(
            """SELECT * FROM assessments
               WHERE (subject_entity_id = ? OR object_entity_id = ?)
                 AND first_seen <= ? AND updated_at > ?
               ORDER BY updated_at DESC, id""",
            (entity_id, entity_id, iso_since, iso_since),
        ).fetchall()
        new_aliases = self._conn.execute(
            """SELECT al.* FROM aliases al
               LEFT JOIN investigations i ON i.id = al.investigation_id
               WHERE al.entity_id = ? AND al.origin = 'document'
                 AND (i.started_at > ? OR al.investigation_id IS NULL)
               ORDER BY al.alias""",
            (entity_id, iso_since),
        ).fetchall()
        return {
            "investigations": [self._investigation(r) for r in investigations],
            "new_assessments": [self._assessment(r) for r in new_assessments],
            "touched_assessments": [self._assessment(r) for r in touched_assessments],
            "new_aliases": [{"alias": r["alias"], "origin": r["origin"],
                             "investigation_id": r["investigation_id"]} for r in new_aliases],
        }

    def coverage_for_entity(self, entity_id: str) -> DocumentCoverage:
        """What the collection aimed at this threat actually yielded.

        Scope is the investigations that resolved to this entity — the collection that was aimed
        at it — not the whole store, which would mix in documents about unrelated targets. An
        entity that was never an investigation target reports an empty coverage, which reads
        correctly: nothing was collected *for* it.
        """
        rows = self._conn.execute(
            """SELECT d.stage AS stage, COUNT(*) AS documents
                 FROM investigation_documents link
                 JOIN investigations i ON i.id = link.investigation_id
                 JOIN documents d ON d.id = link.document_id
                WHERE i.resolved_entity_id = ?
                GROUP BY d.stage""",
            (entity_id,),
        ).fetchall()
        counts = {row["stage"]: row["documents"] for row in rows}
        return DocumentCoverage(
            collected=sum(counts.values()),
            validated=counts.get(Stage.VALIDATED.value, 0),
            unreadable=counts.get(Stage.FAILED.value, 0),
            off_topic=counts.get(Stage.IRRELEVANT.value, 0),
        )

    def assessment_keys(self) -> set[tuple[str, str, str]]:
        rows = self._conn.execute(
            "SELECT subject_entity_id, predicate, object_entity_id FROM assessments"
        ).fetchall()
        return {(r[0], r[1], r[2]) for r in rows}

    def assessment_keys_for_publishers(
        self, publisher_ids: Collection[int]
    ) -> set[tuple[str, str, str]]:
        """Every assessment key with at least one claim from any of these publishers.

        Used to rescore after a publisher merge or a reliability change without recomputing the
        whole store. Both publisher columns count: `publisher_id` is who hosted the document and
        `primary_publisher_id` is who wrote it, and scoring reads the weaker of the two.
        """
        ids = list(dict.fromkeys(publisher_ids))
        if not ids:
            return set()
        placeholders = ",".join("?" * len(ids))
        rows = self._conn.execute(
            f"""SELECT DISTINCT c.subject_entity_id, c.predicate, c.object_entity_id
                  FROM claims c
                  JOIN documents d ON d.id = c.document_id
                 WHERE (d.publisher_id IN ({placeholders})
                        OR d.primary_publisher_id IN ({placeholders}))
                   AND c.subject_entity_id IS NOT NULL
                   AND c.object_entity_id IS NOT NULL""",
            (*ids, *ids),
        ).fetchall()
        return {(r[0], r[1], r[2]) for r in rows}

    # -- entity summaries ----------------------------------------------------------

    def get_entity_summary(self, entity_id: str) -> StoredSummary | None:
        """The cached executive summary for this entity, or None when none was ever written."""
        row = self._conn.execute(
            "SELECT * FROM entity_summaries WHERE entity_id = ?", (entity_id,),
        ).fetchone()
        if row is None:
            return None
        return StoredSummary(
            entity_id=row["entity_id"], summary=row["summary"], fingerprint=row["fingerprint"],
            fact_count=row["fact_count"], prompt_version=row["prompt_version"],
            model=row["model"], created_at=_datetime(row["created_at"]) or _now(),
        )

    def save_entity_summary(
        self, *, entity_id: str, summary: str, fingerprint: str, fact_count: int,
        prompt_version: str, model: str | None,
    ) -> StoredSummary:
        """Insert or replace the entity's cached summary. One row per entity — regenerating
        overwrites, because an operator asking for a fresh summary is asking to replace the
        stale one, not to accumulate a history (the dossier export keeps the point-in-time copy)."""
        self._conn.execute(
            """INSERT INTO entity_summaries
               (entity_id, summary, fingerprint, fact_count, prompt_version, model, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT (entity_id) DO UPDATE SET
                 summary = excluded.summary, fingerprint = excluded.fingerprint,
                 fact_count = excluded.fact_count, prompt_version = excluded.prompt_version,
                 model = excluded.model, created_at = excluded.created_at""",
            (entity_id, summary, fingerprint, fact_count, prompt_version, model, _iso(_now())),
        )
        self._conn.commit()
        stored = self.get_entity_summary(entity_id)
        assert stored is not None  # just written under the store lock
        return stored

