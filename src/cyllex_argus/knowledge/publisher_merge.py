"""Discover publisher rows that are the same organisation under different bylines.

The DISCOVERY half of the fix; `SQLiteStore.merge_publishers` does the work and the CLI
`argus sources merge-duplicates` ties them together — the same split as `entity_merge`.

Why it matters: `scoring.score` keeps one latest piece of evidence per `publisher_id` and reads
corroboration off how many of those there are. A store that holds CISA under seven bylines will
happily report a fact as corroborated by three independent sources when all three are CISA. The
grouping key is `publishers.org_key` (see `publisher_identity`), so rows are only ever grouped
when their registrable domain belongs to one organisation; a row with no key is never touched.

Merging can only remove supporters, so every assessment it changes gets *less* confident. That
is the honest direction, and it is why this runs as an explicit operator command rather than as
part of a migration: the operator should see the confidence move and know why.
"""

from __future__ import annotations

from dataclasses import dataclass

from cyllex_argus.knowledge.publisher_identity import organisation_key


@dataclass(frozen=True)
class PublisherRow:
    id: int
    name: str
    documents: int


@dataclass(frozen=True)
class DuplicateGroup:
    """Several rows that are one organisation. `keep` absorbs `drop`."""
    org_key: str
    keep: PublisherRow
    drop: tuple[PublisherRow, ...]

    @property
    def rows(self) -> int:
        return 1 + len(self.drop)


def organisation_keys(conn) -> dict[int, str]:
    """publisher id -> the organisation it belongs to, for every row that has one.

    Read-only and derived fresh, so a store that has never run the backfill still reports its
    duplicates — the health endpoint asks this question on every page load and must not write.

    Two sources, in order: the row's own `org_key` or `domain`, and failing that the registrable
    domain its documents were actually fetched from. The second is what rescues rows created from
    a byline alone — the Analyst reports "Microsoft Threat Intelligence" with no domain attached,
    and only the document URL knows it came from microsoft.com.

    Only `documents.publisher_id` counts, never `primary_publisher_id`: when CISA republishes
    Mandiant's reporting the URL is CISA's, and crediting mandiant.com with cisa.gov would invent
    exactly the kind of false identity this is here to prevent. A row whose documents span
    several organisations (a local-files or aggregator row) is left without a key, because
    guessing one is worse than keeping identity on the byline.
    """
    keys: dict[int, str] = {}
    undecided: list[int] = []
    for row in conn.execute("SELECT id, domain, org_key FROM publishers").fetchall():
        key = row["org_key"] or organisation_key(row["domain"])
        if key:
            keys[row["id"]] = key
        else:
            undecided.append(row["id"])
    if not undecided:
        return keys
    placeholders = ",".join("?" * len(undecided))
    seen: dict[int, set[str]] = {publisher_id: set() for publisher_id in undecided}
    rows = conn.execute(
        f"""SELECT publisher_id, url FROM documents
             WHERE publisher_id IN ({placeholders}) AND url IS NOT NULL""",
        tuple(undecided),
    ).fetchall()
    for row in rows:
        candidate = organisation_key(row["url"])
        if candidate:
            seen[row["publisher_id"]].add(candidate)
    for publisher_id, candidates in seen.items():
        if len(candidates) == 1:
            keys[publisher_id] = next(iter(candidates))
    return keys


def find_duplicate_publishers(conn, keys: dict[int, str] | None = None) -> list[DuplicateGroup]:
    """Group publisher rows by organisation and return the groups with more than one row.

    The surviving row is the one with the most documents, then the shortest name, then the
    lowest id. Most documents because it is the byline this store actually reports under;
    shortest name as the tiebreak because the canonical form is almost always the short one
    ("CISA" over "CISA Cybersecurity Advisory AA23-320A"). Every losing byline is preserved by
    `merge_publishers`, so the choice decides the label, not what is remembered.
    """
    # `keys` lets a caller that already derived them skip a second pass: the derivation scans
    # `documents` for every publisher without a stored org_key, and /api/health was asking the
    # same question twice on every dashboard poll.
    keys = organisation_keys(conn) if keys is None else keys
    rows = conn.execute(
        """SELECT p.id AS id, p.name AS name,
                  (SELECT COUNT(*) FROM documents d WHERE d.publisher_id = p.id) AS documents
             FROM publishers p ORDER BY p.id"""
    ).fetchall()

    by_org: dict[str, list[PublisherRow]] = {}
    for row in rows:
        key = keys.get(row["id"])
        if key:
            by_org.setdefault(key, []).append(
                PublisherRow(id=row["id"], name=row["name"], documents=row["documents"])
            )

    groups: list[DuplicateGroup] = []
    for org_key, candidates in by_org.items():
        if len(candidates) < 2:
            continue
        ranked = sorted(candidates, key=lambda r: (-r.documents, len(r.name), r.id))
        groups.append(DuplicateGroup(org_key=org_key, keep=ranked[0], drop=tuple(ranked[1:])))
    return sorted(groups, key=lambda g: (-g.rows, g.org_key))
