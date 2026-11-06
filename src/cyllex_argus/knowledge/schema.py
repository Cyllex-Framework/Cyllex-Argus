"""SQLite schema migrations. Append new migrations; never edit applied ones."""

MIGRATIONS: list[str] = [
    """
    CREATE TABLE publishers (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        name_key TEXT NOT NULL UNIQUE,
        domain TEXT,
        reliability TEXT NOT NULL DEFAULT 'F'
            CHECK (reliability IN ('A', 'B', 'C', 'D', 'E', 'F'))
    );
    CREATE TABLE documents (
        id INTEGER PRIMARY KEY,
        url TEXT,
        local_path TEXT,
        canonical_url TEXT UNIQUE,
        title TEXT NOT NULL,
        publisher_id INTEGER NOT NULL REFERENCES publishers(id),
        primary_publisher_id INTEGER REFERENCES publishers(id),
        published_at TEXT,
        retrieved_at TEXT NOT NULL,
        content_hash TEXT NOT NULL UNIQUE,
        raw_path TEXT NOT NULL,
        text TEXT NOT NULL,
        stage TEXT NOT NULL,
        failure_reason TEXT,
        analyzed_prompt_version TEXT
    );
    CREATE TABLE entities (
        id TEXT PRIMARY KEY,
        stix_type TEXT NOT NULL,
        canonical_name TEXT NOT NULL,
        external_id TEXT UNIQUE,
        attributes_json TEXT NOT NULL DEFAULT '{}'
    );
    CREATE TABLE aliases (
        normalized_alias TEXT NOT NULL,
        alias TEXT NOT NULL,
        entity_id TEXT NOT NULL REFERENCES entities(id),
        origin TEXT NOT NULL,
        evidence_claim_id INTEGER,
        PRIMARY KEY (normalized_alias, entity_id)
    );
    CREATE TABLE claims (
        id INTEGER PRIMARY KEY,
        document_id INTEGER NOT NULL REFERENCES documents(id),
        subject_ref TEXT NOT NULL,
        subject_type TEXT NOT NULL,
        predicate TEXT NOT NULL,
        object_ref TEXT NOT NULL,
        object_type TEXT NOT NULL,
        technique_id TEXT,
        polarity TEXT NOT NULL,
        quote TEXT NOT NULL,
        quote_status TEXT NOT NULL,
        observed_at TEXT,
        prompt_version TEXT NOT NULL,
        subject_entity_id TEXT REFERENCES entities(id),
        object_entity_id TEXT REFERENCES entities(id)
    );
    CREATE INDEX claims_key ON claims (subject_entity_id, predicate, object_entity_id);
    CREATE INDEX claims_document ON claims (document_id);
    CREATE TABLE assessments (
        id INTEGER PRIMARY KEY,
        subject_entity_id TEXT NOT NULL REFERENCES entities(id),
        predicate TEXT NOT NULL,
        object_entity_id TEXT NOT NULL REFERENCES entities(id),
        status TEXT NOT NULL,
        confidence INTEGER NOT NULL,
        admiralty TEXT NOT NULL,
        first_seen TEXT,
        last_seen TEXT,
        updated_at TEXT NOT NULL,
        UNIQUE (subject_entity_id, predicate, object_entity_id)
    );
    CREATE TABLE investigations (
        id INTEGER PRIMARY KEY,
        target TEXT NOT NULL,
        target_key TEXT NOT NULL,
        resolved_entity_id TEXT,
        started_at TEXT NOT NULL,
        finished_at TEXT,
        state TEXT NOT NULL,
        collected INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE investigation_documents (
        investigation_id INTEGER NOT NULL REFERENCES investigations(id),
        document_id INTEGER NOT NULL REFERENCES documents(id),
        PRIMARY KEY (investigation_id, document_id)
    );
    """,
    """
    CREATE INDEX IF NOT EXISTS assessments_object ON assessments (object_entity_id);
    CREATE INDEX IF NOT EXISTS aliases_entity ON aliases (entity_id);
    """,
    """
    CREATE TABLE IF NOT EXISTS pipeline_events (
        id INTEGER PRIMARY KEY,
        investigation_id INTEGER NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
        document_id INTEGER REFERENCES documents(id) ON DELETE CASCADE,
        stage TEXT NOT NULL,
        decision TEXT NOT NULL,
        reason TEXT,
        created_at TEXT NOT NULL,
        duration_ms INTEGER,
        input_tokens INTEGER,
        output_tokens INTEGER,
        cost_usd REAL,
        model TEXT,
        raw_prompt TEXT,
        raw_response TEXT
    );
    CREATE INDEX IF NOT EXISTS pipeline_events_investigation ON pipeline_events (investigation_id, created_at);
    CREATE INDEX IF NOT EXISTS pipeline_events_document ON pipeline_events (document_id, created_at);
    """,
    """
    ALTER TABLE claims ADD COLUMN investigation_id INTEGER REFERENCES investigations(id) ON DELETE SET NULL;
    CREATE INDEX IF NOT EXISTS claims_investigation ON claims (investigation_id);
    """,
    """
    ALTER TABLE aliases ADD COLUMN investigation_id INTEGER REFERENCES investigations(id) ON DELETE SET NULL;
    CREATE INDEX IF NOT EXISTS aliases_investigation ON aliases (investigation_id);
    """,
    """
    CREATE INDEX IF NOT EXISTS assessments_subject ON assessments (subject_entity_id);
    CREATE INDEX IF NOT EXISTS claims_object ON claims (object_entity_id);
    """,
    """
    ALTER TABLE publishers ADD COLUMN tlp TEXT
        CHECK (tlp IS NULL OR tlp IN ('clear', 'green', 'amber', 'amber-strict', 'red'));
    """,
    """
    -- ICD 203 analytic confidence (HIGH/MODERATE/LOW): a judgement about the ANALYSIS, not the
    -- SOURCES (that is what Admiralty measures). Derived from `confidence` by default; the
    -- operator can override + attach a free-text rationale that explains WHY.
    ALTER TABLE assessments ADD COLUMN analytic_confidence TEXT
        CHECK (analytic_confidence IS NULL OR analytic_confidence IN ('high', 'moderate', 'low'));
    ALTER TABLE assessments ADD COLUMN confidence_rationale TEXT;
    """,
    """
    -- Backfill ICD 203 for assessments that already exist. Mirrors knowledge.models.confidence_level
    -- exactly so a 0.5 → 0.6 upgrade produces the same badges as a fresh recompute would. Kept as
    -- a separate migration so the previous one stays untouched once applied (file convention).
    UPDATE assessments SET analytic_confidence = CASE
        WHEN status = 'contested' THEN 'low'
        WHEN status = 'corroborated' AND confidence >= 70 THEN 'high'
        WHEN confidence >= 40 THEN 'moderate'
        ELSE 'low'
    END WHERE analytic_confidence IS NULL;
    """,
    """
    -- Cooperative cancel for a running investigation. The pipeline checks this flag between
    -- documents in `_run_pending`; when set, it stops cleanly and marks the investigation as
    -- PAUSED (so a later `argus resume` or Resume button continues from where it left off).
    -- Cleared on every state transition to RUNNING (so an operator-initiated resume does not
    -- immediately re-cancel) and never read outside the pipeline.
    ALTER TABLE investigations ADD COLUMN cancel_requested INTEGER NOT NULL DEFAULT 0;
    """,
    """
    -- Recurring investigations: a cron expression plus the same parameters `argus investigate`
    -- takes. The scheduler thread in web.app queries this table every ~30s for enabled rows
    -- whose `next_run_at` has passed, enqueues an investigate job via the JobManager, and
    -- updates `last_run_at` + recomputes `next_run_at` via croniter. `last_job_id` lets the UI
    -- link each row to the latest job's events / outcome.
    CREATE TABLE IF NOT EXISTS scheduled_investigations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT NOT NULL,
        cron_expr TEXT NOT NULL,
        max_docs INTEGER,
        concurrency INTEGER NOT NULL DEFAULT 1,
        enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
        last_run_at TEXT,
        last_job_id TEXT,
        next_run_at TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS scheduled_investigations_next_run
        ON scheduled_investigations (enabled, next_run_at);
    """,
    """
    -- Human-readable explanation when an investigation lands in PAUSED. Set by the operator
    -- (ignored today), by `argus serve` startup orphan-recovery ("Server restart interrupted
    -- this run."), or by any future auto-pause path. The UI shows it as an amber banner on the
    -- investigation detail / dashboard pages so the operator knows WHY the run is paused
    -- without having to read the server log. Cleared whenever state transitions back to RUNNING.
    ALTER TABLE investigations ADD COLUMN paused_reason TEXT;
    """,
    """
    -- Cached executive summary per entity: the LLM-written answer to "what do I know about
    -- this threat?", generated from consolidated assessments only (never raw documents, see
    -- exporters/summary.py). Cached because it costs an LLM call: the UI reads it on every
    -- profile load, and regenerating on each render would bill the operator for scrolling.
    --
    -- `fingerprint` is the digest of the exact payload the prompt saw (exporters.summary.
    -- profile_fingerprint). The UI compares it against the current profile's fingerprint to
    -- tell "this summary still describes what we know" from "N facts have landed since" —
    -- a stale summary stays readable and visibly marked, because a slightly-old answer beats
    -- no answer while the operator decides whether to spend a regeneration.
    CREATE TABLE IF NOT EXISTS entity_summaries (
        entity_id TEXT PRIMARY KEY REFERENCES entities(id) ON DELETE CASCADE,
        summary TEXT NOT NULL,
        fingerprint TEXT NOT NULL,
        fact_count INTEGER NOT NULL,
        prompt_version TEXT NOT NULL,
        model TEXT,
        created_at TEXT NOT NULL
    );
    """,
    """
    -- Publisher identity by organisation, not by byline.
    --
    -- `scoring.score` counts independent sources by distinct `publisher_id`, so every extra row
    -- for the same organisation reads as another voice agreeing. A real store fragments badly:
    -- seven rows for CISA, five for Microsoft, four for NCSC-UK, all publishing from one domain.
    --
    -- `org_key` is the registrable domain when that domain belongs to one organisation
    -- (knowledge.publisher_identity.organisation_key, which refuses medium.com and friends).
    -- It is intentionally NOT unique: existing duplicates have to keep their rows until the
    -- operator runs `argus sources merge-duplicates`, and lookups resolve the lowest id.
    -- Filled on creation and backfilled whenever an existing row is touched by name, so
    -- fragmentation stops growing the moment this migration lands, with no data rewrite.
    ALTER TABLE publishers ADD COLUMN org_key TEXT;
    CREATE INDEX IF NOT EXISTS publishers_org_key ON publishers (org_key);

    -- Every byline ever seen for a publisher. Two jobs: `argus sources set-reliability` keeps
    -- working with the name the operator read in a document after that row was merged away, and
    -- a merge stops destroying evidence — the operator can still see which bylines one source
    -- row covers, which matters when the row is what corroboration is counted from.
    CREATE TABLE IF NOT EXISTS publisher_names (
        name_key TEXT PRIMARY KEY,
        publisher_id INTEGER NOT NULL REFERENCES publishers(id) ON DELETE CASCADE,
        name TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS publisher_names_publisher ON publisher_names (publisher_id);
    INSERT OR IGNORE INTO publisher_names (name_key, publisher_id, name)
        SELECT name_key, id, name FROM publishers;
    """,
    """
    -- `documents` had no index on either publisher column, so anything asking "what did this
    -- publisher publish?" was a full scan. Three callers do, and two of them run on a timer:
    -- the duplicate-publisher scan behind /api/health (every dashboard poll), the document
    -- count in the Sources table, and `assessment_keys_for_publishers` after a merge or a
    -- grade. The store shares one connection whose lock is held across execute AND the
    -- materialising fetch, so each of those scans blocks every pipeline write for its duration.
    CREATE INDEX IF NOT EXISTS documents_publisher ON documents (publisher_id);
    CREATE INDEX IF NOT EXISTS documents_primary_publisher ON documents (primary_publisher_id);
    """,
    """
    -- Multi-user auth. `username_key` is the case-folded uniqueness key; `username` keeps the
    -- display form. A deleted user is tombstoned (`deleted_at` set) so attribution survives,
    -- and the partial unique index frees the name for reuse once deleted.
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username_key TEXT NOT NULL,
        username TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL,
        disabled INTEGER NOT NULL DEFAULT 0,
        seeded_with_default INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        created_by INTEGER REFERENCES users(id),
        deleted_at TEXT
    );
    CREATE UNIQUE INDEX IF NOT EXISTS users_username_key
        ON users (username_key) WHERE deleted_at IS NULL;
    -- Per-user sessions. Only the token's hash is stored, so a DB read never yields a usable
    -- token. Deleting a user cascades its sessions.
    CREATE TABLE IF NOT EXISTS sessions (
        token_hash TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        created_at TEXT NOT NULL,
        last_seen_at TEXT NOT NULL,
        expires_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS sessions_user ON sessions (user_id);
    -- Attribution: who started each investigation, and who performed a user-initiated event.
    ALTER TABLE investigations ADD COLUMN created_by INTEGER REFERENCES users(id);
    ALTER TABLE pipeline_events ADD COLUMN actor_user_id INTEGER REFERENCES users(id);
    """,
    """
    -- Watchers (Delivery 1). A watcher IS a scheduled_investigations row with an owner; the
    -- diff/alert behaviour hangs off its runs. `watcher_id` on investigations records which
    -- watcher fired a run (attribution); runs started by hand leave it NULL.
    ALTER TABLE scheduled_investigations ADD COLUMN created_by INTEGER REFERENCES users(id);
    ALTER TABLE investigations ADD COLUMN watcher_id INTEGER REFERENCES scheduled_investigations(id);
    -- Per-watcher snapshot of the watched entity's assessed facts: ref_key -> status, as of the
    -- last completed run. The diff compares a fresh snapshot against this to find what changed.
    CREATE TABLE IF NOT EXISTS watcher_snapshots (
        watcher_id INTEGER NOT NULL REFERENCES scheduled_investigations(id) ON DELETE CASCADE,
        ref_key TEXT NOT NULL,
        status TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        PRIMARY KEY (watcher_id, ref_key)
    );
    -- Persisted change events that back the feed and the alert de-dup. `delivered_at` NULL means
    -- the event has not yet been pushed to webhooks.
    CREATE TABLE IF NOT EXISTS watcher_changes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        watcher_id INTEGER NOT NULL REFERENCES scheduled_investigations(id) ON DELETE CASCADE,
        entity_id TEXT REFERENCES entities(id),
        kind TEXT NOT NULL,
        ref_key TEXT NOT NULL,
        subject TEXT,
        predicate TEXT,
        object TEXT,
        from_status TEXT,
        to_status TEXT,
        citation_json TEXT,
        detected_at TEXT NOT NULL,
        run_job_id TEXT,
        delivered_at TEXT,
        delivered_channels TEXT
    );
    CREATE INDEX IF NOT EXISTS watcher_changes_watcher ON watcher_changes (watcher_id, id DESC);
    -- Per-user read state so "unseen" is personal, not global, in this multi-user product.
    CREATE TABLE IF NOT EXISTS watcher_seen (
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        watcher_id INTEGER NOT NULL REFERENCES scheduled_investigations(id) ON DELETE CASCADE,
        last_seen_change_id INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (user_id, watcher_id)
    );
    """,
]
