"""Domain model: documents, claims (what sources say) and assessments (what Argus concludes)."""

from __future__ import annotations

from datetime import date, datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel

Reliability = Literal["A", "B", "C", "D", "E", "F"]
StixType = Literal[
    "intrusion-set", "campaign", "malware", "tool", "attack-pattern",
    "indicator", "vulnerability", "identity", "location",
]
Predicate = Literal[
    "uses", "attributed-to", "targets", "indicates", "variant-of", "exploits", "alias-of",
]


class Stage(StrEnum):
    COLLECTED = "collected"
    TRIAGED = "triaged"
    IRRELEVANT = "irrelevant"
    VALIDATED = "validated"
    FAILED = "failed"


class Polarity(StrEnum):
    ASSERTS = "asserts"
    REFUTES = "refutes"


class QuoteStatus(StrEnum):
    VERIFIED = "verified"
    VERIFIED_FUZZY = "verified_fuzzy"
    REJECTED = "rejected"


class AssessmentStatus(StrEnum):
    CORROBORATED = "corroborated"
    SINGLE_SOURCE = "single-source"
    CONTESTED = "contested"


class AnalyticConfidence(StrEnum):
    """ICD 203 (US DNI) analytic confidence levels. Separate from Admiralty source reliability:
    Admiralty answers 'how reliable is the publisher?'; ICD 203 answers 'how confident is the
    analyst in the judgement?' — a function of source quality AND of analytic logic, alternative
    hypotheses considered, and evidence volume."""

    HIGH = "high"
    MODERATE = "moderate"
    LOW = "low"


def confidence_level(confidence: int, status: AssessmentStatus) -> AnalyticConfidence:
    """Default mapping from Argus's numeric confidence + status to an ICD 203 level.

    The thresholds are intentionally conservative: a single-source claim never reaches HIGH
    even with a perfect A-grade publisher, because 'high' in ICD 203 implies multiple
    independent lines of evidence. CONTESTED can never be HIGH either — competing evidence
    is the explicit "we are not sure" signal.
    """
    if status is AssessmentStatus.CONTESTED:
        return AnalyticConfidence.LOW
    if status is AssessmentStatus.CORROBORATED and confidence >= 70:
        return AnalyticConfidence.HIGH
    if confidence >= 40:
        return AnalyticConfidence.MODERATE
    return AnalyticConfidence.LOW


class InvestigationState(StrEnum):
    RUNNING = "running"
    PAUSED = "paused"
    FINISHED = "finished"


class AliasOrigin(StrEnum):
    ATTACK = "attack"
    DOCUMENT = "document"
    USER = "user"


class Role(StrEnum):
    """What a user may do. Strictly ordered: a higher rank subsumes every lower one."""

    READER = "reader"
    OPERATOR = "operator"
    ADMIN = "admin"

    @property
    def rank(self) -> int:
        return {Role.READER: 0, Role.OPERATOR: 1, Role.ADMIN: 2}[self]


class User(BaseModel):
    id: int
    username: str
    role: Role
    disabled: bool = False
    created_at: str
    created_by: int | None = None
    # True only while the admin still holds the built-in default password; cleared on first change.
    seeded_with_default: bool = False
    # A deleted user is tombstoned, not removed, so attribution ("started by …") survives. The row
    # stops resolving by name (the name is freed) but still resolves by id.
    deleted_at: str | None = None


class TLP(StrEnum):
    """Traffic Light Protocol 2.0 (FIRST.org). Attaches a sharing restriction to a publisher
    and, through it, to every claim whose document was written by that publisher. The CLI
    `argus export --tlp-cap <tlp>` filters facts whose publisher's TLP exceeds the cap, so a
    report prepared for TLP:CLEAR sharing cannot leak content classified above that level.

    Ordering (least to most restrictive) is CLEAR < GREEN < AMBER < AMBER+STRICT < RED. A
    publisher with no TLP set is treated as "unclassified" — the export filter neither strips
    those facts nor assumes they are safe to share; the operator decides."""

    CLEAR = "clear"
    GREEN = "green"
    AMBER = "amber"
    AMBER_STRICT = "amber-strict"
    RED = "red"


TLP_ORDER: dict[str, int] = {
    TLP.CLEAR: 0, TLP.GREEN: 1, TLP.AMBER: 2, TLP.AMBER_STRICT: 3, TLP.RED: 4,
}


class Publisher(BaseModel):
    id: int
    name: str
    domain: str | None = None
    reliability: Reliability = "F"
    tlp: TLP | None = None
    # The registrable domain this publisher IS, when the domain stands for a single organisation
    # (knowledge.publisher_identity). It is the identity used to avoid filing one organisation as
    # several independent sources; None means identity falls back to the byline.
    org_key: str | None = None


class NewDocument(BaseModel):
    url: str | None = None
    local_path: str | None = None
    canonical_url: str | None = None
    title: str
    publisher_id: int
    published_at: date | None = None
    content_hash: str
    raw_path: str
    text: str


class Document(NewDocument):
    id: int
    retrieved_at: datetime
    primary_publisher_id: int | None = None
    stage: Stage
    failure_reason: str | None = None
    analyzed_prompt_version: str | None = None

    @property
    def effective_publisher_id(self) -> int:
        return self.primary_publisher_id or self.publisher_id


class Entity(BaseModel):
    id: str
    stix_type: StixType
    canonical_name: str
    external_id: str | None = None
    # Optional structured attributes (persisted in the entities.attributes_json column). Keys
    # Argus currently uses:
    # - `sector`: free-text sector label such as "energy", "financial-services" (for identity SDOs).
    # - `country`: ISO 3166 alpha-2 like "US", "DE" (for identity SDOs).
    # - `sectors`: list[str] on actor-shaped entities (intrusion-set / campaign / malware / tool)
    #   that holds the sector labels the actor targets, per STIX 2.1 threat-actor.sectors[].
    #   Values are kept lowercase and deduped.
    # Other entity types may populate it with their own keys; readers must treat the dict as open.
    attributes: dict[str, str | list[str]] = {}


class ClaimDraft(BaseModel):
    """A claim as extracted by the Analyst, before validation."""

    subject: str
    subject_type: StixType
    predicate: Predicate
    object: str
    object_type: StixType
    polarity: Polarity = Polarity.ASSERTS
    quote: str
    observed_at: date | None = None
    technique_id: str | None = None


class Claim(BaseModel):
    id: int
    document_id: int
    subject_ref: str
    subject_type: StixType
    predicate: Predicate
    object_ref: str
    object_type: StixType
    technique_id: str | None = None
    polarity: Polarity
    quote: str
    quote_status: QuoteStatus
    observed_at: date | None = None
    prompt_version: str
    subject_entity_id: str | None = None
    object_entity_id: str | None = None
    investigation_id: int | None = None  # None: written before claims were linked to an investigation


class Evidence(BaseModel):
    """One non-rejected claim, joined with its effective publisher, as input to scoring."""

    claim_id: int
    publisher_id: int
    reliability: Reliability
    polarity: Polarity
    published_at: date | None = None
    observed_at: date | None = None
    document_reliability: Reliability | None = None


class Assessment(BaseModel):
    id: int | None = None
    subject_entity_id: str
    predicate: Predicate
    object_entity_id: str
    status: AssessmentStatus
    confidence: int
    admiralty: str
    first_seen: date | None = None
    last_seen: date | None = None
    updated_at: datetime | None = None
    analytic_confidence: AnalyticConfidence | None = None
    confidence_rationale: str | None = None


class Citation(BaseModel):
    claim_id: int
    quote: str
    quote_status: QuoteStatus
    polarity: Polarity
    document_title: str
    location: str | None = None
    publisher: str
    published_at: date | None = None
    publisher_tlp: str | None = None  # None when the publisher has no TLP label set.


class DocumentCoverage(BaseModel):
    """How much of the collection aimed at one threat actually produced evidence.

    Reported on an exported profile so the reader can size the gap. `collected` is every document
    gathered by the investigations that resolved to this entity; `validated` produced verified
    claims; `unreadable` failed to fetch or parse; `off_topic` was ruled irrelevant at triage.
    """
    collected: int = 0
    validated: int = 0
    unreadable: int = 0
    off_topic: int = 0

    @property
    def complete(self) -> bool:
        """True when nothing was lost: every document was read and judged."""
        return self.unreadable == 0


class Investigation(BaseModel):
    id: int
    target: str
    resolved_entity_id: str | None = None
    started_at: datetime
    finished_at: datetime | None = None
    state: InvestigationState
    collected: bool = False
    # The user who launched this run, or None for a scheduler/CLI run (rendered "system").
    created_by: int | None = None
    # Human-readable explanation when state is PAUSED (e.g. "Server restart interrupted this
    # run."). None when the operator paused it themselves — the UI treats that as the baseline
    # case and does not render the banner.
    paused_reason: str | None = None


class ScheduledInvestigation(BaseModel):
    """A recurring `argus investigate` run. The scheduler thread fires it when `next_run_at`
    has passed, enqueues an investigate job via the JobManager, and recomputes `next_run_at`."""
    id: int
    target: str
    cron_expr: str
    max_docs: int | None = None
    concurrency: int = 1
    enabled: bool = True
    last_run_at: datetime | None = None
    last_job_id: str | None = None
    next_run_at: datetime
    created_at: datetime
    created_by: int | None = None  # the owner, when this schedule is a watcher


class ChangeKind(StrEnum):
    """What a watcher noticed between two runs. NEW/NEW_SOURCE are discoveries; the rest are
    status transitions on an already-known fact."""

    NEW = "new"                # a fact / IoC / technique not present before
    NEW_SOURCE = "new_source"  # a newly ingested document above the reliability floor
    VERIFIED = "verified"      # status moved up toward corroboration (single-source -> corroborated)
    WEAKENED = "weakened"      # status lost corroboration (corroborated -> single-source)
    CONTESTED = "contested"    # status moved to contested


class Watcher(BaseModel):
    """A standing monitor over one target. It is a `scheduled_investigations` row with an owner;
    `unseen_count` is per the calling user and filled by the read path, not stored on the row."""
    id: int
    target: str
    entity_id: str | None = None
    cron_expr: str
    enabled: bool = True
    created_by: int | None = None
    max_docs: int | None = None
    concurrency: int = 1
    last_run_at: datetime | None = None
    next_run_at: datetime
    created_at: datetime
    unseen_count: int = 0


class SnapshotEntry(BaseModel):
    """One row of a watcher's per-run snapshot: the status of one assessed fact."""
    ref_key: str
    status: AssessmentStatus


class WatcherChange(BaseModel):
    """A persisted change event that backs the feed and the webhook alert."""
    id: int
    watcher_id: int
    entity_id: str | None = None
    kind: ChangeKind
    ref_key: str
    subject: str | None = None
    predicate: str | None = None
    object: str | None = None
    from_status: AssessmentStatus | None = None
    to_status: AssessmentStatus | None = None
    citation: Citation | None = None
    detected_at: datetime
    run_job_id: str | None = None
