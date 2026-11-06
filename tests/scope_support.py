"""Fixtures for the investigation scope: a second investigation and claims with a chosen investigation id."""

from __future__ import annotations

from cyllex_argus.knowledge.models import (
    Assessment,
    AssessmentStatus,
    ClaimDraft,
    NewDocument,
    Polarity,
    QuoteStatus,
)
from cyllex_argus.knowledge.sqlite_store import SQLiteStore
from tests.support import SPIDER, World

VOICE = "attack-pattern--00000000-0000-4000-8000-000015660004"
BLACKCAT = "malware--00000000-0000-4000-8000-000000001068"
RCLONE = "tool--00000000-0000-4000-8000-000000001040"


def add_second_investigation(world: World) -> int:
    """A second investigation of the same threat (the seeded world holds investigation 1); returns its id."""
    with SQLiteStore(world.paths.db_file) as store:
        return store.create_investigation("Scattered Spider", SPIDER).id


def add_scoped_claim(
    world: World, investigation_id: int | None, object_id: str, *, object_name: str = "Object",
    object_type: str = "malware", polarity: Polarity = Polarity.ASSERTS,
    status: QuoteStatus = QuoteStatus.VERIFIED, predicate: str = "uses", assess: bool = True,
) -> None:
    """One claim `SPIDER <predicate> object_id` written for `investigation_id` (None: an older claim)."""
    with SQLiteStore(world.paths.db_file) as store:
        n = store.connection.execute("SELECT COUNT(*) FROM documents").fetchone()[0]
        publisher = store.get_or_create_publisher("Scope Labs")
        doc, _ = store.add_document(NewDocument(
            url=f"https://scope.test/{n}", canonical_url=f"https://scope.test/{n}", title=f"Scope {n}",
            publisher_id=publisher.id, content_hash=f"scope-{n}", raw_path=f"raw/scope-{n}", text="t"))
        draft = ClaimDraft(subject="Scattered Spider", subject_type="intrusion-set", predicate=predicate,
                           object=object_name, object_type=object_type, quote="q", polarity=polarity)
        store.add_claim(doc.id, draft, status, "v1", SPIDER, object_id, investigation_id)
        if assess:
            store.upsert_assessment(Assessment(
                subject_entity_id=SPIDER, predicate=predicate, object_entity_id=object_id,
                status=AssessmentStatus.SINGLE_SOURCE, confidence=40, admiralty="C3"))
