"""Read model used by `argus show` and the exporters: one entity and every assessed fact about it."""

from __future__ import annotations

from datetime import date

from pydantic import BaseModel

from cyllex_argus.knowledge.models import AssessmentStatus, Citation, Entity, Polarity
from cyllex_argus.knowledge.sqlite_store import SQLiteStore


class EntityRef(BaseModel):
    id: str
    stix_type: str
    name: str
    external_id: str | None = None
    attack: bool = False  # comes from the MITRE ATT&CK catalog, which exporters must not redefine
    attributes: dict[str, str | list[str]] = {}

    @property
    def label(self) -> str:
        return f"{self.name} ({self.external_id})" if self.external_id else self.name


class FactView(BaseModel):
    subject: EntityRef
    predicate: str
    object: EntityRef
    status: AssessmentStatus
    confidence: int
    admiralty: str
    first_seen: date | None = None
    last_seen: date | None = None
    citations: list[Citation]
    assessment_id: int | None = None
    analytic_confidence: str | None = None
    confidence_rationale: str | None = None

    @property
    def source_count(self) -> int:
        return len({c.publisher for c in self.citations if c.polarity is Polarity.ASSERTS})


class Profile(BaseModel):
    entity: EntityRef
    aliases: list[str]
    facts: list[FactView]


def _ref(entity: Entity, attack_ids: set[str]) -> EntityRef:
    return EntityRef(
        id=entity.id, stix_type=entity.stix_type, name=entity.canonical_name,
        external_id=entity.external_id, attack=entity.id in attack_ids,
        attributes=dict(entity.attributes),
    )


def build_profile(store: SQLiteStore, entity: Entity, investigation_id: int | None = None) -> Profile:
    """With `investigation_id`, only the facts (and citations) that investigation's own claims support.

    Entities and citations are batched: a profile with N assessments issues O(1) queries instead
    of O(N) (one per assessment for `get_entity`, one per assessment for `citations`).
    """
    assessments = store.assessments_involving(entity.id, investigation_id)
    needed_ids = {entity.id}
    for a in assessments:
        needed_ids.add(a.subject_entity_id)
        needed_ids.add(a.object_entity_id)
    entities = store.get_entities(needed_ids)
    entities[entity.id] = entity
    attack_ids = store.attack_entity_ids(entities)
    triples = [(a.subject_entity_id, a.predicate, a.object_entity_id) for a in assessments]
    cites = store.citations_batch(triples, investigation_id)
    facts = [
        FactView(
            subject=_ref(entities[a.subject_entity_id], attack_ids), predicate=a.predicate,
            object=_ref(entities[a.object_entity_id], attack_ids),
            status=a.status, confidence=a.confidence, admiralty=a.admiralty,
            first_seen=a.first_seen, last_seen=a.last_seen,
            citations=cites.get((a.subject_entity_id, a.predicate, a.object_entity_id), []),
            assessment_id=a.id,
            analytic_confidence=a.analytic_confidence.value if a.analytic_confidence else None,
            confidence_rationale=a.confidence_rationale,
        )
        for a in assessments
    ]
    return Profile(entity=_ref(entity, attack_ids), aliases=store.aliases_for(entity.id), facts=facts)
