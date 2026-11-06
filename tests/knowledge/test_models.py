from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from cyllex_argus.knowledge.models import ClaimDraft, Document, Polarity, Stage


def test_claim_draft_rejects_unknown_predicate():
    with pytest.raises(ValidationError):
        ClaimDraft(
            subject="Scattered Spider", subject_type="intrusion-set", predicate="loves",
            object="Okta", object_type="identity", quote="x" * 30,
        )


def test_claim_draft_defaults_to_asserts():
    draft = ClaimDraft(
        subject="Scattered Spider", subject_type="intrusion-set", predicate="uses",
        object="Spearphishing Voice", object_type="attack-pattern",
        quote="the actor called the help desk", technique_id="T1566.004",
    )
    assert draft.polarity is Polarity.ASSERTS


def test_effective_publisher_prefers_primary():
    doc = Document(
        id=1, title="t", publisher_id=1, primary_publisher_id=7, content_hash="h",
        raw_path="r", text="x", retrieved_at=datetime.now(UTC), stage=Stage.COLLECTED,
    )
    assert doc.effective_publisher_id == 7
    assert doc.model_copy(update={"primary_publisher_id": None}).effective_publisher_id == 1
