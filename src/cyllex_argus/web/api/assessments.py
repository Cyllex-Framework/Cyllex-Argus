"""ICD 203 analytic-confidence override for a single assessment.

The score() function already derives a HIGH/MODERATE/LOW level from the numeric confidence
and status (see `knowledge.models.confidence_level`). This endpoint lets a human analyst
override that derivation — because ICD 203 is explicitly a judgement about analytic
SOUNDNESS (alternative hypotheses, logic quality, evidence volume), not something a formula
can decide. Posting `level=null` clears the override and restores the derived value on the
next recompute.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from cyllex_argus.knowledge.models import AnalyticConfidence
from cyllex_argus.web.deps import open_services

router = APIRouter()


class AnalyticConfidenceUpdate(BaseModel):
    """Clearing the override: pass `level: null, rationale: null`."""

    level: AnalyticConfidence | None = None
    rationale: str | None = Field(None, max_length=2000)


@router.put("/assessments/{assessment_id}/analytic-confidence")
def set_analytic_confidence(assessment_id: int, body: AnalyticConfidenceUpdate, request: Request):
    with open_services(request) as services:
        updated = services.store.set_analytic_confidence(
            assessment_id, body.level, body.rationale,
        )
        if updated is None:
            raise HTTPException(status_code=404, detail="assessment not found")
        return {
            "id": updated.id,
            "analytic_confidence": updated.analytic_confidence.value if updated.analytic_confidence else None,
            "confidence_rationale": updated.confidence_rationale,
        }
