"""Deterministic scoring: how 'the truth' about one fact is computed (spec section 7)."""

from __future__ import annotations

from datetime import date
from decimal import ROUND_HALF_UP, Decimal

from pydantic import BaseModel

from cyllex_argus.config.settings import ScoringConfig
from cyllex_argus.knowledge.models import (
    AnalyticConfidence,
    AssessmentStatus,
    Evidence,
    Polarity,
    Reliability,
    confidence_level,
)

RELIABILITY_ORDER = "ABCDEF"


class ScoreResult(BaseModel):
    status: AssessmentStatus
    confidence: int
    admiralty: str
    first_seen: date | None = None
    last_seen: date | None = None
    analytic_confidence: AnalyticConfidence


def _recency(published: date | None, cfg: ScoringConfig, today: date) -> float:
    # Three bands of trust: a fresh dated page keeps full weight, a known-ancient page is
    # discounted by stale_factor, and an UNDATED page is discounted by undated_factor (harsher
    # by default — the ICD 203 position that "we do not know when the claim was true" is a
    # bigger analytic hole than "the claim was true seven years ago"). Pre-undated-factor
    # scoring treated the second and third cases identically, which is the audit's finding.
    if published is None:
        return cfg.undated_factor
    return 1.0 if (today - published).days <= cfg.recency_years * 365 else cfg.stale_factor


def _effective_reliability(e: Evidence, cfg: ScoringConfig) -> Reliability:
    """The weaker (lower configured weight) of the primary and the hosting publisher's reliability.

    A page cannot borrow the weight of a vendor it claims to republish. Weights, not letter order,
    decide, because they are configurable. On a tie the primary publisher's letter is kept.
    """
    document = e.document_reliability
    if document is not None and cfg.reliability_weights[document] < cfg.reliability_weights[e.reliability]:
        return document
    return e.reliability


def score(
    evidence: list[Evidence], competing_publishers: set[int], cfg: ScoringConfig, today: date
) -> ScoreResult:
    supporting = [e for e in evidence if e.polarity is Polarity.ASSERTS]
    refuters = [e for e in evidence if e.polarity is Polarity.REFUTES]
    # A refuter contests the fact only when its reliability clears the configured threshold.
    # Without this, a single F- or E-grade publisher would flip a well-corroborated fact to
    # CONTESTED on its own; the agent-review PR 3 scoring finding is the regression this guards.
    credible_refuters = {
        e.publisher_id for e in refuters
        if cfg.reliability_weights[_effective_reliability(e, cfg)] >= cfg.contested_min_weight
    }

    latest: dict[int, Evidence] = {}
    for e in supporting:
        current = latest.get(e.publisher_id)
        if current is None or (e.published_at or date.min) > (current.published_at or date.min):
            latest[e.publisher_id] = e

    effective = {publisher: _effective_reliability(e, cfg) for publisher, e in latest.items()}

    product = 1.0
    for publisher, e in latest.items():
        weight = cfg.reliability_weights[effective[publisher]]
        product *= 1 - cfg.base_weight * weight * _recency(e.published_at, cfg, today)
    raw = round(100 * (1 - product), 9)
    confidence = int(Decimal(str(raw)).quantize(Decimal("1"), rounding=ROUND_HALF_UP))

    supporters = len(latest)
    contested = bool((credible_refuters | competing_publishers) - set(latest))
    if contested:
        status = AssessmentStatus.CONTESTED
    elif supporters >= 2:
        status = AssessmentStatus.CORROBORATED
    else:
        status = AssessmentStatus.SINGLE_SOURCE

    letter = min(effective.values(), key=RELIABILITY_ORDER.index, default="F")
    if contested:
        number = 4
    elif supporters >= 3:
        number = 1
    elif supporters == 2:
        number = 2
    else:
        number = 3

    seen = [d for e in supporting if (d := e.observed_at or e.published_at)]
    return ScoreResult(
        status=status,
        confidence=confidence,
        admiralty=f"{letter}{number}",
        first_seen=min(seen) if seen else None,
        last_seen=max(seen) if seen else None,
        analytic_confidence=confidence_level(confidence, status),
    )
