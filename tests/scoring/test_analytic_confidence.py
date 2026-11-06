"""ICD 203 analytic-confidence level derived from (confidence, status)."""

from __future__ import annotations

from cyllex_argus.knowledge.models import (
    AnalyticConfidence,
    AssessmentStatus,
    confidence_level,
)


def test_contested_is_always_low_even_at_high_numeric_confidence():
    # ICD 203 HIGH says the analyst has few plausible alternative hypotheses. A CONTESTED
    # assessment has explicit competing evidence, so HIGH is semantically wrong regardless
    # of the number.
    assert confidence_level(95, AssessmentStatus.CONTESTED) is AnalyticConfidence.LOW


def test_single_source_never_reaches_high():
    # "HIGH" implies multiple independent lines of evidence; a lone source cannot cross it,
    # even with a perfect A-grade publisher pushing confidence into the 90s.
    assert confidence_level(90, AssessmentStatus.SINGLE_SOURCE) is AnalyticConfidence.MODERATE


def test_corroborated_above_threshold_is_high():
    assert confidence_level(80, AssessmentStatus.CORROBORATED) is AnalyticConfidence.HIGH


def test_moderate_band_between_40_and_70():
    assert confidence_level(50, AssessmentStatus.CORROBORATED) is AnalyticConfidence.MODERATE
    assert confidence_level(40, AssessmentStatus.SINGLE_SOURCE) is AnalyticConfidence.MODERATE


def test_below_40_is_low():
    assert confidence_level(10, AssessmentStatus.CORROBORATED) is AnalyticConfidence.LOW
    assert confidence_level(0, AssessmentStatus.SINGLE_SOURCE) is AnalyticConfidence.LOW
