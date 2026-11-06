"""Validator rejects identity drafts whose name is a known tech / sector mistype.

This is the deterministic backstop for the Analyst's negative identity rules in
SYSTEM_PROMPT v2 — even if the LLM extracts "AWS" as an identity, the Validator
marks the claim rejected with a clear reason before it reaches the store.
"""

from __future__ import annotations

from cyllex_argus.knowledge.mistype import is_known_mistype, suggest_retype
from cyllex_argus.knowledge.models import ClaimDraft, Polarity
from cyllex_argus.pipeline.validator import Validator


def _draft(object_name: str, object_type: str = "identity") -> ClaimDraft:
    return ClaimDraft(
        subject="ZetaActor",
        subject_type="intrusion-set",
        predicate="targets",
        object=object_name,
        object_type=object_type,
        polarity=Polarity.ASSERTS,
        quote="verbatim quote from the document that we never verify at this layer",
    )


def test_known_tool_name_rejected_with_tech_reason():
    reason = Validator._identity_mistype_reason(_draft("AWS"))
    assert reason is not None
    assert "technology" in reason.lower() or "platform" in reason.lower()
    assert "analyst-v2" in reason


def test_known_sector_name_rejected_with_sector_reason():
    reason = Validator._identity_mistype_reason(_draft("Aerospace and Defense"))
    assert reason is not None
    assert "sector" in reason.lower()
    assert "attributes" in reason.lower()


def test_legitimate_identity_name_passes():
    """A real organization name must not be flagged — a false positive would nag the
    operator to drop a legitimate attribution."""
    assert Validator._identity_mistype_reason(_draft("Mahak Rayan Afraz")) is None
    assert Validator._identity_mistype_reason(_draft("Caesars Entertainment")) is None
    assert Validator._identity_mistype_reason(_draft("UK NHS")) is None


def test_non_identity_drafts_untouched():
    """A draft whose object_type is NOT identity goes through untouched — the mistype
    check is scoped to identity to avoid false positives on the tool side."""
    assert Validator._identity_mistype_reason(
        _draft("AWS", object_type="tool"),
    ) is None
    assert Validator._identity_mistype_reason(
        _draft("Cloudflare", object_type="tool"),
    ) is None


def test_case_insensitive_match():
    """The LLM sometimes capitalises or lowercases — the detector normalises first."""
    assert Validator._identity_mistype_reason(_draft("aws")) is not None
    assert Validator._identity_mistype_reason(_draft("CLOUDFLARE")) is not None
    assert Validator._identity_mistype_reason(_draft("  AWS  ")) is not None


# -- knowledge.mistype helpers exported for the Validator ------------------------------


def test_is_known_mistype_matches_both_lists():
    assert is_known_mistype("AWS") is True
    assert is_known_mistype("Aerospace and Defense") is True
    assert is_known_mistype("Mahak Rayan Afraz") is False


def test_suggest_retype_differentiates_tool_vs_sector():
    assert suggest_retype("AWS") == "tool"
    assert suggest_retype("Aerospace and Defense") == "sector-tag"
    assert suggest_retype("random company") is None


def test_suggest_retype_covers_015_audit_additions():
    """0.15 real-DB audit surfaced these patterns the detector missed. The additions
    are deliberately conservative — a false positive would nag the operator to drop a
    legitimate attribution."""
    # Tools: SaaS and collaboration platforms Scattered Spider's docs name as targets.
    assert suggest_retype("Salesforce") == "tool"
    assert suggest_retype("Signal") == "tool"
    assert suggest_retype("Zoom") == "tool"
    assert suggest_retype("Jira") == "tool"
    # Sector labels: generic categories, not organisations.
    assert suggest_retype("SaaS applications") == "sector-tag"
    assert suggest_retype("Maritime") == "sector-tag"
    assert suggest_retype("Media & Entertainment") == "sector-tag"
    assert suggest_retype("media and entertainment") == "sector-tag"  # alt spelling
    assert suggest_retype("Hospitality") == "sector-tag"
    assert suggest_retype("Government") == "sector-tag"
    assert suggest_retype("Education") == "sector-tag"


def test_suggest_retype_covers_banking_vocabulary():
    """The 0.17 Carbanak resume surfaced sector-shaped `targets` claims that this
    detector did not recognise: 'financial institutions', 'banks', 'financial sector'.
    All three are generic financial-sector synonyms the Analyst picks up verbatim from
    the document. Without them in the vocabulary, the Validator's capture path never
    fires and the actor ends with `attributes.sectors = {}` despite 38 targets claims.
    """
    assert suggest_retype("banks") == "sector-tag"
    assert suggest_retype("banking") == "sector-tag"
    assert suggest_retype("banking sector") == "sector-tag"
    assert suggest_retype("financial institutions") == "sector-tag"
    assert suggest_retype("financial sector") == "sector-tag"
    # Case/whitespace normalisation already proved by test_case_insensitive_match,
    # but check once on a new entry.
    assert suggest_retype("  Banks  ") == "sector-tag"
