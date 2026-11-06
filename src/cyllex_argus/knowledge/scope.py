"""The "this investigation" view: which assessments an investigation's own claims support."""

from __future__ import annotations

# The alias is interpolated into SQL, so it must never come from user input. Callers pass a literal from this set.
_ALLOWED_ALIASES = frozenset({"a", "assessments"})


def investigation_claim_filter(investigation_id: int, assessment_alias: str = "a") -> tuple[str, tuple]:
    """An `AND EXISTS (...)` fragment and its parameters, to append to a query over `assessments`.

    A claim contributes to investigation I when it carries I, asserts and was not rejected. An assessment belongs
    to the view when a contributing claim has the same (subject, predicate, object). Claims written before they
    were linked to an investigation (NULL) never match.
    """
    if assessment_alias not in _ALLOWED_ALIASES:
        raise ValueError(f"unknown assessment alias: {assessment_alias!r}")
    fragment = f"""AND EXISTS (
        SELECT 1 FROM claims sc
        WHERE sc.subject_entity_id = {assessment_alias}.subject_entity_id
          AND sc.predicate = {assessment_alias}.predicate
          AND sc.object_entity_id = {assessment_alias}.object_entity_id
          AND sc.investigation_id = ? AND sc.polarity = 'asserts' AND sc.quote_status <> 'rejected')"""
    return fragment, (investigation_id,)
