"""Build comparable claim keys for the evaluation, following the labeling contract.

A claim is scored only when it is asserted (not refuted), uses one of SCORED_PREDICATES and has the
case target (after alias canonicalization) as its subject or its object. Predictions and hand-made
labels go through the same filter, so precision and recall compare like with like.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Mapping
from typing import Any, Protocol

from cyllex_argus.evaluation.metrics import ClaimKey, Score, make_key, score_claims
from cyllex_argus.knowledge.models import Polarity, QuoteStatus
from cyllex_argus.knowledge.names import normalize_name

SCORED_PREDICATES = frozenset({"uses", "targets", "exploits", "attributed-to"})

# make_key normalizes "T1566.004" to "t1566 004", so accept either separator.
_TECHNIQUE_KEY = re.compile(r"^T\d{4}(?:[. ]\d{3})?$")

NameResolver = Callable[[str], str]
"""Maps any name to its canonical name (unknown names map to themselves)."""

TechniqueResolver = Callable[[str], str | None]
"""Maps a technique ID to the current ATT&CK ID, or None when it is unknown."""


class ClaimLike(Protocol):
    @property
    def subject_ref(self) -> str: ...
    @property
    def predicate(self) -> str: ...
    @property
    def object_ref(self) -> str: ...
    @property
    def object_type(self) -> str: ...
    @property
    def technique_id(self) -> str | None: ...
    @property
    def polarity(self) -> str: ...
    @property
    def quote_status(self) -> str: ...


def _build_key(
    subject: str,
    predicate: str,
    obj: str,
    object_type: str,
    technique_id: str | None,
    resolve_name: NameResolver,
    resolve_technique: TechniqueResolver,
) -> ClaimKey:
    if object_type == "attack-pattern" and technique_id:
        object_name = resolve_technique(technique_id) or technique_id
    else:
        object_name = resolve_name(obj)
    return make_key(resolve_name(subject), predicate, object_name)


def _exclusion(key: ClaimKey, polarity: str, target: str) -> str | None:
    """Why this claim is outside the labeling contract, or None when it is scored."""
    if polarity != Polarity.ASSERTS:
        return f"polarity is {polarity}, only asserted claims are scored"
    if key.predicate not in SCORED_PREDICATES:
        return f"predicate {key.predicate!r} is not scored"
    if target not in (key.subject, key.object):
        return "the target is neither subject nor object"
    return None


def scored_claim_keys(
    claims: Iterable[ClaimLike],
    target_name: str,
    resolve_name: NameResolver,
    resolve_technique: TechniqueResolver,
) -> set[ClaimKey]:
    """Keys of the predicted claims that count toward the score."""
    target = normalize_name(resolve_name(target_name))
    keys: set[ClaimKey] = set()
    for claim in claims:
        if claim.quote_status == QuoteStatus.REJECTED:
            continue
        key = _build_key(
            claim.subject_ref, claim.predicate, claim.object_ref, claim.object_type,
            claim.technique_id, resolve_name, resolve_technique,
        )
        if _exclusion(key, claim.polarity, target) is None:
            keys.add(key)
    return keys


def check_expected(
    entries: Iterable[Mapping[str, Any]],
    target_name: str,
    resolve_name: NameResolver,
    resolve_technique: TechniqueResolver,
) -> tuple[set[ClaimKey], list[str]]:
    """Keys of the hand-labeled claims that count toward the score, plus a warning per excluded label."""
    target = normalize_name(resolve_name(target_name))
    keys: set[ClaimKey] = set()
    warnings: list[str] = []
    for entry in entries:
        key = _build_key(
            entry["subject"], entry["predicate"], entry["object"], entry["object_type"],
            entry.get("technique_id"), resolve_name, resolve_technique,
        )
        reason = _exclusion(key, entry.get("polarity", Polarity.ASSERTS), target)
        if reason is None:
            keys.add(key)
        else:
            warnings.append(f"{entry['subject']} {entry['predicate']} {entry['object']}: {reason}")
    return keys, warnings


def expected_claim_keys(
    entries: Iterable[Mapping[str, Any]],
    target_name: str,
    resolve_name: NameResolver,
    resolve_technique: TechniqueResolver,
) -> set[ClaimKey]:
    return check_expected(entries, target_name, resolve_name, resolve_technique)[0]


def is_ttp_key(key: ClaimKey) -> bool:
    """A TTP claim: the target uses an ATT&CK technique (the object is a technique ID)."""
    return key.predicate == "uses" and _TECHNIQUE_KEY.match(key.object.upper()) is not None


def score_ttp_claims(predicted: set[ClaimKey], expected: set[ClaimKey]) -> Score:
    """Score only the TTP claims; its recall is the spec's 'TTP claim recall'."""
    return score_claims({k for k in predicted if is_ttp_key(k)}, {k for k in expected if is_ttp_key(k)})
