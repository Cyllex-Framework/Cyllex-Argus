"""Precision/recall of extracted claims against hand-labeled expectations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import NamedTuple

from cyllex_argus.knowledge.names import normalize_name


class ClaimKey(NamedTuple):
    subject: str
    predicate: str
    object: str


def make_key(subject: str, predicate: str, obj: str) -> ClaimKey:
    return ClaimKey(normalize_name(subject), predicate, normalize_name(obj))


@dataclass(frozen=True)
class Score:
    true_positives: int
    predicted: int
    expected: int

    @property
    def precision(self) -> float:
        return self.true_positives / self.predicted if self.predicted else 0.0

    @property
    def recall(self) -> float:
        return self.true_positives / self.expected if self.expected else 0.0

    def __add__(self, other: Score) -> Score:
        return Score(
            self.true_positives + other.true_positives,
            self.predicted + other.predicted,
            self.expected + other.expected,
        )


def score_claims(predicted: set[ClaimKey], expected: set[ClaimKey]) -> Score:
    return Score(len(predicted & expected), len(predicted), len(expected))
