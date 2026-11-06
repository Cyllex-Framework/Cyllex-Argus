"""LLM-written executive summary, generated from assessments only (never from raw documents)."""

from __future__ import annotations

import hashlib
import json

from pydantic import BaseModel

from cyllex_argus.knowledge.models import Polarity, QuoteStatus
from cyllex_argus.knowledge.profile import Profile
from cyllex_argus.llm.base import LLMProvider, LLMRequest, LLMUsage

SUMMARY_PROMPT_VERSION = "summary-v5"

SYSTEM_PROMPT = """You write the opening executive summary of a cyber threat intelligence dossier
for a purple team: the first thing a reader sees, meant to tell them what this threat actually is.

You receive consolidated assessments as JSON. "facts" are the validated relationships, each with a
subject, predicate, object, a status and confidence, the number of independent sources, and the first
and last dates observed. "characterization" is a short list of verbatim, source-verified excerpts that
describe who the actor is: its nature, motivation and attributed origin (this language lives in the
sources, not in the relationships).

Write a briefing on the THREAT ITSELF, in English, as 4 to 7 sentences of flowing prose:
- open with what the sources DO establish: the actor's type and the tradecraft and objectives it is
  known for (its signature techniques, notable malware and tools, and what its activity aims at). Weave
  in its motivation and attributed origin where the input supports them: a financial motive is supported
  when the facts show ransomware or extortion; an origin only when a source states one, whether a state
  or a group defined by language or demographics (for example "a collective of English-speaking actors").
  Do not open with, or build the briefing around, what is not established: note a missing attribution at
  most once and briefly, never as the opening. Never invent a country, sponsor or motivation the input
  does not support;
- then its main aliases, and the tradecraft that characterises it (signature techniques, notable malware
  and tools);
- who and where it targets (sectors and regions);
- the span of observed activity, using the first and last observed dates when present (for example
  "active since 2008" or "reported through 2026").

Use the "characterization" excerpts for the actor's nature, motivation and origin when they are present,
and the facts for the tradecraft, targeting and dates. Write it as a presentation of the adversary a reader could brief from,
not as an audit of the evidence: do not list confidence scores or source counts, and do not grade each
claim one by one. You may add at most one short closing caveat, and only if a headline attribution is
genuinely contested. Use only facts and excerpts present in the input; never invent a name, date,
technique or detail. Write plain prose and do not use em-dashes or double hyphens; use commas, colons,
parentheses or separate sentences instead."""


class Summary(BaseModel):
    summary: str


MAX_CHARACTERIZATION_QUOTES = 8  # cap on verbatim excerpts handed to the summary beside the triples
# Identity predicates carry who/what/origin language (motivation, nationality, group nature); the other
# predicates are tradecraft and targeting, which already reach the summary as triples.
_CHARACTERIZATION_PREDICATES = ("attributed-to", "alias-of")


def _characterization(profile: Profile) -> list[dict]:
    """A capped set of verbatim, verified excerpts describing who the actor is: its motivation, nature
    and attributed origin. This language lives in quotes, not triples, so the summary cannot state it
    from the relationships alone. Only identity predicates and only verified quotes qualify, so a
    rejected (unverifiable or poisoned) excerpt can never reach the briefing. Highest confidence first."""
    out: list[dict] = []
    seen: set[str] = set()
    facts = sorted(
        (f for f in profile.facts if f.predicate in _CHARACTERIZATION_PREDICATES),
        key=lambda f: f.confidence, reverse=True,
    )
    for fact in facts:
        for cite in fact.citations:
            if cite.polarity is not Polarity.ASSERTS:
                continue
            if cite.quote_status not in (QuoteStatus.VERIFIED, QuoteStatus.VERIFIED_FUZZY):
                continue
            key = " ".join(cite.quote.split()).casefold()
            if not key or key in seen:
                continue
            seen.add(key)
            out.append({"quote": cite.quote, "source": cite.publisher})
            if len(out) >= MAX_CHARACTERIZATION_QUOTES:
                return out
    return out


def summary_payload(profile: Profile) -> dict:
    """The JSON the summary prompt sees. Assessments only — the raw document text never
    reaches this prompt, which is what lets the summary inherit the profile's provenance."""
    return {
        "entity": profile.entity.label,
        "type": profile.entity.stix_type,
        "aliases": profile.aliases,
        "facts": [
            {
                "subject": fact.subject.label, "predicate": fact.predicate, "object": fact.object.label,
                "status": fact.status.value, "confidence": fact.confidence,
                "independent_sources": fact.source_count,
                "first_seen": fact.first_seen.isoformat() if fact.first_seen else None,
                "last_seen": fact.last_seen.isoformat() if fact.last_seen else None,
            }
            for fact in profile.facts
        ],
        "characterization": _characterization(profile),
    }


def profile_fingerprint(profile: Profile) -> str:
    """Stable digest of everything the summary prompt would see, so a cached summary knows
    whether it is still the answer to the current knowledge.

    The facts are sorted here (and only here) before hashing: `build_profile`'s row order is
    stable in practice but not guaranteed by contract, and a reordering is not a knowledge
    change — it must not mark a good summary stale. The payload handed to the LLM keeps its
    original order so this function cannot change prompt output.
    """
    payload = summary_payload(profile)
    payload["facts"] = sorted(
        payload["facts"], key=lambda fact: json.dumps(fact, sort_keys=True),
    )
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def summarize_profile_detailed(profile: Profile, llm: LLMProvider) -> tuple[str, LLMUsage | None]:
    """The summary plus the provider's usage record, so a caller that caches the text can store
    which model wrote it. `usage` is None for providers that do not report it (the fake)."""
    request = LLMRequest(
        system=SYSTEM_PROMPT, content=json.dumps(summary_payload(profile), indent=2),
        prompt_version=SUMMARY_PROMPT_VERSION, agent="summary",
    )
    response = llm.complete_json(request, Summary)
    return response.output.summary.strip(), response.usage


def summarize_profile(profile: Profile, llm: LLMProvider) -> str:
    return summarize_profile_detailed(profile, llm)[0]
