"""`_candidate_aliases` turns a search-engine-style target string into aliases that
`triage` can actually match against document text. The whole phrase stays on the list for
callers that want a literal match; capitalized multi-word runs come off it because they
are what threat-group names look like in English CTI.
"""

from __future__ import annotations

from cyllex_argus.pipeline.investigation import _candidate_aliases, _single_capitalized_tokens


def test_single_group_name_passes_through_unchanged():
    """A one-word target has nothing to extract — the alias list is just the input."""
    assert _candidate_aliases("APT29") == ["APT29"]


def test_two_word_group_name_passes_through_unchanged():
    """A two-word, all-capitalized target already looks like a group name — one alias is enough."""
    assert _candidate_aliases("Scattered Spider") == ["Scattered Spider"]


def test_long_query_extracts_the_leading_group_name():
    """The regression this fix targets: a 10-word query like a user would type into Google
    becomes an atomic alias under the old code, and triage drops every doc. Extracting
    'Midnight Blizzard' as its own alias is what lets the Microsoft blog match."""
    out = _candidate_aliases("Midnight Blizzard Microsoft January 2024 OAuth corporate email breach")
    assert "Midnight Blizzard Microsoft January 2024 OAuth corporate email breach" in out
    assert "Midnight Blizzard" in out


def test_single_capitalized_words_are_not_aliases():
    """A bare 'Microsoft' or 'January' would match every unrelated article; we only extract
    runs of 2+ consecutive capitalized words to keep triage useful."""
    out = _candidate_aliases("The Microsoft breach of January 2024")
    # 'Microsoft' and 'January' are capitalized but each stands alone — neither should surface.
    assert "Microsoft" not in out
    assert "January" not in out
    # The original full string stays, because callers that know what they typed get a literal fallback.
    assert out == ["The Microsoft breach of January 2024"]


def test_multiple_runs_each_become_an_alias():
    """When a target contains two separate proper-noun runs, both are kept so either hit
    makes a document pass triage."""
    out = _candidate_aliases("APT29 attacks SolarWinds Orion customers")
    assert "SolarWinds Orion" in out
    # 'APT29' alone is a single-word run and does not qualify under the ≥2 rule — the full-
    # target fallback still provides a literal match for it.
    assert "APT29 attacks SolarWinds Orion customers" in out


def test_numbers_break_the_run():
    """Numeric tokens like a year reset the run — '2024 OAuth' is not a group name."""
    out = _candidate_aliases("Dark Caracal 2024 Office attack")
    assert "Dark Caracal" in out
    # 'Office' is a single-word run after the year; it must not become an alias of its own.
    assert "Office" not in out


def test_leading_or_trailing_lowercase_does_not_break_things():
    """Users do type lowercase prefixes ('the midnight blizzard incident'). Nothing is
    extracted — the user gets the literal fallback, which is at least no worse than today."""
    out = _candidate_aliases("the midnight blizzard incident")
    # Nothing to extract (all tokens are lowercase or the run is <2 cap words), fallback kept.
    assert out == ["the midnight blizzard incident"]


def test_empty_input_returns_empty_list():
    """Resolve_target strips the target; a whitespace-only input bottoms out as [] so the
    caller can decide what to do rather than crashing on a stray alias."""
    assert _candidate_aliases("") == []
    assert _candidate_aliases("   ") == []


def test_duplicates_are_dropped_in_order():
    """When the extracted run equals the full target, the alias list keeps one copy and
    preserves insertion order (original first)."""
    out = _candidate_aliases("Scattered Spider")
    assert out == ["Scattered Spider"]


def test_single_capitalized_tokens_picks_proper_nouns():
    """Used to probe find_by_alias when the multi-word runs don't resolve — e.g. a target
    like 'APT29 Microsoft corporate email breach' has no multi-word proper noun ('APT29
    Microsoft' is not a group), but 'APT29' alone is a MITRE alias."""
    tokens = _single_capitalized_tokens("APT29 Microsoft corporate email breach 2024")
    assert tokens == ["APT29", "Microsoft"]


def test_single_capitalized_tokens_drops_short_and_lowercase():
    """Length<3 and lowercase tokens are not threat-group alias candidates."""
    assert _single_capitalized_tokens("A the on Of") == []
    assert _single_capitalized_tokens("the midnight blizzard incident") == []
    # A 3-char all-caps acronym IS worth trying ("SVR").
    assert _single_capitalized_tokens("SVR cloud operations") == ["SVR"]


def test_single_capitalized_tokens_preserves_order_and_dedupes():
    """When the same token appears twice ('APT29 attack by APT29'), only one probe fires."""
    assert _single_capitalized_tokens("APT29 attack by APT29 against Microsoft") == ["APT29", "Microsoft"]
