"""The shipped Admiralty starting grades.

Mostly invariants on the table itself. A typo in a domain here does not fail loudly — it just
silently never matches, and a national CERT quietly stays at the confidence floor. These tests
are the only thing that would notice.
"""

import pytest

from cyllex_argus.knowledge.publisher_identity import organisation_key
from cyllex_argus.knowledge.publisher_ratings import KNOWN_PUBLISHERS, known_rating


@pytest.mark.parametrize(("org_key", "expected"), [
    ("cisa.gov", "A"),          # national agency
    ("sec.gov", "A"),           # the victim's own accountable filing
    ("mandiant.com", "B"),      # first-hand incident response
    ("shadowserver.org", "B"),  # primary scanning data
    ("reuters.com", "C"),       # good record, no primary access
])
def test_the_grade_follows_the_track_record(org_key, expected):
    entry = known_rating(org_key)
    assert entry is not None and entry.reliability == expected


@pytest.mark.parametrize("org_key", [None, "", "medium.com", "some-random-blog.example"])
def test_an_unknown_publisher_stays_unjudged(org_key):
    """F is the right answer for most of the internet: nobody has judged it yet. The table is
    short on purpose — it is not a directory of the industry."""
    assert known_rating(org_key) is None


def test_every_domain_in_the_table_is_a_domain_the_matcher_can_produce():
    """The invariant that catches the silent failure.

    Matching is `organisation_key(publisher domain) == entry.domain`, and `organisation_key`
    returns the *registrable* domain. An entry written as "attack.mitre.org" or "www.cisa.gov"
    would therefore never match anything, and the publisher would sit at F forever with nothing
    to show that the table meant to cover it.
    """
    wrong = [e.domain for e in KNOWN_PUBLISHERS if organisation_key(e.domain) != e.domain]
    assert wrong == []


def test_the_table_is_internally_consistent():
    domains = [entry.domain for entry in KNOWN_PUBLISHERS]
    assert len(domains) == len(set(domains)), "a domain is listed twice"
    for entry in KNOWN_PUBLISHERS:
        assert entry.reliability in "ABC", f"{entry.domain}: only A, B and C are defensible here"
        assert entry.name and entry.rationale, f"{entry.domain}: a grade needs a reason"
        # The reason is shown to the operator who is being asked to accept the grade, so it has
        # to be a sentence about this source, not a label.
        assert len(entry.rationale) > 20, f"{entry.domain}: rationale is too thin to judge"


def test_a_new_publisher_from_a_known_organisation_does_not_start_at_the_floor(store):
    """End to end through the store: the grade has to reach the row, since F is the floor
    `scoring.score` multiplies by, not a neutral midpoint."""
    entry = known_rating(organisation_key("https://www.cisa.gov/alert/x"))
    assert entry is not None
    publisher = store.get_or_create_publisher(
        "CISA", domain="https://www.cisa.gov/alert/x", default_reliability=entry.reliability
    )
    assert publisher.reliability == "A"
