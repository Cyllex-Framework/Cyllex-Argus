"""Publisher identity is the unit of independence, so these tests are about corroboration.

`scoring.score` keeps one piece of evidence per publisher row and reads corroboration off how
many rows support a fact. Every test here exists because a store that files one organisation
under several bylines reports agreement between a source and itself.
"""

from concurrent.futures import ThreadPoolExecutor
from datetime import date

import pytest

from cyllex_argus.config.settings import ScoringConfig
from cyllex_argus.knowledge.models import AssessmentStatus, ClaimDraft, NewDocument
from cyllex_argus.knowledge.publisher_identity import organisation_key, registrable_domain
from cyllex_argus.knowledge.publisher_merge import find_duplicate_publishers
from cyllex_argus.pipeline.validator import Validator

CISA_ALERT = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a"

# Lifted from the attack_mini fixture so the end-to-end test can read its own result.
SPIDER = "intrusion-set--00000000-0000-4000-8000-000000001015"
QUOTE = "called the IT help desk and impersonated an employee"
TEXT = f"Octo Tempest operators {QUOTE} to reset MFA."


def _doc(store, publisher_id: int, tag: str, text: str = "Some text") -> object:
    """A document attributed to one publisher, built without the `new_doc` fixture.

    The fixture creates a publisher of its own as a side effect, and these tests count rows.
    """
    url = f"{CISA_ALERT}-{tag}"
    document, _ = store.add_document(NewDocument(
        url=url, canonical_url=url, title=f"Advisory {tag}", publisher_id=publisher_id,
        published_at=date(2025, 1, 10), content_hash=f"hash-{tag}", raw_path=f"raw/{tag}", text=text,
    ))
    return document


# -- what counts as one organisation ---------------------------------------------------------


@pytest.mark.parametrize(("value", "expected"), [
    # Subdomains and `www.` are the same organisation.
    ("https://www.cisa.gov/news-events/alerts/x", "cisa.gov"),
    ("us-cert.cisa.gov", "cisa.gov"),
    ("blog.talosintelligence.com", "talosintelligence.com"),
    # A multi-label public suffix must not be mistaken for the organisation: two labels of
    # ncsc.gov.uk is `gov.uk`, which is the entire British government.
    ("https://www.ncsc.gov.uk/report/y", "ncsc.gov.uk"),
    ("ncsc.gov.uk", "ncsc.gov.uk"),
    ("gov.uk", None),
    # No usable organisation anywhere in these.
    ("", None),
    (None, None),
    ("localhost", None),
    ("192.168.1.1", None),
    ("SEC", None),
])
def test_registrable_domain_reduces_a_host_to_its_organisation(value, expected):
    assert registrable_domain(value) == expected


@pytest.mark.parametrize("value", [
    # `urlsplit` raises ValueError("Invalid IPv6 URL") on a stray bracket, and this string is
    # Analyst output: model-written text taken from an untrusted document.
    "[bold]labs[/bold].example",
    "http://[::1/x",
    "https://exa mple.com",
    "\x00.example",
    ":::",
])
def test_a_domain_nobody_can_parse_is_not_an_organisation(value):
    """Never raise on Analyst output. Unparseable means "no organisation", not "crash"."""
    assert registrable_domain(value) is None
    assert organisation_key(value) is None


@pytest.mark.parametrize("value", [
    "https://medium.com/@researcher/the-post",
    "someone.substack.com",
    "https://github.com/org/repo",
    "https://sites.google.com/view/threat-notes",
    # An archive republishes someone else's work; the byline is the publisher, not the archive.
    "https://web.archive.org/web/20240101/https://www.sec.gov/a",
])
def test_a_platform_domain_is_not_an_organisation(value):
    """Merging on these would fuse independent researchers into one source — the error worse
    than a duplicate row, because it hides disagreement instead of inventing agreement."""
    assert organisation_key(value) is None
    assert registrable_domain(value) is not None  # it IS a domain; it just is not a publisher


@pytest.mark.parametrize("value", [CISA_ALERT, "cisa.gov", "https://cloud.google.com/blog/x"])
def test_an_organisation_domain_is_an_organisation(value):
    assert organisation_key(value) == registrable_domain(value)


# -- the store resolves a publisher by organisation ------------------------------------------


def test_two_bylines_from_one_domain_are_one_source(store):
    first = store.get_or_create_publisher("CISA", domain="cisa.gov")
    second = store.get_or_create_publisher(
        "Cybersecurity and Infrastructure Security Agency", domain="www.cisa.gov"
    )
    assert second.id == first.id
    assert len(store.list_publishers()) == 1
    # The byline is not lost: it is what the operator reads in the document.
    assert store.publisher_names(first.id) == [
        "CISA", "Cybersecurity and Infrastructure Security Agency",
    ]


def test_two_authors_on_one_platform_stay_independent(store):
    one = store.get_or_create_publisher("Researcher A", domain="https://medium.com/@a/post")
    two = store.get_or_create_publisher("Researcher B", domain="https://medium.com/@b/post")
    assert one.id != two.id


def test_a_publisher_first_seen_without_a_domain_adopts_one_later(store):
    """The Analyst reports a byline with no domain attached; the next document carries the URL."""
    bare = store.get_or_create_publisher("Unit 42")
    assert bare.org_key is None
    with_domain = store.get_or_create_publisher("Unit 42", domain="unit42.paloaltonetworks.com")
    assert with_domain.id == bare.id
    assert with_domain.org_key == "paloaltonetworks.com"


def test_any_byline_resolves_the_publisher(store):
    publisher = store.get_or_create_publisher("CISA", domain="cisa.gov")
    store.get_or_create_publisher("US-CERT", domain="cisa.gov")
    # Rating the organisation under the byline printed on the document has to work, whichever
    # byline the row itself ended up carrying.
    assert store.publisher_id_by_name("us-cert") == publisher.id
    assert store.set_publisher_reliability("US-CERT", "A").reliability == "A"
    with pytest.raises(KeyError):
        store.publisher_id_by_name("Nobody")


def test_the_same_organisation_from_two_threads_creates_one_row(store):
    """`get_or_create_publisher` runs on the Analyst's thread pool, and the domain lookup has to
    be as atomic as the byline lookup already was — see `argus-store-concurrency`."""
    with ThreadPoolExecutor(max_workers=8) as pool:
        ids = list(pool.map(
            lambda n: store.get_or_create_publisher(f"CISA byline {n}", domain=CISA_ALERT).id,
            range(8),
        ))
    assert len(set(ids)) == 1
    assert len(store.list_publishers()) == 1


# -- backfilling a store written before organisation identity existed -------------------------


def test_org_keys_are_backfilled_from_the_documents_a_publisher_published(store):
    """A legacy row has no domain of its own — only its documents know where they came from."""
    publisher = store.get_or_create_publisher("CISA Advisory")
    _doc(store, publisher.id, "a")
    assert store.backfill_publisher_org_keys() == 1
    assert store.get_publisher(publisher.id).org_key == "cisa.gov"


def test_a_publisher_whose_documents_span_organisations_is_left_alone(store):
    """A local-files or aggregator row has no single organisation behind it, and guessing one
    would invent the false identity this module exists to prevent."""
    publisher = store.get_or_create_publisher("Local files")
    _doc(store, publisher.id, "a")
    url = "https://www.ncsc.gov.uk/report/y"
    store.add_document(NewDocument(
        url=url, canonical_url=url, title="Report", publisher_id=publisher.id,
        content_hash="hash-ncsc", raw_path="raw/ncsc", text="Some text",
    ))
    assert store.backfill_publisher_org_keys() == 0
    assert store.get_publisher(publisher.id).org_key is None


@pytest.fixture
def fragmented(store):
    """A store as it looked before this feature existed: one organisation, three rows."""
    rows = []
    for index, name in enumerate(("CISA", "Cybersecurity and Infrastructure Security Agency", "US-CERT")):
        publisher = store.get_or_create_publisher(name)
        _doc(store, publisher.id, str(index))
        rows.append(publisher)
    return rows


def test_duplicates_are_found_by_domain_and_the_busiest_byline_survives(store, fragmented):
    second = fragmented[1]
    _doc(store, second.id, "extra")
    store.backfill_publisher_org_keys()

    [group] = find_duplicate_publishers(store.connection)
    assert group.org_key == "cisa.gov"
    assert group.rows == 3
    # Two documents against one each: the row this store actually reports under wins.
    assert group.keep.id == second.id
    assert {row.id for row in group.drop} == {fragmented[0].id, fragmented[2].id}


def test_a_single_row_organisation_is_not_a_duplicate(store):
    store.get_or_create_publisher("CISA", domain="cisa.gov")
    store.get_or_create_publisher("NCSC-UK", domain="ncsc.gov.uk")
    assert find_duplicate_publishers(store.connection) == []


def test_merging_repoints_documents_and_keeps_every_byline(store, fragmented):
    store.backfill_publisher_org_keys()
    keep, *drop = fragmented
    store.set_publisher_reliability("US-CERT", "A")  # a rating a human set deliberately

    moved = store.merge_publishers(keep.id, [row.id for row in drop])

    assert moved == 2
    assert [p.id for p in store.list_publishers()] == [keep.id]
    assert store.publisher_names(keep.id) == [
        "CISA", "Cybersecurity and Infrastructure Security Agency", "US-CERT",
    ]
    # The strongest letter in the group survives: resetting it to F would discard the only
    # analytic judgement anyone had made about this source.
    assert store.get_publisher(keep.id).reliability == "A"
    assert store.get_publisher(keep.id).org_key == "cisa.gov"


def test_merging_is_a_no_op_when_there_is_nothing_to_merge(store):
    publisher = store.get_or_create_publisher("CISA", domain="cisa.gov")
    assert store.merge_publishers(publisher.id, []) == 0
    assert store.merge_publishers(publisher.id, [publisher.id]) == 0
    with pytest.raises(KeyError):
        store.merge_publishers(publisher.id, [9999])


# -- what it all buys: corroboration that means something ------------------------------------


def test_one_organisation_under_two_bylines_stops_corroborating_itself(attack_store, attack_catalog):
    """The whole point, end to end.

    Two documents, one claim, one organisation — filed under two bylines because that is what a
    pre-fix store did. Scoring counts two independent publishers and calls the fact corroborated.
    After the merge it is what it always was: one source repeating itself.
    """
    validator = Validator(attack_store, attack_catalog, ScoringConfig(), today=lambda: date(2026, 9, 29))
    draft = ClaimDraft(
        subject="Octo Tempest", subject_type="intrusion-set", predicate="uses",
        object="Spearphishing Voice", object_type="attack-pattern",
        quote=QUOTE, technique_id="T1566.004",
    )
    for index, name in enumerate(("CISA", "US-CERT")):
        publisher = attack_store.get_or_create_publisher(name, default_reliability="A")
        validator.process(_doc(attack_store, publisher.id, str(index), text=TEXT), [draft], "analyst-v1")

    [before] = attack_store.assessments_involving(SPIDER)
    assert before.status is AssessmentStatus.CORROBORATED

    attack_store.backfill_publisher_org_keys()
    [group] = find_duplicate_publishers(attack_store.connection)
    keys = attack_store.assessment_keys_for_publishers([group.keep.id, *(r.id for r in group.drop)])
    assert keys == {(before.subject_entity_id, before.predicate, before.object_entity_id)}

    attack_store.merge_publishers(group.keep.id, [row.id for row in group.drop])
    validator.recompute(keys)

    [after] = attack_store.assessments_involving(SPIDER)
    assert after.status is AssessmentStatus.SINGLE_SOURCE
    assert after.confidence < before.confidence
