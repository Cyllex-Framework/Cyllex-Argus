"""A dossier that does not declare its coverage is a misleading dossier.

`argus export` used to print 25 facts with no hint that 15 of the 40 documents collected for the
threat were never read. These tests hold the line that the file says so, and says what the gap
does and does not mean.
"""

from datetime import date

import pytest

from cyllex_argus.exporters.markdown import render_markdown
from cyllex_argus.knowledge.models import AliasOrigin, DocumentCoverage, NewDocument, Stage
from cyllex_argus.knowledge.profile import build_profile


@pytest.fixture
def entity(store):
    return store.create_entity("intrusion-set", "Scattered Spider", AliasOrigin.USER)


def _collect(store, investigation_id: int, tag: str, stage: Stage) -> None:
    document, _ = store.add_document(
        NewDocument(
            url=f"https://example.com/{tag}", canonical_url=f"https://example.com/{tag}",
            title=f"Report {tag}", publisher_id=store.get_or_create_publisher("Vendor").id,
            content_hash=f"hash-{tag}", raw_path=f"raw/{tag}", text="Some text",
        ),
        stage=stage,
    )
    store.link_document(investigation_id, document.id)


def test_coverage_counts_the_collection_aimed_at_this_threat(store, entity):
    investigation = store.create_investigation("Scattered Spider", entity.id)
    for tag, stage in (("a", Stage.VALIDATED), ("b", Stage.VALIDATED),
                       ("c", Stage.FAILED), ("d", Stage.IRRELEVANT)):
        _collect(store, investigation.id, tag, stage)

    coverage = store.coverage_for_entity(entity.id)

    assert (coverage.collected, coverage.validated) == (4, 2)
    assert (coverage.unreadable, coverage.off_topic) == (1, 1)
    assert coverage.complete is False


def test_an_entity_nobody_investigated_reports_an_empty_coverage(store, entity):
    """Correct rather than alarming: nothing was collected *for* it, so there is no gap to
    declare — and the exporter prints no evidence-base section at all."""
    coverage = store.coverage_for_entity(entity.id)
    assert coverage.collected == 0 and coverage.complete
    profile = build_profile(store, entity)
    assert "Evidence base" not in render_markdown(profile, None, date(2026, 10, 29), coverage=coverage)


def test_the_export_states_what_it_could_not_read(store, entity):
    profile = build_profile(store, entity)
    text = render_markdown(
        profile, None, date(2026, 10, 29),
        coverage=DocumentCoverage(collected=40, validated=25, unreadable=15, off_topic=0),
    )
    assert "Built from **25 of 40** documents" in text
    assert "15 could not be retrieved or parsed." in text
    # The sentence a reader cannot derive from the facts themselves.
    assert "may be absent from the reporting, or present only in a document" in text
    # And it comes before the findings, not in a footnote after them.
    assert text.index("## Evidence base") < text.index("## Assessed facts")


def test_a_complete_collection_claims_no_gap(store, entity):
    profile = build_profile(store, entity)
    text = render_markdown(
        profile, None, date(2026, 10, 29),
        coverage=DocumentCoverage(collected=25, validated=25, unreadable=0, off_topic=0),
    )
    assert "Built from **25 of 25** documents" in text
    assert "could not be retrieved" not in text
