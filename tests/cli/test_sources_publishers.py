"""`argus sources rate-known`, `merge-duplicates` and `merge`.

Both commands change what the tool reports about the strength of its own evidence, so both are
gated behind an explicit confirmation and both rescore afterwards. These tests are about that
contract, not about the grouping rules (those live in tests/knowledge/test_publisher_identity.py).
"""

import pytest
from typer.testing import CliRunner

from cyllex_argus.cli import app as cli_module
from cyllex_argus.cli.app import app
from cyllex_argus.knowledge.models import NewDocument

from .test_commands import cli  # noqa: F401 - the fixture, reused verbatim

runner = CliRunner(env={"COLUMNS": "200"})

CISA = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a"


def _publisher_with_document(store, name: str, tag: str, url: str) -> int:
    publisher = store.get_or_create_publisher(name)
    store.add_document(NewDocument(
        url=url, canonical_url=url, title=f"Advisory {tag}", publisher_id=publisher.id,
        content_hash=f"hash-{tag}", raw_path=f"raw/{tag}", text="Some text",
    ))
    return publisher.id


@pytest.fixture
def seeded(cli):  # noqa: F811
    """A store the way a real one looks: one organisation, three bylines, nothing graded."""
    services = cli_module.services_factory()
    try:
        for index, name in enumerate(("CISA", "US-CERT", "Cybersecurity and Infrastructure Security Agency")):
            _publisher_with_document(services.store, name, str(index), f"{CISA}-{index}")
        _publisher_with_document(services.store, "Some Person's Blog", "x", "https://medium.com/@p/post")
    finally:
        services.close()
    return cli


def _reliabilities(cli) -> dict[str, str]:  # noqa: F811
    services = cli_module.services_factory()
    try:
        return {p.name: p.reliability for p in services.store.list_publishers()}
    finally:
        services.close()


# -- rate-known ------------------------------------------------------------------------------


def test_rate_known_explains_each_grade_and_changes_nothing_on_a_dry_run(seeded):
    result = runner.invoke(app, ["sources", "rate-known", "--dry-run"])

    assert result.exit_code == 0, result.output
    assert "CISA" in result.output
    # The reason is part of the output, because the operator is being asked to accept a judgement.
    assert "joint advisories with primary incident access" in result.output
    assert "Dry run" in result.output
    assert set(_reliabilities(seeded).values()) == {"F"}


def test_rate_known_refuses_to_act_without_confirmation(seeded):
    result = runner.invoke(app, ["sources", "rate-known"])
    assert result.exit_code == 1
    assert "Pass --yes" in result.output
    assert set(_reliabilities(seeded).values()) == {"F"}


def test_rate_known_grades_what_it_recognises_and_leaves_the_rest_at_f(seeded):
    result = runner.invoke(app, ["sources", "rate-known", "--yes"])

    assert result.exit_code == 0, result.output
    grades = _reliabilities(seeded)
    assert grades["CISA"] == "A"
    assert grades["US-CERT"] == "A"
    # A blog on a platform Argus cannot speak to stays unjudged, which is the accurate answer.
    assert grades["Some Person's Blog"] == "F"


def test_rate_known_does_not_overrule_the_analyst(seeded):
    services = cli_module.services_factory()
    try:
        services.store.set_publisher_reliability("CISA", "C")
    finally:
        services.close()

    assert runner.invoke(app, ["sources", "rate-known", "--yes"]).exit_code == 0
    # A grade on the row is somebody's judgement; the shipped table does not get to undo it.
    assert _reliabilities(seeded)["CISA"] == "C"

    assert runner.invoke(app, ["sources", "rate-known", "--yes", "--include-rated"]).exit_code == 0
    assert _reliabilities(seeded)["CISA"] == "A"


def test_rate_known_says_so_when_there_is_nothing_left_to_grade(seeded):
    runner.invoke(app, ["sources", "rate-known", "--yes"])
    result = runner.invoke(app, ["sources", "rate-known"])
    assert result.exit_code == 0, result.output
    assert "Nothing to grade" in result.output
    # And it points at the ones only a human can settle, rather than implying the job is done.
    assert "still F" in result.output


# -- merge-duplicates ------------------------------------------------------------------------


def test_merge_duplicates_shows_the_plan_and_changes_nothing_on_a_dry_run(seeded):
    result = runner.invoke(app, ["sources", "merge-duplicates", "--dry-run"])

    assert result.exit_code == 0, result.output
    assert "cisa.gov" in result.output
    assert "'CISA'" in result.output
    assert "Dry run" in result.output
    assert len(_reliabilities(seeded)) == 4


def test_merge_duplicates_warns_that_confidence_will_drop(seeded):
    result = runner.invoke(app, ["sources", "merge-duplicates"])
    assert result.exit_code == 1
    # The operator is told which direction the numbers move before being asked to agree.
    assert "Confidence will drop" in result.output
    assert len(_reliabilities(seeded)) == 4


def test_merge_duplicates_leaves_one_row_per_organisation(seeded):
    result = runner.invoke(app, ["sources", "merge-duplicates", "--yes"])

    assert result.exit_code == 0, result.output
    names = _reliabilities(seeded)
    assert len(names) == 2  # the one CISA row, plus the blog it refused to touch
    assert "Some Person's Blog" in names
    # The bylines survive the merge: the rating command still resolves the one that went away.
    assert runner.invoke(app, ["sources", "set-reliability", "US-CERT", "A"]).exit_code == 0
    assert set(_reliabilities(seeded).values()) == {"A", "F"}


def test_merge_duplicates_on_a_clean_store_says_so(cli):  # noqa: F811
    services = cli_module.services_factory()
    try:
        services.store.get_or_create_publisher("CISA", domain="cisa.gov")
    finally:
        services.close()
    result = runner.invoke(app, ["sources", "merge-duplicates"])
    assert result.exit_code == 0, result.output
    assert "No duplicate publishers" in result.output


# -- merge, by hand --------------------------------------------------------------------------


def test_merge_folds_named_publishers_and_reports_the_unknown_one(seeded):
    assert "Unknown publisher: Nobody" in runner.invoke(
        app, ["sources", "merge", "CISA", "Nobody", "--yes"]
    ).output

    result = runner.invoke(app, ["sources", "merge", "CISA", "US-CERT", "--yes"])
    assert result.exit_code == 0, result.output
    assert "US-CERT" not in _reliabilities(seeded)
    assert "CISA" in _reliabilities(seeded)


def test_merge_requires_confirmation(seeded):
    result = runner.invoke(app, ["sources", "merge", "CISA", "US-CERT"])
    assert result.exit_code == 1
    assert "Pass --yes" in result.output
    assert "US-CERT" in _reliabilities(seeded)


# -- list leads to the fix --------------------------------------------------------------------


def test_list_names_the_command_that_fixes_what_it_shows(seeded):
    """A table of unjudged sources states the problem and used to offer nothing. F is the floor
    `scoring.score` multiplies by, so it is suppressed confidence, not caution."""
    result = runner.invoke(app, ["sources", "list"])

    assert result.exit_code == 0, result.output
    assert "argus sources rate-known" in result.output
    assert "argus sources merge-duplicates" in result.output


def test_list_offers_nothing_when_there_is_nothing_to_offer(cli):  # noqa: F811
    services = cli_module.services_factory()
    try:
        services.store.get_or_create_publisher("CISA", domain="cisa.gov")
        services.store.set_publisher_reliability("CISA", "A")
    finally:
        services.close()
    result = runner.invoke(app, ["sources", "list"])
    assert result.exit_code == 0, result.output
    assert "argus sources" not in result.output
