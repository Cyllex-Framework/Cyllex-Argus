from datetime import date

from cyllex_argus.knowledge.dates import parse_loose_date
from cyllex_argus.knowledge.names import count_mentions, mentions_any, normalize_name


def test_normalize_name():
    assert normalize_name("Octo-Tempest") == "octo tempest"
    assert normalize_name("  UNC3944 ") == "unc3944"
    assert normalize_name("Storm_0875") == "storm 0875"
    assert normalize_name("Roasted 0ktapus!") == "roasted 0ktapus"


def test_count_mentions_whole_words_only():
    text = "UNC3944 and Octo Tempest; later octo-tempest. Spiderman is unrelated."
    assert count_mentions(text, ["UNC3944", "Octo Tempest"]) == 3
    assert count_mentions(text, ["Spider"]) == 0


def test_count_mentions_ignores_empty_aliases():
    assert count_mentions("anything", ["", "   "]) == 0


def test_mentions_any_matches_count_mentions_on_normalized_text():
    text = "UNC3944 and Octo Tempest; later octo-tempest. Spiderman is unrelated."
    normalized = normalize_name(text)
    assert mentions_any(normalized, ["Spider", "Octo-Tempest"])
    assert not mentions_any(normalized, ["Spider", "", "Tempest Octo"])


def test_parse_loose_date():
    assert parse_loose_date("2024-05-17") == date(2024, 5, 17)
    assert parse_loose_date("2024-05") == date(2024, 5, 1)
    assert parse_loose_date("2024") == date(2024, 1, 1)
    assert parse_loose_date("2024-05-17T10:00:00Z") == date(2024, 5, 17)
    assert parse_loose_date("May 2024") is None
    assert parse_loose_date("2024-13-01") is None
    assert parse_loose_date(None) is None


def test_parse_loose_date_rejects_unanchored():
    """Reject dates with unanchored patterns or trailing garbage."""
    assert parse_loose_date("2024/05/17") is None
    assert parse_loose_date("2024.05.17") is None
    assert parse_loose_date("20240517") is None
    assert parse_loose_date("2024-Q3") is None
    assert parse_loose_date("2024-W12") is None
    assert parse_loose_date("2024-05-17garbage") is None
    assert parse_loose_date("2024-051") is None
    assert parse_loose_date("12345") is None
