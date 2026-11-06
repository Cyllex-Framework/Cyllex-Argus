from datetime import date, timedelta

import pytest

from cyllex_argus.knowledge.indicators import freshness_for, indicator_kind, sector_hint

TODAY = date(2026, 9, 30)


@pytest.mark.parametrize("days, expected", [
    (0, "active"), (89, "active"), (90, "active"), (91, "dormant"),
    (364, "dormant"), (365, "dormant"), (366, "historical"),
])
def test_freshness_boundaries(days, expected):
    assert freshness_for(TODAY - timedelta(days=days), TODAY) == expected


def test_freshness_unknown_without_a_date():
    assert freshness_for(None, TODAY) == "unknown"


def test_freshness_defaults_today_to_the_current_date():
    assert freshness_for(date.today()) == "active"


@pytest.mark.parametrize("value, expected", [
    ("https://evil.example/a", "url"), ("HTTP://evil.example", "url"),
    ("203.0.113.7", "ipv4"), ("2001:db8::1", "ipv6"),
    ("d" * 32, "md5"), ("A" * 40, "sha1"), ("0123456789abcdef" * 4, "sha256"),
    ("d" * 31, "other"), ("d" * 33, "other"), ("d" * 39, "other"), ("d" * 41, "other"),
    ("d" * 63, "other"), ("d" * 65, "other"), ("g" * 32, "other"),
    ("evil.example", "domain"), ("Sub.Evil-Site.example", "domain"),
    ("localhost", "other"), ("-bad.example", "other"), ("evil..example", "other"),
    ("evil.example/path", "other"), ("300.1.1.1", "other"), ("", "other"),
])
def test_indicator_kind(value, expected):
    assert indicator_kind(value) == expected


def test_sector_hint_is_case_insensitive_and_first_in_list_order_wins():
    assert sector_hint(["Acme Healthcare Group"]) == "healthcare"
    assert sector_hint(["Technology Government Bank"]) == "government"
    assert sector_hint(["Big Financial Services Co"]) == "financial services"
    assert sector_hint(["Acme", "Regional Energy Board"]) == "energy"


def test_sector_hint_is_none_without_a_match():
    assert sector_hint(["Acme Corp", "ACME"]) is None
    assert sector_hint([]) is None
