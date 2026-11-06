"""Recency-biased candidate ordering for scheduled (watcher) runs."""

from datetime import date
from types import SimpleNamespace

from cyllex_argus.pipeline.investigation import _order_candidates


def _c(name, published):
    return SimpleNamespace(url=name, published_at=published)


def test_prefer_recent_sorts_newest_first():
    cands = [
        _c("old", date(2020, 1, 1)),
        _c("new", date(2026, 10, 30)),
        _c("mid", date(2023, 6, 1)),
    ]
    out = _order_candidates(cands, prefer_recent=True)
    assert [c.url for c in out] == ["new", "mid", "old"]


def test_prefer_recent_false_preserves_order():
    cands = [_c("a", date(2020, 1, 1)), _c("b", date(2026, 1, 1))]
    out = _order_candidates(cands, prefer_recent=False)
    assert [c.url for c in out] == ["a", "b"]  # grouping/order from the connectors is kept


def test_undated_candidates_sort_last_under_prefer_recent():
    cands = [_c("dated", date(2025, 1, 1)), _c("undated", None)]
    out = _order_candidates(cands, prefer_recent=True)
    assert [c.url for c in out] == ["dated", "undated"]
