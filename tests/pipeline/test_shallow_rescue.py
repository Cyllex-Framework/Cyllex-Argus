"""Shallow-text heuristic for the "JS-rendered page" Wayback rescue. Fires when the
publisher serves a big HTML shell but the extractor pulls only nav/boilerplate — the
usual shape of a SPA that renders the article in JavaScript after page load. The MSRC
blog Jan 2024 postmortem is the canonical case: 50 KB of HTML, 1185 chars of extracted
text, which triage then rejects as "no mention of the target" even though the real
article is loaded with the group's name on it.

The pure heuristic is tested here; the end-to-end rescue (which hits network) is covered
by test_investigation.py as an integration path.
"""

from __future__ import annotations

from cyllex_argus.pipeline.investigation import _looks_shallow


def test_shallow_fires_on_msrc_blog_shape():
    """The exact signature the MSRC blog produces: ~50 KB page, ~1 KB of extracted text
    (2% ratio). Must fire — this is why the rescue exists."""
    assert _looks_shallow(fetched_bytes=50_000, extracted_chars=1200) is True


def test_shallow_does_not_fire_on_a_legitimately_short_cisa_alert():
    """A short CISA alert can be <5 KB total with ~2 KB of text. Dense content: 40% of
    the bytes are text. Must not fire — Wayback would be wasted."""
    assert _looks_shallow(fetched_bytes=5_000, extracted_chars=2_000) is False


def test_shallow_does_not_fire_on_a_full_microsoft_security_blog_post():
    """The Microsoft Security Blog version of the January 2024 postmortem is ~60 KB with
    17 KB of extracted text (28%). The static extractor got the real article; the ratio
    sits well above the threshold. Must not fire."""
    assert _looks_shallow(fetched_bytes=60_000, extracted_chars=17_000) is False


def test_shallow_requires_byte_threshold_to_filter_out_truly_tiny_pages():
    """A 2 KB page with 300 chars of text has a bad ratio (15%) but is below the byte
    threshold — some legitimate CTI publishers' RSS entries look like this. Firing here
    would waste a request on every short feed item."""
    assert _looks_shallow(fetched_bytes=2_000, extracted_chars=300) is False


def test_shallow_requires_text_to_be_short_in_absolute_terms():
    """A 100 KB page with 2 KB of text has a bad ratio (2%) but 2 KB IS a substantive
    article (think: a dense technical blog post with heavy ad / nav markup). Don't fire —
    the extractor got something to work with."""
    assert _looks_shallow(fetched_bytes=100_000, extracted_chars=2_000) is False


def test_shallow_fires_on_very_heavy_js_page():
    """A heavier SPA (modern vendor blog with 150 KB of React bundle, 500 chars of real
    article) is the exact pattern Wayback rescue should catch."""
    assert _looks_shallow(fetched_bytes=150_000, extracted_chars=500) is True


def test_shallow_handles_zero_text():
    """A page that extracted to no text at all (binary we misclassified, blank SPA) is
    the loudest shallow case."""
    assert _looks_shallow(fetched_bytes=30_000, extracted_chars=0) is True


def test_shallow_handles_zero_bytes_defensively():
    """Pathological input: nothing fetched. Don't false-positive — the caller already
    failed, no rescue would help."""
    assert _looks_shallow(fetched_bytes=0, extracted_chars=0) is False
