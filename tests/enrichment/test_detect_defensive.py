"""detect_observable_type defends against Python 3.11+ URL-parse exceptions.

Python 3.11 changed `urllib.parse.urlparse` to raise `ValueError("Invalid IPv6 URL")`
on malformed IPv6 URLs. The ToddyCat investigation surfaced this: a Securelist
document with an IPv6-shaped indicator aborted the whole doc's processing. The fix
wraps the urlparse call so the classifier degrades silently.
"""

from __future__ import annotations

from cyllex_argus.enrichment.detect import detect_observable_type


def test_unclosed_ipv6_bracket_url_returns_none_not_raises():
    """Python 3.13 raises ValueError('Invalid IPv6 URL') on URLs with mismatched IPv6
    brackets. detect_observable_type must degrade silently so the whole document doesn't
    abort."""
    assert detect_observable_type("http://[::1/x") is None


def test_bracketed_non_ipv6_url_returns_none():
    """Python raises ValueError on a bracketed host that is not a valid IPv6 address.
    Same graceful degradation as the unclosed bracket case."""
    assert detect_observable_type("http://[not-ipv6]/foo") is None
    assert detect_observable_type("http://[::fg00]/x") is None


def test_valid_url_still_classifies():
    """The defensive wrap must not break the happy path."""
    assert detect_observable_type("https://evil.example/path") == "url"


def test_ipv6_bare_literal_still_classifies_as_ipv6_addr():
    """A bare IPv6 literal (without URL brackets) uses ipaddress.ip_address, not urlparse,
    and should classify correctly."""
    assert detect_observable_type("fe80::1") == "ipv6-addr"
    assert detect_observable_type("2001:db8::1") == "ipv6-addr"
