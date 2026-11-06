"""Observable-type detection: the single place that maps a free-text IOC to a STIX type."""

from __future__ import annotations

import pytest

from cyllex_argus.enrichment.detect import detect_observable_type


@pytest.mark.parametrize("value,expected", [
    # IPv4
    ("1.2.3.4", "ipv4-addr"),
    ("192.168.1.1", "ipv4-addr"),
    # IPv6
    ("::1", "ipv6-addr"),
    ("fe80::1", "ipv6-addr"),
    ("2001:db8::1", "ipv6-addr"),
    # CVE
    ("CVE-2024-12345", "vulnerability"),
    ("cve-2023-9", None),         # too few digits in the suffix
    ("CVE-2024-123456789", "vulnerability"),
    # URL
    ("http://evil.example/x", "url"),
    ("https://evil.example:8443/p?q=1", "url"),
    ("ftp://files.example", "url"),
    # Hashes
    ("d41d8cd98f00b204e9800998ecf8427e", "file-hash"),   # MD5
    ("da39a3ee5e6b4b0d3255bfef95601890afd80709", "file-hash"),   # SHA1
    ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "file-hash"),   # SHA256
    # Domain
    ("evil.example", "domain-name"),
    ("sub.evil.example", "domain-name"),
    ("UPPER.EXAMPLE", "domain-name"),
    # Ambiguous / junk
    ("", None),
    ("   ", None),
    ("evil", None),             # single label is not a domain
    ("not a domain!", None),
    ("CVE-not-a-cve", None),
])
def test_detect_observable_type(value, expected):
    assert detect_observable_type(value) == expected


def test_literal_ipv4_wins_over_domain_regex():
    """'1.2.3.4' is both a valid hostname per the DNS grammar and an IPv4 literal; IPv4 must win."""
    assert detect_observable_type("1.2.3.4") == "ipv4-addr"
