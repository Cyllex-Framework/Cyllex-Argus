"""Infer a STIX observable type from the free-text value of an indicator claim.

The Analyst extracts an `indicates` claim where the subject is the raw IOC string: `1.2.3.4`,
`evil.example`, `https://evil.example/x`, `d41d8cd98f00b204e9800998ecf8427e`, `CVE-2024-12345`.
The claim's subject_type is just "indicator"; it does not say whether that string is an IP, a
domain, a URL, a hash or a CVE id. The enrichment framework needs the specific observable type
to decide which enricher accepts it, so this module does the shape-based classification. It is
deliberately conservative: on anything ambiguous we return None and the pipeline skips enrichment.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

from cyllex_argus.enrichment.base import EnrichedIndicatorType

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_MD5_RE = re.compile(r"^[A-Fa-f0-9]{32}$")
_SHA1_RE = re.compile(r"^[A-Fa-f0-9]{40}$")
_SHA256_RE = re.compile(r"^[A-Fa-f0-9]{64}$")
_SHA512_RE = re.compile(r"^[A-Fa-f0-9]{128}$")
# A conservative hostname check: labels separated by dots, each label alnum+hyphen, no leading/trailing hyphens,
# at least one dot (to rule out single words), at most 253 chars overall.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$",
    re.IGNORECASE,
)


def detect_observable_type(value: str) -> EnrichedIndicatorType | None:
    """Classify `value` as one of the known observable types, or return None if ambiguous.

    Order matters because some strings parse as more than one shape (e.g. '1.2.3.4' is also a
    valid hostname per the strict DNS grammar). We check IP first, then CVE, then URL (because
    scheme is unambiguous), then hashes (ordered by length so a short hash does not shadow a
    longer one), then hostname.
    """
    candidate = (value or "").strip()
    if not candidate:
        return None
    try:
        ip = ipaddress.ip_address(candidate)
        return "ipv6-addr" if isinstance(ip, ipaddress.IPv6Address) else "ipv4-addr"
    except ValueError:
        pass
    if _CVE_RE.match(candidate):
        return "vulnerability"
    if "://" in candidate:
        try:
            parsed = urlparse(candidate)
        except ValueError:
            # Python 3.11+ raises ValueError on malformed IPv6 URLs ("Invalid IPv6 URL").
            # A classifier should degrade silently rather than crash the pipeline — the
            # observable just stays unclassified and the enrichment step skips it.
            return None
        if parsed.scheme in ("http", "https", "ftp", "ftps") and parsed.netloc:
            return "url"
    for pattern in (_SHA512_RE, _SHA256_RE, _SHA1_RE, _MD5_RE):
        if pattern.match(candidate):
            return "file-hash"
    if _HOSTNAME_RE.match(candidate):
        return "domain-name"
    return None
