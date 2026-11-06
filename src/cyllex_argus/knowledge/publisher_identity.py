"""Publisher identity: one row per ORGANISATION, not one per byline.

Publisher identity is not cosmetic in Argus — it is the unit of independence. `scoring.score`
keeps one latest piece of evidence per `publisher_id` and derives corroboration from how many
of those there are, so two rows for the same organisation read as two independent sources that
agree. Identity by name alone cannot hold that line: a real store collects "CISA",
"Cybersecurity and Infrastructure Security Agency", "CISA Advisory" and four more variants, all
publishing from cisa.gov, and each one becomes its own voice in the count.

So identity is taken from the registrable domain when the domain belongs to one organisation.
Two rules make that safe:

1. **Reduce to the registrable domain**, not the hostname: `www.cisa.gov`, `us-cert.cisa.gov`
   and `cisa.gov` are one organisation. This needs the public-suffix distinction, because
   `ncsc.gov.uk` reduced to two labels would be `gov.uk` — the entire British government.
   `_MULTI_LABEL_SUFFIXES` carries the suffixes that actually appear in CTI reporting rather
   than a vendored public-suffix list; an unknown multi-label suffix degrades to "too coarse to
   merge", which costs a duplicate row and never merges two different organisations.

2. **Refuse the domains that host unrelated publishers.** On medium.com or substack.com the
   domain says nothing about who wrote the piece, and folding them together would conflate
   genuinely independent researchers into one source. For those the byline is all we have, so
   identity falls back to the name and the duplicate rows stay.

Both failure directions were chosen deliberately: a missed merge leaves independence
*overstated* for one organisation, a wrong merge understates it for two. Overstating is the
error this module exists to remove, so it only merges where the domain is unambiguous — and a
merge that does happen can only lower a confidence score, never raise one.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

# A hostname label: letters, digits and hyphens. The last label is the TLD, so it must be
# alphabetic and at least two characters. Anything else is not a domain, whatever `urlsplit`
# says about it: it will report a hostname for a string holding a NUL byte or a space.
# A raw non-ASCII domain is refused rather than IDNA-encoded here: identity then falls back to
# the byline, which costs a duplicate row and never merges two unrelated publishers.
_HOSTNAME = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$")


def _hostname(value: str) -> str | None:
    """The hostname in `value`, or None when there is not one.

    Never raises. The domain reaching this module is Analyst output — model-written text from an
    untrusted document — and `urlsplit` raises ValueError on a stray bracket ("Invalid IPv6
    URL"). A domain nobody can parse simply does not identify an organisation.
    """
    raw = value.strip().lower()
    if not raw:
        return None
    # urlsplit only fills .hostname when it sees a scheme; a bare host parses as a path.
    try:
        host = urlsplit(raw if "//" in raw else "//" + raw).hostname
    except ValueError:
        return None
    return host.strip(".") or None if host else None

# Public-suffix entries with more than one label. Not exhaustive by design (see the module
# docstring): these are the ones CTI sources actually publish under — national CERTs, ministries
# and the country-code commercial suffixes. An entry here means "the label in front of this is
# the organisation".
_MULTI_LABEL_SUFFIXES = frozenset({
    # United Kingdom
    "ac.uk", "co.uk", "gov.uk", "ltd.uk", "me.uk", "net.uk", "nhs.uk", "org.uk", "plc.uk",
    "police.uk", "sch.uk",
    # Australia / New Zealand
    "asn.au", "com.au", "edu.au", "gov.au", "id.au", "net.au", "org.au",
    "ac.nz", "co.nz", "govt.nz", "net.nz", "org.nz",
    # Japan / Korea / Taiwan / China / Hong Kong / Singapore / Malaysia / Thailand / India
    "ac.jp", "co.jp", "go.jp", "ne.jp", "or.jp",
    "co.kr", "go.kr", "or.kr", "re.kr",
    "com.tw", "edu.tw", "gov.tw", "org.tw",
    "com.cn", "edu.cn", "gov.cn", "net.cn", "org.cn",
    "com.hk", "edu.hk", "gov.hk", "org.hk",
    "com.sg", "edu.sg", "gov.sg", "org.sg",
    "com.my", "edu.my", "gov.my", "org.my",
    "ac.th", "co.th", "go.th", "or.th",
    "ac.in", "co.in", "edu.in", "gov.in", "net.in", "nic.in", "org.in",
    # Americas
    "com.ar", "gob.ar", "com.br", "gov.br", "org.br", "com.co", "gov.co",
    "com.mx", "gob.mx", "org.mx", "com.pe", "gob.pe", "com.uy", "gub.uy",
    # Europe, Middle East, Africa
    "co.il", "gov.il", "org.il", "com.tr", "edu.tr", "gov.tr", "org.tr",
    "com.ua", "gov.ua", "co.za", "gov.za", "org.za", "com.sa", "gov.sa",
    "com.es", "gob.es", "com.pl", "gov.pl", "com.pt", "gov.pt",
    # The agency is the label in front of these, not the whole state: ANSSI is ssi.gouv.fr and
    # BSI is bsi.bund.de, so reducing to two labels would file every French or German ministry
    # as one source. Same for the EU institutions, which would otherwise all be `europa.eu`.
    "gouv.fr", "bund.de", "europa.eu",
    "co.at", "or.at", "co.hu", "com.cy", "com.gr", "gov.gr", "com.ro", "gov.ro",
    # Canada's federal government publishes everything under gc.ca; one government, one source.
    "gc.ca", "qc.ca", "on.ca",
})

# Domains where the registrable domain is the HOST, not the author: blogging platforms, code
# forges, social networks, file lockers and archives. Folding these together would merge
# independent researchers into a single source, which is the one error worse than a duplicate
# row. Matched against the full hostname and against the registrable domain, so
# `sites.google.com` is refused while `cloud.google.com` still resolves to Google.
_PLATFORM_DOMAINS = frozenset({
    "medium.com", "substack.com", "blogspot.com", "wordpress.com", "wordpress.org",
    "tumblr.com", "livejournal.com", "ghost.io", "hashnode.dev", "dev.to", "svbtle.com",
    "github.com", "github.io", "githubusercontent.com", "gitlab.com", "gitlab.io",
    "bitbucket.org", "sourceforge.net", "readthedocs.io", "gitbook.io", "notion.site",
    "linkedin.com", "x.com", "twitter.com", "facebook.com", "youtube.com", "youtu.be",
    "reddit.com", "mastodon.social", "infosec.exchange", "bsky.app", "t.me", "telegram.me",
    "news.ycombinator.com", "quora.com",
    "pastebin.com", "scribd.com", "slideshare.net", "issuu.com", "dropbox.com", "box.com",
    "sharepoint.com", "wetransfer.com", "mega.nz", "anonfiles.com",
    "netlify.app", "vercel.app", "pages.dev", "wixsite.com", "weebly.com", "squarespace.com",
    "herokuapp.com", "cloudfront.net", "amazonaws.com", "azurewebsites.net", "r2.dev",
    # Archives and caches republish someone else's work; the byline is the publisher.
    "archive.org", "archive.ph", "archive.today", "webcache.googleusercontent.com",
    # Google properties that host user content, refused ahead of the reduction to google.com.
    "sites.google.com", "docs.google.com", "drive.google.com", "groups.google.com",
})


def registrable_domain(value: str | None) -> str | None:
    """Reduce a URL or hostname to `example.com` / `ncsc.gov.uk`, or None when there is none.

    Accepts what the collectors actually hold: a bare hostname, a hostname with `www.`, a full
    URL, a URL with no scheme, a host with a port, or junk. Returns lowercase with no trailing
    dot. A hostname whose suffix is multi-label and unknown to `_MULTI_LABEL_SUFFIXES` keeps
    three labels, which is too specific to merge on — deliberately the harmless direction.
    """
    if not value:
        return None
    host = _hostname(value)
    # An IP literal identifies a machine, not an organisation.
    if host is None or host.replace(".", "").isdigit() or ":" in host:
        return None
    if not _HOSTNAME.match(host):
        return None
    labels = host.split(".")
    if ".".join(labels[-2:]) in _MULTI_LABEL_SUFFIXES:
        return ".".join(labels[-3:]) if len(labels) >= 3 else None
    return ".".join(labels[-2:])


def organisation_key(value: str | None) -> str | None:
    """The registrable domain when it identifies ONE organisation, else None.

    None means "this domain cannot stand for a publisher" — either there is no usable domain or
    it is a platform that hosts unrelated authors. Callers fall back to the byline.
    """
    if not value:
        return None
    host = _hostname(value)
    if host is not None and host in _PLATFORM_DOMAINS:
        return None
    domain = registrable_domain(value)
    if domain is None or domain in _PLATFORM_DOMAINS:
        return None
    return domain
