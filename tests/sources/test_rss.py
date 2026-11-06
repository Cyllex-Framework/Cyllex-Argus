from datetime import date

import httpx

from cyllex_argus.config.settings import FeedConfig
from cyllex_argus.documents.fetch import Fetcher
from cyllex_argus.sources.base import ResolvedTarget
from cyllex_argus.sources.rss import RssConnector
from tests.support import _public_resolver

RSS = b"""<?xml version="1.0"?><rss version="2.0"><channel><title>Vendor</title>
<item><title>Octo Tempest expands to ransomware</title><link>https://vendor.example/octo</link>
<pubDate>Tue, 10 Oct 2023 10:00:00 GMT</pubDate><description>New activity.</description></item>
<item><title>Weekly roundup</title><link>https://vendor.example/weekly</link>
<pubDate>Mon, 01 Jan 2024 10:00:00 GMT</pubDate><description>&lt;p&gt;Includes UNC3944 updates.&lt;/p&gt;</description></item>
<item><title>Unrelated</title><link>https://vendor.example/other</link>
<pubDate>Mon, 01 Jan 2024 10:00:00 GMT</pubDate><description>Nothing here.</description></item>
</channel></rss>"""

TARGET = ResolvedTarget(name="Scattered Spider", aliases=["Scattered Spider", "Octo Tempest", "UNC3944"])


def test_rss_filters_by_alias_sorts_newest_first_and_skips_broken_feeds():
    def handler(request):
        url = str(request.url)
        host = request.url.host
        # The Wayback rescue added in 0.17 fires on 404 and would otherwise go hunting for
        # broken.example in archive.org — which the mock would then serve the Vendor RSS to,
        # duplicating entries. Fail the wayback hop too so the broken feed stays broken.
        if host == "broken.example" or (host == "web.archive.org" and "broken.example" in url):
            return httpx.Response(404)
        return httpx.Response(200, content=RSS, headers={"content-type": "application/rss+xml"})

    fetcher = Fetcher(
        httpx.Client(transport=httpx.MockTransport(handler)),
        max_bytes=100_000, sleep=lambda s: None, resolve_host=_public_resolver,
    )
    logs = []
    connector = RssConnector(
        [FeedConfig(name="Broken", url="https://broken.example/feed"),
         FeedConfig(name="Vendor", url="https://vendor.example/feed")],
        fetcher, log=logs.append,
    )
    results = connector.search(TARGET)
    assert [r.url for r in results] == ["https://vendor.example/weekly", "https://vendor.example/octo"]
    assert results[0].publisher == "Vendor"
    assert results[0].published_at == date(2024, 1, 1)
    assert len(logs) == 1 and "Broken" in logs[0]
