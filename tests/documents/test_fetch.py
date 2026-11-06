import ipaddress

import httpx
import pytest

from cyllex_argus.documents.fetch import BROWSER_USER_AGENT, USER_AGENT, Fetcher, FetchError
from tests.support import INVALID_URLS


def _public_resolver(_host: str) -> list:
    return [ipaddress.ip_address("93.184.216.34")]


def _fetcher(handler, max_bytes=1_000, sleeps=None, resolve_host=_public_resolver):
    # Mirror build_client's default: in production every request carries the Argus UA unless
    # the caller overrides per-call. The 403-pivot tests rely on this being set.
    client = httpx.Client(
        transport=httpx.MockTransport(handler), headers={"User-Agent": USER_AGENT},
    )
    return Fetcher(
        client, max_bytes=max_bytes,
        sleep=(sleeps.append if sleeps is not None else lambda s: None),
        resolve_host=resolve_host,
    )


def test_success():
    fetcher = _fetcher(lambda r: httpx.Response(200, content=b"<html>hi</html>", headers={"content-type": "text/html"}))
    result = fetcher.fetch("https://example.com/a")
    assert result.content == b"<html>hi</html>"
    assert result.content_type == "text/html"
    assert result.final_url == "https://example.com/a"


def test_retries_server_errors_with_backoff():
    responses = iter([httpx.Response(503), httpx.Response(200, content=b"ok")])
    sleeps = []
    result = _fetcher(lambda r: next(responses), sleeps=sleeps).fetch("https://example.com/a")
    assert result.content == b"ok"
    assert sleeps == [1.0]


def test_client_errors_fail_immediately():
    """4xx failures don't hit the retry loop (that's for 5xx + network). The default
    Fetcher attempts the publisher URL once, then one Wayback hop as a last-ditch rescue —
    two requests total, no retries on either."""
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(404)

    with pytest.raises(FetchError, match="404"):
        _fetcher(handler).fetch("https://example.com/missing")
    # Original + Wayback. Each got a single shot; the 3-attempt retry loop is for 5xx/network.
    assert len(calls) == 2


def test_size_limit():
    sleeps = []
    with pytest.raises(FetchError, match="size limit"):
        _fetcher(lambda r: httpx.Response(200, content=b"x" * 2_000), sleeps=sleeps).fetch("https://example.com/big")
    assert sleeps == []


def test_size_limit_streamed():
    """Streamed response with generator body has no Content-Length header."""
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, content=iter([b"x" * 600, b"x" * 600]))

    sleeps = []
    with pytest.raises(FetchError, match="size limit"):
        _fetcher(handler, max_bytes=1_000, sleeps=sleeps).fetch("https://example.com/big")
    assert len(calls) == 1
    assert sleeps == []


def test_network_errors_exhaust_retries():
    def handler(request):
        raise httpx.ConnectError("boom")

    sleeps = []
    with pytest.raises(FetchError, match="network error"):
        _fetcher(handler, sleeps=sleeps).fetch("https://example.com/a")
    assert sleeps == [1.0, 2.0]


def test_redirect_loop():
    """Redirect loop raises FetchError."""
    def handler(request):
        raise httpx.TooManyRedirects("too many redirects", request=request)

    with pytest.raises(FetchError, match="HTTP error"):
        _fetcher(handler).fetch("https://example.com/a")


def test_corrupt_gzip():
    """Corrupt gzip content raises FetchError."""
    def handler(request):
        return httpx.Response(200, content=b"not gzip", headers={"content-encoding": "gzip"})

    with pytest.raises(FetchError, match="HTTP error"):
        _fetcher(handler).fetch("https://example.com/a")


def test_unsupported_protocol():
    """Unsupported protocol like ftp:// raises FetchError immediately."""
    def handler(request):
        raise httpx.UnsupportedProtocol("ftp")

    sleeps = []
    with pytest.raises(FetchError, match="unsupported URL"):
        _fetcher(handler, sleeps=sleeps).fetch("ftp://example.com/x")
    assert sleeps == []


@pytest.mark.parametrize("url", INVALID_URLS)
def test_invalid_urls_fail_immediately_without_retries(url):
    calls, sleeps = [], []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, content=b"ok")

    with pytest.raises(FetchError, match="invalid URL") as info:
        _fetcher(handler, sleeps=sleeps).fetch(url)
    assert calls == [] and sleeps == []
    assert isinstance(info.value.__cause__, httpx.InvalidURL)


@pytest.mark.parametrize("error", [UnicodeError("label too long"), ValueError("bad value")])
def test_unicode_and_value_errors_are_fetch_errors(error):
    sleeps = []

    def handler(request):
        raise error

    with pytest.raises(FetchError, match="invalid URL") as info:
        _fetcher(handler, sleeps=sleeps).fetch("https://example.com/a")
    assert sleeps == []
    assert info.value.__cause__ is error


# -- SSRF guard --------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("private_url", [
    "http://127.0.0.1/foo",
    "http://127.1.2.3/foo",
    "http://10.0.0.1/",
    "http://172.16.0.1/",
    "http://192.168.1.1/admin",
    "http://169.254.169.254/latest/meta-data/",   # AWS/GCP/Azure IMDS (link-local)
    "http://0.0.0.0/",
    "http://[::1]/",
    "http://[fe80::1]/",   # IPv6 link-local
    "http://[fc00::1]/",   # IPv6 unique-local (private)
])
def test_fetch_refuses_private_or_metadata_literal_ip(private_url):
    """SSRF guard refuses private, loopback, link-local and metadata URLs without a network call."""
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, content=b"should-never-be-read")

    with pytest.raises(FetchError, match="refusing|private|loopback|link-local|metadata"):
        _fetcher(handler).fetch(private_url)
    assert calls == []


def test_fetch_refuses_redirect_to_private_ip():
    """A 302 to a private IP must be caught before Argus issues the second request."""
    seen = []

    def handler(request):
        seen.append(str(request.url))
        if request.url.path == "/public":
            return httpx.Response(302, headers={"location": "http://127.0.0.1/stolen"})
        return httpx.Response(200, content=b"should-not-fetch")

    with pytest.raises(FetchError, match="refusing|loopback|private"):
        _fetcher(handler).fetch("http://93.184.216.34/public")
    assert seen == ["http://93.184.216.34/public"]


def test_fetch_follows_safe_redirect():
    """A 302 to another public URL is followed and its body returned."""
    def handler(request):
        if request.url.path == "/a":
            return httpx.Response(302, headers={"location": "http://93.184.216.34/b"})
        return httpx.Response(200, content=b"ok")

    result = _fetcher(handler).fetch("http://93.184.216.34/a")
    assert result.content == b"ok"
    assert result.final_url == "http://93.184.216.34/b"


def test_fetch_refuses_hostname_that_resolves_to_private():
    """A hostname whose DNS resolves to a private IP is refused."""
    def private_resolver(_host: str) -> list:
        return [ipaddress.ip_address("10.0.0.5")]

    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, content=b"should-not-happen")

    with pytest.raises(FetchError, match="refusing|private"):
        _fetcher(handler, resolve_host=private_resolver).fetch("http://evil.example/")
    assert calls == []


def test_fetch_bounds_redirect_chain():
    """An infinite redirect chain to safe hosts is bounded by max_redirects."""
    def handler(request):
        return httpx.Response(302, headers={"location": "http://93.184.216.34/loop"})

    with pytest.raises(FetchError, match="too many redirects|redirect"):
        _fetcher(handler).fetch("http://93.184.216.34/start")


def test_403_auto_retries_once_with_browser_ua():
    """Gov sites (CISA, SEC, cyber.gov.au, media.defense.gov) return 403 when they see the
    Argus UA by policy. The fetcher gives them one more shot with the browser UA before
    giving up — losing those sources silently was the worst outcome of the triage drop we
    saw on the Midnight Blizzard run."""
    calls = []

    def handler(request):
        calls.append(request.headers.get("user-agent"))
        if request.headers.get("user-agent") == BROWSER_USER_AGENT:
            return httpx.Response(200, content=b"ok")
        return httpx.Response(403)

    sleeps = []
    result = _fetcher(handler, sleeps=sleeps).fetch("https://cisa.gov/alert/aa24-057a")
    assert result.content == b"ok"
    # First attempt: Argus UA; second (post-403): browser UA. Nothing else.
    assert calls == [USER_AGENT, BROWSER_USER_AGENT]
    # The pivot runs through the same attempt loop as a network-level retry, so one backoff
    # tick fires before the second request. Harmless (sub-second against gov sites) and keeps
    # the control flow simple; the alternative was a dedicated branch that bypasses the loop.
    assert sleeps == [1.0]


def test_403_still_fails_when_browser_ua_also_blocked():
    """Pivoting once is the ceiling on UA retries: if the browser UA is also refused we
    stop pivoting UAs — but with Wayback fallback shipped alongside, one more hop fires
    through archive.org before the final 403 propagates. Keeps the fetcher's budget
    bounded (three requests total, one per path)."""
    calls = []

    def handler(request):
        # Record the UA + host so we can tell the three legs apart.
        calls.append((request.headers.get("user-agent"), request.url.host))
        return httpx.Response(403)

    with pytest.raises(FetchError, match="403"):
        _fetcher(handler).fetch("https://cisa.gov/alert/aa24-057a")
    # Argus UA + browser UA against publisher (the primary pivot), then the same two-shot
    # pattern against wayback (the rescue uses the same _httpx_fetch, so its own UA pivot
    # fires too — harmless, archive.org doesn't care which UA).
    assert calls == [
        (USER_AGENT, "cisa.gov"),
        (BROWSER_USER_AGENT, "cisa.gov"),
        (USER_AGENT, "web.archive.org"),
        (BROWSER_USER_AGENT, "web.archive.org"),
    ]


def test_403_does_not_pivot_when_caller_specified_ua():
    """When the retry endpoint already picked a specific UA (its "Retry as browser" button
    hits this path), we respect it. Pivoting again would silently discard the caller's
    choice — surprising if the caller tried an uncommon UA on purpose."""
    calls = []

    def handler(request):
        calls.append(request.headers.get("user-agent"))
        return httpx.Response(403)

    custom = "Mozilla/5.0 (something custom)"
    with pytest.raises(FetchError, match="403"):
        _fetcher(handler).fetch("https://cisa.gov/alert/aa24-057a", user_agent=custom)
    # Only one attempt with the caller's UA — no pivot.
    assert calls == [custom]


def test_401_does_not_trigger_browser_pivot():
    """401 means "we need credentials", not "we don't like your UA". The browser UA won't
    help, so we fail fast rather than wasting a request."""
    calls = []

    def handler(request):
        calls.append(request.headers.get("user-agent"))
        return httpx.Response(401)

    with pytest.raises(FetchError, match="401"):
        _fetcher(handler).fetch("https://private.example/api")
    assert calls == [USER_AGENT]


# ---- TLS-impersonation fallback (curl_cffi) ------------------------------------------

from cyllex_argus.documents.fetch import Fetched  # noqa: E402


def _fetcher_with_impersonator(handler, impersonator, max_bytes=1_000):
    """Variant of _fetcher that wires a stub TLS impersonator alongside the httpx mock,
    so the test can observe when the fallback fires."""
    client = httpx.Client(
        transport=httpx.MockTransport(handler), headers={"User-Agent": USER_AGENT},
    )
    return Fetcher(
        client, max_bytes=max_bytes, sleep=lambda s: None,
        resolve_host=_public_resolver, tls_impersonator=impersonator,
    )


def test_403_falls_back_to_tls_impersonator_when_browser_ua_also_fails():
    """CloudFlare / Akamai keep the 403 even after the browser UA pivot — they match on
    JA3/JA4 TLS fingerprint. With a TLS impersonator wired, Fetcher gets one more shot
    through curl_cffi (Chrome's full handshake) before giving up. This is the path that
    rescues CISA, NCSC, cyber.gov.au, media.defense.gov from the Argus pipeline."""
    httpx_calls = []
    def httpx_handler(request):
        httpx_calls.append(request.headers.get("user-agent"))
        return httpx.Response(403)

    impersonator_calls = []
    def fake_impersonator(url, max_bytes, resolver):
        impersonator_calls.append(url)
        return Fetched(url=url, final_url=url, content=b"<html>rescued</html>",
                       content_type="text/html")

    result = _fetcher_with_impersonator(httpx_handler, fake_impersonator).fetch(
        "https://cisa.gov/alert/aa24-057a"
    )
    assert result.content == b"<html>rescued</html>"
    # Two httpx attempts (Argus UA + browser UA), then one impersonator call.
    assert httpx_calls == [USER_AGENT, BROWSER_USER_AGENT]
    assert impersonator_calls == ["https://cisa.gov/alert/aa24-057a"]


def test_tls_impersonator_failure_is_propagated_as_the_original_403():
    """If the impersonator ALSO 403s or network-errors, the operator sees the original
    HTTP 403 message rather than a confusing "curl_cffi says X" one — the two paths are
    conceptually the same recovery and both failing means the publisher really meant no."""
    def httpx_handler(request):
        return httpx.Response(403)

    def failing_impersonator(url, max_bytes, resolver):
        raise FetchError(f"HTTP 403 for {url}")

    with pytest.raises(FetchError, match="HTTP 403"):
        _fetcher_with_impersonator(httpx_handler, failing_impersonator).fetch(
            "https://cisa.gov/alert/aa24-057a"
        )


@pytest.mark.parametrize("status", (404, 500))
def test_tls_impersonator_not_called_for_non_403_errors(status):
    """500 / network / 404 all propagate without touching the impersonator — a different
    TLS fingerprint doesn't fix those, so we don't waste a request."""
    def httpx_handler(request):
        return httpx.Response(status)
    impersonator_calls = []
    def impersonator(url, max_bytes, resolver):  # noqa: ARG001
        impersonator_calls.append(url)
        return Fetched(url=url, final_url=url, content=b"", content_type=None)
    with pytest.raises(FetchError, match=f"HTTP {status}"):
        _fetcher_with_impersonator(httpx_handler, impersonator).fetch(
            "https://example.com/x"
        )
    assert impersonator_calls == [], f"impersonator called for {status}"


def test_tls_impersonator_not_called_when_caller_specified_ua():
    """The retry endpoint's "Retry as browser" path (user_agent kwarg set) handles its own
    recovery. We respect that: do not pivot to a different stack if the caller already
    picked one."""
    def httpx_handler(request):
        return httpx.Response(403)

    impersonator_calls = []
    def impersonator(url, max_bytes, resolver):  # noqa: ARG001
        impersonator_calls.append(url)
        return Fetched(url=url, final_url=url, content=b"", content_type=None)

    with pytest.raises(FetchError, match="403"):
        _fetcher_with_impersonator(httpx_handler, impersonator).fetch(
            "https://example.com/x", user_agent="SomeCustomUA/1.0"
        )
    assert impersonator_calls == []


def test_fetcher_without_impersonator_behaves_as_before():
    """The default Fetcher (no tls_impersonator) must preserve the old failure mode so
    tests and callers that don't need the fallback keep working.

    Note: wayback fallback still applies, but with the mock transport that returns 403
    for ALL URLs including the wayback one, the net result is still a propagated 403."""
    def handler(request):
        return httpx.Response(403)

    with pytest.raises(FetchError, match="403"):
        _fetcher(handler).fetch("https://example.com/x")


# ---- Wayback Machine rescue -----------------------------------------------------------

def test_403_falls_back_to_wayback_after_tls_also_fails():
    """When the publisher 403s through httpx AND the TLS impersonator ALSO 403s (Akamai's
    Super Bot Fight tier, old-format CloudFlare rules, etc.), the Wayback Machine almost
    certainly has the paper cached — fetch that snapshot before giving up.

    This is what rescues SEC EDGAR and the Akamai-protected gov sites that curl_cffi can't
    get past."""
    calls = []
    def handler(request):
        url = str(request.url)
        calls.append(url)
        # Original URL is blocked; wayback replay returns success.
        if "web.archive.org" in url:
            return httpx.Response(200, content=b"<html>archived</html>",
                                   headers={"content-type": "text/html"})
        return httpx.Response(403)

    def failing_impersonator(url, max_bytes, resolver):
        raise FetchError(f"HTTP 403 for {url}")

    result = _fetcher_with_impersonator(handler, failing_impersonator).fetch(
        "https://vendor.example/some-report"
    )
    assert result.content == b"<html>archived</html>"
    # The returned Fetched carries the ORIGINAL url so downstream investigation_documents
    # dedup / display doesn't suddenly become archive-flavoured — operators still see the
    # publisher URL they typed, and the wayback hop is transparent.
    assert result.url == "https://vendor.example/some-report"
    # Order: Argus UA → browser UA → impersonator (via failing_impersonator) → wayback.
    # The two httpx calls to the publisher come first, then one call to the wayback URL.
    assert len([c for c in calls if "vendor.example" in c and "archive.org" not in c]) == 2
    assert any("web.archive.org/web/0/https://vendor.example/some-report" in c for c in calls)


def test_404_falls_back_to_wayback_without_tls_hop():
    """404 means "the publisher moved or removed this page". The TLS impersonator wouldn't
    help (same URL, same answer), so skip it and go straight to Wayback — which almost
    certainly has the paper cached if the operator was pointed at it from a research corpus."""
    calls = []
    def handler(request):
        url = str(request.url)
        calls.append(url)
        if "web.archive.org" in url:
            return httpx.Response(200, content=b"<html>archived old post</html>",
                                   headers={"content-type": "text/html"})
        return httpx.Response(404)

    impersonator_calls = []
    def impersonator(url, max_bytes, resolver):  # noqa: ARG001
        impersonator_calls.append(url)
        return Fetched(url=url, final_url=url, content=b"", content_type=None)

    result = _fetcher_with_impersonator(handler, impersonator).fetch(
        "https://example.com/old-post"
    )
    assert result.content == b"<html>archived old post</html>"
    # Impersonator must not have been called — 404 is a URL problem, not a fingerprint one.
    assert impersonator_calls == []


def test_wayback_rescue_does_not_recurse_on_wayback_urls():
    """A URL that already points at archive.org must not retry via archive.org (infinite
    recursion risk). The guard: skip the wayback branch when the URL already lives there."""
    calls = []
    def handler(request):
        calls.append(str(request.url))
        return httpx.Response(403)

    # Use a FAILING impersonator so the flow reaches the wayback branch — only then is the
    # recursion guard observable. If the impersonator succeeded, we'd never see the guard.
    def failing_impersonator(url, max_bytes, resolver):
        raise FetchError(f"HTTP 403 for {url}")

    with pytest.raises(FetchError, match="403"):
        _fetcher_with_impersonator(handler, failing_impersonator).fetch(
            "https://web.archive.org/web/0/https://foo.example/x"
        )
    # The handler fired for the Argus UA + browser UA attempts against archive.org directly.
    # Crucially, no FOURTH call with another wayback-wrapped URL — recursion was prevented.
    assert all("web.archive.org" in c for c in calls)
    assert len(calls) == 2


def test_wayback_rescue_not_used_for_5xx():
    """5xx means the server is temporarily broken, not that it refuses us. The httpx retry
    loop already covers that; adding a Wayback hop would delay the real recovery."""
    def handler(request):
        return httpx.Response(503)

    with pytest.raises(FetchError, match="503"):
        _fetcher_with_impersonator(handler, lambda u, m, r: Fetched(
            url=u, final_url=u, content=b"", content_type=None,
        )).fetch("https://example.com/x")


def test_wayback_rescue_not_used_when_caller_specified_ua():
    """The retry endpoint's 'Retry as browser' flow has already picked its path. Don't
    rewrite its URL out from under it — the operator picked that URL specifically."""
    calls = []
    def handler(request):
        calls.append(str(request.url))
        return httpx.Response(403)

    with pytest.raises(FetchError, match="403"):
        _fetcher_with_impersonator(handler, lambda u, m, r: Fetched(
            url=u, final_url=u, content=b"", content_type=None,
        )).fetch("https://example.com/x", user_agent="SomeUA/1.0")
    # Only the single httpx call with the caller's UA. No wayback, no impersonator.
    assert calls == ["https://example.com/x"]


# -- the rescue chain follows redirects, reports the truest status, and respects a policy -----


def test_impersonation_rescue_follows_the_redirect_the_waf_would_not_serve(monkeypatch):
    """The bug that cost three documents out of forty-six.

    `cisa.gov` 301s to `www.cisa.gov`, and Akamai answers httpx with 403 *before* it will serve
    that 301 — so the impersonator is the only path that ever sees the redirect. It used to
    report the 301 as a failure, and "HTTP 301" is not a Wayback trigger, so the chain died on a
    document one extra hop away.
    """
    hops = []

    class _Response:
        def __init__(self, status, headers, body=b""):
            self.status_code, self.headers, self._body = status, headers, body
        def iter_content(self, chunk_size=8192):
            yield self._body
        def close(self):
            pass

    def fake_get(url, **_kwargs):
        hops.append(url)
        if url == "https://cisa.gov/advisory":
            return _Response(301, {"location": "https://www.cisa.gov/advisory"})
        return _Response(200, {"content-type": "text/html"}, b"<html>advisory</html>")

    monkeypatch.setattr(
        "curl_cffi.requests.get", fake_get, raising=False,
    )
    from cyllex_argus.documents.fetch import curl_cffi_impersonate_fetch
    result = curl_cffi_impersonate_fetch(
        "https://cisa.gov/advisory", 1_000_000, _public_resolver
    )

    assert hops == ["https://cisa.gov/advisory", "https://www.cisa.gov/advisory"]
    assert result.content == b"<html>advisory</html>"
    # The original URL is what dedup keys on; the final hop is bookkeeping.
    assert result.url == "https://cisa.gov/advisory"
    assert result.final_url == "https://www.cisa.gov/advisory"


def test_impersonation_rescue_guards_every_redirect_hop(monkeypatch):
    """A 301 into the cloud-metadata address must bail on the impersonator path too — it is the
    whole reason this code follows redirects itself instead of letting the client do it."""
    class _Response:
        status_code = 301
        headers = {"location": "http://169.254.169.254/latest/meta-data/"}
        def iter_content(self, chunk_size=8192):
            yield b""
        def close(self):
            pass

    monkeypatch.setattr("curl_cffi.requests.get", lambda url, **k: _Response(), raising=False)
    from cyllex_argus.documents.fetch import curl_cffi_impersonate_fetch
    with pytest.raises(FetchError, match="private/loopback/link-local/metadata"):
        curl_cffi_impersonate_fetch("https://vendor.example/x", 1_000_000, _public_resolver)


def test_a_waf_403_over_a_real_404_is_reported_as_the_404():
    """`cisa.gov/.../ed-24-02-…` was stored as "HTTP 403" when the page is simply gone.

    The 403 is what the WAF tells httpx; the impersonator gets past it and sees the 404. Storing
    the 403 told the operator to retry a URL that will never work again — and it is what sent me
    down the wrong diagnosis twice.
    """
    def handler(request):
        return httpx.Response(403)

    def impersonator(url, max_bytes, resolver):
        raise FetchError(f"HTTP 404 for {url}")

    with pytest.raises(FetchError, match="HTTP 404"):
        _fetcher_with_impersonator(handler, impersonator).fetch("https://vendor.example/gone")


def test_a_network_error_in_the_rescue_does_not_mask_the_publishers_refusal():
    """The reverse case: the impersonator failing to connect says nothing about the document, so
    the publisher's own answer stays the reported one."""
    def handler(request):
        return httpx.Response(403)

    def impersonator(url, max_bytes, resolver):
        raise FetchError(f"network error for {url}: connection reset")

    with pytest.raises(FetchError, match="HTTP 403"):
        _fetcher_with_impersonator(handler, impersonator).fetch("https://vendor.example/blocked")


def test_a_publisher_that_asks_to_be_identified_is_not_disguised():
    """The SEC documents an access policy: declare a User-Agent with contact details, stay under
    the rate limit, and you are served — and it blocks unidentified automated tools. The generic
    Chrome string is what that policy blocks, so pivoting to it makes things worse, and
    impersonating a browser's TLS handshake to route around a published policy is not something
    this tool should do. One request, Argus's own identity, and the refusal stands."""
    seen = []
    def handler(request):
        seen.append((str(request.url), request.headers.get("user-agent")))
        return httpx.Response(403)

    impersonated = []
    def impersonator(url, max_bytes, resolver):
        impersonated.append(url)
        raise FetchError(f"HTTP 403 for {url}")

    fetcher = _fetcher_with_impersonator(handler, impersonator)
    with pytest.raises(FetchError, match="HTTP 403"):
        fetcher.fetch("https://www.sec.gov/Archives/edgar/data/1/filing.htm")

    assert impersonated == [], "a declared-identity publisher must not be TLS-impersonated"
    # Only the requests to the SEC itself: asking archive.org for its copy is not evading the
    # SEC's policy — it is a different publisher serving a document it already holds — so the
    # Wayback hop keeps the ordinary rescue chain, browser pivot included.
    to_sec = [ua for url, ua in seen if "sec.gov" in url and "archive.org" not in url]
    assert to_sec, seen
    assert all(ua and ua.startswith("CyllexArgus/") for ua in to_sec), to_sec
    assert not any("Chrome" in (ua or "") for ua in to_sec)
    # And it is one request, not a retry storm: the refusal is accepted, not fought.
    assert len(to_sec) == 1, to_sec


def test_other_publishers_are_still_rescued_normally():
    """The policy is a short, explicit list — it must not quietly disable the rescue chain."""
    impersonated = []
    def impersonator(url, max_bytes, resolver):
        impersonated.append(url)
        return Fetched(url=url, final_url=url, content=b"ok", content_type="text/html")

    result = _fetcher_with_impersonator(
        lambda request: httpx.Response(403), impersonator
    ).fetch("https://vendor.example/report")
    assert result.content == b"ok"
    assert impersonated == ["https://vendor.example/report"]


def test_a_rescue_that_times_out_does_not_disable_the_wayback_fallback():
    """The finding: the rescue's error replaced the publisher's, and the Wayback gate read it.

    The TLS rescue can fail for reasons that say nothing about the document — its own 15s
    timeout, or a curl_cffi C-extension that will not import. The publisher still said 403, and
    archive.org may well be holding the paper, so the fallback has to run.
    """
    calls = []
    def handler(request):
        url = str(request.url)
        calls.append(url)
        if "web.archive.org" in url:
            return httpx.Response(200, content=b"<html>archived</html>",
                                  headers={"content-type": "text/html"})
        return httpx.Response(403)

    def timing_out_impersonator(url, max_bytes, resolver):
        raise FetchError(f"network error for {url}: timed out")

    result = _fetcher_with_impersonator(handler, timing_out_impersonator).fetch(
        "https://vendor.example/paper"
    )

    assert result.content == b"<html>archived</html>"
    assert any("web.archive.org" in c for c in calls), "the 403 should still reach Wayback"


def test_a_rescue_that_cannot_import_does_not_disable_the_wayback_fallback():
    """Same shape, for the failure the lazy curl_cffi import exists to tolerate."""
    def handler(request):
        if "web.archive.org" in str(request.url):
            return httpx.Response(200, content=b"<html>archived</html>",
                                  headers={"content-type": "text/html"})
        return httpx.Response(403)

    def missing_impersonator(url, max_bytes, resolver):
        raise FetchError("curl_cffi not available: No module named 'curl_cffi'")

    result = _fetcher_with_impersonator(handler, missing_impersonator).fetch(
        "https://vendor.example/paper"
    )
    assert result.content == b"<html>archived</html>"
