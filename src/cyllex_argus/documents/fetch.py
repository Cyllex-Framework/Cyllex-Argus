"""Download documents with retries, backoff and a hard size limit. Nothing downloaded is executed."""

from __future__ import annotations

import ipaddress
import logging
import re
import socket
import time
from collections.abc import Callable

import httpx
from pydantic import BaseModel

from cyllex_argus import __version__

_log = logging.getLogger(__name__)

USER_AGENT = f"CyllexArgus/{__version__} (+https://github.com/Cyllex-Framework/Cyllex-Argus)"
# Wayback Machine URL template. `/web/0/` tells archive.org to resolve to the newest snapshot
# it has — operators are usually looking for the live content, and the newest archive is the
# closest proxy. The URL encoded upstream can keep its original scheme and path verbatim; the
# Wayback replay layer handles the rewriting.
WAYBACK_URL_TEMPLATE = "https://web.archive.org/web/0/{url}"
# Rescue triggers: anything the publisher is actively refusing (403) or saying is gone (404,
# 410). We don't rescue on 5xx (that's "server having a moment, retry later" — the httpx
# backoff loop already covers it) nor on 401 (that's "we need credentials", Wayback doesn't).
_WAYBACK_RESCUE_STATUSES = (403, 404, 410)
# Browser-shaped User-Agent for the retry endpoint's "Retry as browser" option. Not used by
# scheduled runs — those keep the identifying CyllexArgus UA so publishers can rate-limit or
# block us by policy. This string is a mainstream Chrome fingerprint that most WAFs allow.
BROWSER_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)

# Publishers that document an automated-access policy: identify yourself, keep under the rate
# limit, and you are served. The SEC's is explicit — it "does not allow botnets or automated
# tools" that do not declare a User-Agent, and it caps request rates. For these hosts Argus
# keeps its own identifying UA and does NOT pivot to a browser string or impersonate a browser's
# TLS handshake: the generic Chrome UA is precisely what such a policy blocks, and evading a
# published access policy is not a thing this tool does. A refusal from them is a refusal, and
# the operator can still supply the document by hand.
_DECLARED_IDENTITY_DOMAINS = ("sec.gov",)

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
Resolver = Callable[[str], list[IPAddress]]


def _respects_declared_identity(url: str) -> bool:
    """True when this host publishes an access policy Argus should comply with, not work around."""
    try:
        host = (httpx.URL(url).host or "").lower()
    except (httpx.InvalidURL, UnicodeError, ValueError):
        return False
    return any(host == domain or host.endswith("." + domain) for domain in _DECLARED_IDENTITY_DOMAINS)


def _http_status_in(message: str) -> int | None:
    """The HTTP status a FetchError message reports, or None when it is not a status error."""
    match = re.search(r"HTTP (\d{3})", message)
    return int(match.group(1)) if match else None


class FetchError(Exception):
    """A document could not be downloaded."""


class Fetched(BaseModel):
    url: str
    final_url: str
    content: bytes
    content_type: str | None = None


def build_client(timeout_seconds: float) -> httpx.Client:
    # follow_redirects is off here: the Fetcher follows redirects itself so it can enforce the SSRF
    # guard on every hop. If httpx followed them silently a 302 from a public page to 127.0.0.1 or
    # the cloud-metadata address would leak internal services even though the first URL was public.
    return httpx.Client(
        timeout=timeout_seconds, follow_redirects=False, headers={"User-Agent": USER_AGENT}
    )


def _is_safe_ip(ip: IPAddress) -> bool:
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _default_resolver(host: str) -> list[IPAddress]:
    """Resolve `host` to the list of IPs the OS would use. Handles raw IP literals without DNS."""
    try:
        return [ipaddress.ip_address(host)]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise FetchError(f"refusing to fetch unresolvable host {host!r}: {exc}") from exc
    return list({ipaddress.ip_address(info[4][0]) for info in infos})


class Fetcher:
    def __init__(
        self,
        client: httpx.Client,
        max_bytes: int,
        attempts: int = 3,
        backoff_seconds: float = 1.0,
        sleep: Callable[[float], None] = time.sleep,
        resolve_host: Resolver = _default_resolver,
        max_redirects: int = 10,
        tls_impersonator: Callable[[str, int, Resolver], Fetched] | None = None,
    ) -> None:
        self._client = client
        self._max_bytes = max_bytes
        self._attempts = attempts
        self._backoff = backoff_seconds
        self._sleep = sleep
        self._resolve_host = resolve_host
        self._max_redirects = max_redirects
        # Final-recourse fallback for publishers that fingerprint the Python TLS stack and
        # 403 anything that isn't a real browser (CloudFlare, Akamai). None in tests so
        # they stay fully in httpx.MockTransport-land; the default production builder in
        # Services wires _curl_cffi_impersonate_fetch here. See `build_impersonator`.
        self._tls_impersonator = tls_impersonator

    def _assert_public_url(self, url: str) -> None:
        try:
            parsed = httpx.URL(url)
        except (httpx.InvalidURL, UnicodeError, ValueError) as exc:
            raise FetchError(f"invalid URL {url!r}: {exc}") from exc
        host = parsed.host
        if not host:
            raise FetchError(f"invalid URL {url!r}: no host")
        # Literal IPs are checked directly: the injectable resolver is only for hostname DNS.
        # Otherwise a test stub or a creative implementation could accidentally neutralize the guard.
        try:
            ips: list[IPAddress] = [ipaddress.ip_address(host)]
        except ValueError:
            ips = self._resolve_host(host)
        bad = [ip for ip in ips if not _is_safe_ip(ip)]
        if bad:
            raise FetchError(
                f"refusing to fetch {url}: host {host!r} resolves to a "
                f"private/loopback/link-local/metadata address ({bad[0]})"
            )

    def fetch(self, url: str, user_agent: str | None = None) -> Fetched:
        """Fetch `url` with the configured bot User-Agent, OR with `user_agent` when given.

        Overriding the UA is the last-resort recovery for publishers (CISA, several vendors)
        that refuse any identifier not matching a mainstream browser. The override is
        deliberately per-call: changing the default globally would make every scheduled run
        pretend to be a browser, which is not the identity Argus wants in logs most of the
        time. The retry endpoint uses this for its "Retry as browser" button.

        Rescue chain, in order (triggered by HTTP 4xx — "we read you and said no"):
          1. If no `user_agent` was given, retry once with the browser UA. Catches simple
             WAFs that match only on the UA string. Fires on 403 only.
          2. If 1) still gets 403 and a TLS impersonator is configured, try one more
             fetch through it (curl_cffi with Chrome's full TLS fingerprint). This
             rescues CloudFlare / Akamai gates that match on JA3/JA4 rather than UA —
             CISA, NCSC, cyber.gov.au, media.defense.gov all behave this way.
          3. If 2) also fails or the status was 404 / 410 (publisher moved or removed
             the URL), fall back to the Wayback Machine. Operators are after a 2024
             paper that archive.org almost certainly has, so letting the Argus
             pipeline drop it because the publisher 403s / 404s today loses CTI value
             the operator can see is still accessible.

        429 and 5xx keep going through the httpx retry loop before any rescue runs:
        those are rate or capacity issues, not identity or availability ones.
        """
        try:
            return self._httpx_fetch(url, user_agent)
        except FetchError as exc:
            msg = str(exc)
            # The error we will ultimately raise. It starts as httpx's, but a later step that
            # got PAST the gate knows better: a WAF answers httpx with 403 for a page that is
            # really a 404, and reporting the 403 tells the operator to retry a URL that is
            # gone. The truest status wins, and it is also what the Wayback trigger reads.
            final = exc
            # TLS-impersonation rescue — only for 403, only when the caller is not driving
            # a specific UA (that path handles its own recovery via the UI), and never against
            # a publisher whose access policy asks to be identified rather than outwitted.
            if (
                self._tls_impersonator is not None
                and user_agent is None
                and "HTTP 403" in msg
                and not _respects_declared_identity(url)
            ):
                try:
                    result = self._tls_impersonator(url, self._max_bytes, self._resolve_host)
                    _log.info("tls-impersonation rescue succeeded for %s", url)
                    return result
                except FetchError as rescue_exc:
                    _log.info("tls-impersonation rescue also failed for %s: %s", url, rescue_exc)
                    msg = str(rescue_exc)
                    if _http_status_in(msg) is not None:
                        final = rescue_exc
            # Wayback-Machine rescue — for anything the publisher still refuses (403 after
            # the TLS fallback above, or a 404/410 that says the paper moved). Not for 5xx
            # (we want the live retry loop to handle transient capacity) and not when the
            # caller already specified a UA (same reason as above).
            # Either status counts. `msg` holds the rescue's error when one ran, and that
            # rescue can fail for reasons that say nothing about the document — its own timeout,
            # or a curl_cffi C-extension that will not import. Gating on `msg` alone dropped a
            # 403'd paper that archive.org was holding because the rescue had timed out.
            rescuable = _is_rescuable_by_wayback(msg) or _is_rescuable_by_wayback(str(exc))
            if user_agent is None and rescuable and not url.startswith("https://web.archive.org/"):
                wayback_url = _wayback_url_for(url)
                try:
                    result = self._httpx_fetch(wayback_url, user_agent=None)
                    _log.info("wayback rescue succeeded for %s via %s", url, wayback_url)
                    # Preserve the original URL so downstream dedup / investigation_documents
                    # continue to key on the publisher URL the operator searched for.
                    return Fetched(
                        url=url, final_url=result.final_url, content=result.content,
                        content_type=result.content_type,
                    )
                except FetchError as wayback_exc:
                    _log.info("wayback rescue also failed for %s: %s", url, wayback_exc)
            if final is not exc:
                raise final from exc
            raise

    def _httpx_fetch(self, url: str, user_agent: str | None) -> Fetched:
        """The httpx request path with the UA-pivot rescue chain. Wrapped by `fetch` so the
        TLS-impersonation fallback can run after this returns 403."""
        self._assert_public_url(url)
        browser_retry_available = user_agent is None
        for _hop in range(self._max_redirects + 1):
            last_error: FetchError | None = None
            last_cause: Exception | None = None
            redirect_target: str | None = None
            for attempt in range(self._attempts):
                if attempt:
                    self._sleep(self._backoff * 2 ** (attempt - 1))
                try:
                    headers = {"User-Agent": user_agent} if user_agent else None
                    with self._client.stream("GET", url, headers=headers) as response:
                        status = response.status_code
                        if status == 429 or status >= 500:
                            last_error = FetchError(f"HTTP {status} for {url}")
                            last_cause = None
                            continue
                        if 300 <= status < 400:
                            location = response.headers.get("location")
                            if not location:
                                raise FetchError(f"HTTP {status} for {url} with no Location header")
                            try:
                                redirect_target = str(httpx.URL(url).join(location))
                            except (httpx.InvalidURL, UnicodeError, ValueError) as exc:
                                raise FetchError(
                                    f"invalid redirect location {location!r} from {url}: {exc}"
                                ) from exc
                            break
                        if (
                            status == 403
                            and browser_retry_available
                            and not _respects_declared_identity(url)
                        ):
                            # One-shot UA pivot: the server actively refused the Argus UA. Switch
                            # to the browser UA for the remainder of this fetch and keep going.
                            # Skipped for publishers who ask to be identified — there the generic
                            # browser string is the thing that gets blocked.
                            user_agent = BROWSER_USER_AGENT
                            browser_retry_available = False
                            continue
                        if status >= 400:
                            raise FetchError(f"HTTP {status} for {url}")
                        declared = response.headers.get("content-length", "")
                        if declared.isdigit() and int(declared) > self._max_bytes:
                            raise FetchError(f"{url} exceeds the size limit ({declared} bytes)")
                        body = bytearray()
                        for chunk in response.iter_bytes():
                            body.extend(chunk)
                            if len(body) > self._max_bytes:
                                raise FetchError(f"{url} exceeds the size limit")
                        return Fetched(
                            url=url, final_url=str(response.url), content=bytes(body),
                            content_type=response.headers.get("content-type"),
                        )
                except httpx.UnsupportedProtocol as exc:
                    raise FetchError(f"unsupported URL {url}: {exc}") from exc
                except (httpx.InvalidURL, UnicodeError, ValueError) as exc:
                    # httpx refuses some URLs that urllib accepts (control characters, invalid IDNA hosts).
                    raise FetchError(f"invalid URL {url!r}: {exc}") from exc
                except httpx.TransportError as exc:
                    last_error = FetchError(f"network error for {url}: {exc}")
                    last_cause = exc
                except httpx.HTTPError as exc:
                    raise FetchError(f"HTTP error for {url}: {exc}") from exc
            else:
                raise (last_error or FetchError(f"could not fetch {url}")) from last_cause
            # inner loop broke on a redirect: validate the new target and go around.
            assert redirect_target is not None
            self._assert_public_url(redirect_target)
            url = redirect_target
        raise FetchError(f"too many redirects (over {self._max_redirects}) starting from {url!r}")


def _is_rescuable_by_wayback(error_message: str) -> bool:
    """Return True when the publisher's error reads like "we won't serve this" rather than
    "come back in a moment". 5xx retries happen inside the httpx loop; 401 is credentials
    (Wayback can't help); anything else listed in _WAYBACK_RESCUE_STATUSES is a candidate."""
    for status in _WAYBACK_RESCUE_STATUSES:
        if f"HTTP {status}" in error_message:
            return True
    return False


def wayback_url_for(url: str) -> str:
    """Build the Wayback Machine replay URL for the given publisher URL."""
    return WAYBACK_URL_TEMPLATE.format(url=url)


_wayback_url_for = wayback_url_for  # backwards-compatible alias


def _assert_public_url_simple(url: str, resolver: Resolver) -> None:
    """Standalone SSRF guard mirroring Fetcher._assert_public_url, usable without a Fetcher
    instance. Needed by the TLS-impersonation fallback which bypasses httpx entirely."""
    try:
        parsed = httpx.URL(url)
    except (httpx.InvalidURL, UnicodeError, ValueError) as exc:
        raise FetchError(f"invalid URL {url!r}: {exc}") from exc
    host = parsed.host
    if not host:
        raise FetchError(f"invalid URL {url!r}: no host")
    try:
        ips: list[IPAddress] = [ipaddress.ip_address(host)]
    except ValueError:
        ips = resolver(host)
    bad = [ip for ip in ips if not _is_safe_ip(ip)]
    if bad:
        raise FetchError(
            f"refusing to fetch {url}: host {host!r} resolves to a "
            f"private/loopback/link-local/metadata address ({bad[0]})"
        )


def curl_cffi_impersonate_fetch(
    url: str, max_bytes: int, resolver: Resolver, max_redirects: int = 10
) -> Fetched:
    """TLS-impersonation GET using curl_cffi with Chrome 131's full handshake. This is what
    gets Argus past CloudFlare / Akamai gates that fingerprint the Python TLS stack
    (JA3/JA4) rather than just the UA — CISA, NCSC, cyber.gov.au, media.defense.gov all
    behave this way, and they refuse httpx even when it sends the same User-Agent that curl
    gets served with.

    Redirects ARE followed, one hop at a time, with the same SSRF guard on every hop as the
    httpx path (`allow_redirects=False` plus our own loop, so a 302 to a private address or the
    cloud-metadata endpoint still bails). This used to propagate a redirect as a failure on the
    theory that "403 then redirect" was a rare combination. It is not: `cisa.gov` 301s to
    `www.cisa.gov`, `silentpush.com/?p=…` 301s to its permalink, and because the gate answers
    httpx with 403 *before* it will serve the 301, this path is the only one that ever sees the
    redirect. Dropping it lost three documents out of forty-six.

    Imports curl_cffi lazily so a broken install (missing C-ext on an unsupported arch)
    does not break every `from documents.fetch` import — only this function path.
    """
    try:
        from curl_cffi import requests as curl_requests
    except ImportError as exc:
        raise FetchError(f"curl_cffi not available: {exc}") from exc
    original = url
    for _hop in range(max_redirects + 1):
        _assert_public_url_simple(url, resolver)
        try:
            response = curl_requests.get(
                url, impersonate="chrome131", allow_redirects=False, timeout=15,
                stream=True,
            )
        except Exception as exc:  # noqa: BLE001 — curl_cffi raises a wide family we treat as network failures
            raise FetchError(f"network error for {url}: {exc}") from exc
        try:
            status = response.status_code
            if 300 <= status < 400:
                location = response.headers.get("location")
                if not location:
                    raise FetchError(f"HTTP {status} for {url} with no Location header")
                try:
                    url = str(httpx.URL(url).join(location))
                except (httpx.InvalidURL, UnicodeError, ValueError) as exc:
                    raise FetchError(
                        f"invalid redirect location {location!r} from {url}: {exc}"
                    ) from exc
                continue
            if status != 200:
                raise FetchError(f"HTTP {status} for {url}")
            body = bytearray()
            for chunk in response.iter_content(chunk_size=8192):
                body.extend(chunk)
                if len(body) > max_bytes:
                    raise FetchError(f"{original} exceeds the size limit")
            return Fetched(
                # The original URL is what dedup and investigation_documents key on; the hop
                # chain is bookkeeping.
                url=original, final_url=url, content=bytes(body),
                content_type=response.headers.get("content-type"),
            )
        finally:
            response.close()
    raise FetchError(f"too many redirects (over {max_redirects}) starting from {original!r}")
