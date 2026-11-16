"""Download one filter list.

* HTTPS only, TLS ≥ 1.2 against the system CA store, ``trust_env=False``
  (no proxies or netrc from the environment), no cookies.
* Host names are resolved by asking the daemon (``127.0.0.1:153``), never
  the system resolver; every address must be global (no loopback, private,
  link-local, CGNAT, multicast or reserved ranges: SSRF). The connection
  goes to that IP with the TLS name pinned in the SSL context
  (``doh.pinned_tls_context``), so SNI and the certificate check use the
  host name on every httpcore version.
* At most 3 redirects, each HTTPS to HTTPS, each resolved and checked again
  (a new client per hop: the name may change).
* Limits: ``max_bytes`` of (decoded) body, a read timeout and a total
  deadline. The body streams to a file and is hashed on the way.
* ``If-None-Match`` / ``If-Modified-Since`` → ``not_modified``.
* An HTML page (a captive portal, an error page served with 200) is
  rejected by content type and by sniffing the first bytes.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import http.cookiejar
import ipaddress
import os
import ssl
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urljoin, urlsplit

import httpx

from .. import __version__
from ..daemon.upstream.doh import pinned_tls_context
from ..filters.catalog import CatalogError, validate_list_url

MAX_BYTES = 128 * 1024 * 1024
MAX_REDIRECTS = 3
TOTAL_TIMEOUT = 15 * 60.0
READ_TIMEOUT = 30.0
CONNECT_TIMEOUT = 10.0
USER_AGENT = f"blockads-linux/{__version__}"
_HTML_PREFIXES = (b"<!doctype html", b"<html", b"<head", b"<body", b"<?xml")
CGNAT = ipaddress.ip_network("100.64.0.0/10")

Resolve = Callable[[str], Awaitable[Sequence[str]]]


class FetchError(Exception):
    """The list could not be downloaded; the message has no secrets and no body text."""


@dataclass(frozen=True, slots=True)
class FetchResult:
    status: str  # "ok" | "not_modified"
    url: str  # the final URL (after redirects)
    sha256: str = ""
    size: int = 0
    etag: str = ""
    last_modified: str = ""


def is_global_address(address: str) -> bool:
    ip = ipaddress.ip_address(address.split("%", 1)[0])
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if isinstance(ip, ipaddress.IPv4Address) and ip in CGNAT:
        return False
    return ip.is_global and not ip.is_multicast


class _NoCookies(http.cookiejar.DefaultCookiePolicy):
    def set_ok(self, cookie, request):  # type: ignore[no-untyped-def,override]
        return False

    def return_ok(self, cookie, request):  # type: ignore[no-untyped-def,override]
        return False


class Fetcher:
    def __init__(self, resolve: Resolve, *, cafile: str | None = None,
                 allow_address: Callable[[str], bool] = is_global_address,
                 max_bytes: int = MAX_BYTES, total_timeout: float = TOTAL_TIMEOUT,
                 read_timeout: float = READ_TIMEOUT, connect_timeout: float = CONNECT_TIMEOUT) -> None:
        self.resolve = resolve
        self.cafile = cafile
        self.allow_address = allow_address
        self.max_bytes = max_bytes
        self.total_timeout = total_timeout
        self.read_timeout = read_timeout
        self.connect_timeout = connect_timeout

    async def fetch(self, url: str, destination: Path, *, etag: str = "", last_modified: str = "") -> FetchResult:
        """Download ``url`` into ``destination`` (replaced only on success)."""
        # The deadline cancels a child task, never the caller: with httpcore 0.16-1.0.2
        # (Debian 12, Ubuntu 24.04), cancelling the calling task through asyncio.timeout()
        # surfaces as a bare CancelledError instead of TimeoutError (as in upstream/doh.py).
        task = asyncio.ensure_future(self._fetch(url, destination, etag, last_modified))
        try:
            done, _ = await asyncio.wait((task,), timeout=self.total_timeout)
            if not done:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await task
                raise FetchError("took too long")
            return task.result()
        except asyncio.CancelledError:
            task.cancel()
            raise
        finally:
            _remove_partial(destination)

    async def _fetch(self, url: str, destination: Path, etag: str, last_modified: str) -> FetchResult:
        current = url
        for _hop in range(MAX_REDIRECTS + 1):
            try:
                validate_list_url(current)
            except CatalogError:
                raise FetchError("redirect to a non-HTTPS URL refused" if current != url else "not an HTTPS URL") \
                    from None
            parts = urlsplit(current)
            host = parts.hostname or ""
            addresses = await self._addresses(host)
            headers = {"Accept-Encoding": "gzip", "User-Agent": USER_AGENT}
            if etag:
                headers["If-None-Match"] = etag
            if last_modified:
                headers["If-Modified-Since"] = last_modified
            response = await self._request(current, host, parts.port or 443, addresses, headers, destination)
            if isinstance(response, str):  # a redirect target
                current = urljoin(current, response)
                continue
            return FetchResult(**{**response, "url": current})
        raise FetchError(f"more than {MAX_REDIRECTS} redirects")

    async def _addresses(self, host: str) -> list[str]:
        try:
            literal = ipaddress.ip_address(host)
        except ValueError:
            literal = None
        if literal is not None:
            candidates = [str(literal)]
        else:
            try:
                candidates = list(await self.resolve(host))
            except Exception as exc:
                raise FetchError(f"cannot resolve the host ({type(exc).__name__})") from None
        allowed = [a for a in candidates if self.allow_address(a)]
        if not allowed:
            raise FetchError("the host has no public address" if candidates else "the host has no address")
        return allowed

    async def _request(self, url: str, host: str, port: int, addresses: list[str], headers: dict[str, str],
                       destination: Path) -> dict | str:
        parts = urlsplit(url)
        target = parts.path or "/"
        if parts.query:
            target += "?" + parts.query
        last_error = "no address"
        for address in addresses:
            literal = f"[{address}]" if ":" in address else address
            request_url = f"https://{literal}:{port}{target}"
            host_header = host if port == 443 else f"{host}:{port}"
            context = pinned_tls_context(host, self.cafile)
            async with httpx.AsyncClient(
                http2=True, verify=context, trust_env=False, follow_redirects=False,
                cookies=http.cookiejar.CookieJar(policy=_NoCookies()),
                timeout=httpx.Timeout(self.read_timeout, connect=self.connect_timeout),
            ) as client:
                client.headers.pop("User-Agent", None)
                request = client.build_request("GET", request_url, headers={**headers, "Host": host_header},
                                               extensions={"sni_hostname": host})
                try:
                    response = await client.send(request, stream=True)
                except httpx.ConnectError as exc:
                    last_error = _describe(exc)
                    continue  # try the next address
                except ssl.SSLError as exc:  # httpcore 0.16/1.0.2 (Debian 12, Ubuntu 24.04) do not wrap it
                    last_error = type(exc).__name__ + (" (certificate)" if "CERTIFICATE" in str(exc).upper() else "")
                    continue
                except httpx.HTTPError as exc:
                    raise FetchError(_describe(exc)) from None
                try:
                    return await self._handle(response, destination)
                except httpx.HTTPError as exc:
                    raise FetchError(_describe(exc)) from None
                finally:
                    await response.aclose()
        raise FetchError(f"cannot connect: {last_error}")

    async def _handle(self, response: httpx.Response, destination: Path) -> dict | str:
        status = response.status_code
        if status in (301, 302, 303, 307, 308):
            location = response.headers.get("Location", "")
            if not location or len(location) > 2048:
                raise FetchError(f"HTTP {status} without a usable Location")
            return location
        if status == 304:
            return {"status": "not_modified", "etag": response.headers.get("ETag", ""),
                    "last_modified": response.headers.get("Last-Modified", "")}
        if status != 200:
            raise FetchError(f"HTTP {status}")
        content_type = response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type in ("text/html", "application/xhtml+xml"):
            raise FetchError("the server sent an HTML page, not a list")
        length = response.headers.get("Content-Length", "")
        if length.isdigit() and "gzip" not in response.headers.get("Content-Encoding", "") \
                and int(length) > self.max_bytes:
            raise FetchError(f"list larger than {self.max_bytes // (1024 * 1024)} MiB")
        digest = hashlib.sha256()
        size = 0
        partial = _partial(destination)
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, "wb") as out:
            first = True
            async for chunk in response.aiter_bytes():
                if first and chunk:
                    first = False
                    head = chunk[:512].lstrip(b"\xef\xbb\xbf \t\r\n").lower()
                    if head.startswith(_HTML_PREFIXES):
                        raise FetchError("the server sent an HTML page, not a list")
                size += len(chunk)
                if size > self.max_bytes:
                    raise FetchError(f"list larger than {self.max_bytes // (1024 * 1024)} MiB")
                digest.update(chunk)
                out.write(chunk)
            out.flush()
            os.fsync(out.fileno())
        if size == 0:
            raise FetchError("empty response")
        os.replace(partial, destination)
        return {"status": "ok", "sha256": digest.hexdigest(), "size": size,
                "etag": response.headers.get("ETag", "")[:256],
                "last_modified": response.headers.get("Last-Modified", "")[:64]}


def _partial(destination: Path) -> Path:
    return destination.with_name(destination.name + ".part")


def _remove_partial(destination: Path) -> None:
    with contextlib.suppress(OSError):
        _partial(destination).unlink()


def _describe(exc: BaseException) -> str:
    text = type(exc).__name__
    cause = exc.__cause__ or exc.__context__
    if cause is not None and "CERTIFICATE" in str(cause).upper():
        text += " (certificate)"
    return text


class DaemonResolver:
    """Resolve names by asking blockadsd (A and AAAA), as the updater must."""

    def __init__(self, address: str = "127.0.0.1", port: int = 153, timeout: float = 5.0) -> None:
        self.address = address
        self.port = port
        self.timeout = timeout

    async def __call__(self, host: str) -> list[str]:
        import dns.asyncquery
        import dns.flags
        import dns.message
        import dns.rdatatype

        results: list[str] = []
        errors = 0
        for rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
            query = dns.message.make_query(host, rdtype)
            try:
                reply = await dns.asyncquery.udp(query, self.address, timeout=self.timeout, port=self.port)
                if reply.flags & dns.flags.TC:
                    reply = await dns.asyncquery.tcp(query, self.address, timeout=self.timeout, port=self.port)
            except Exception:
                errors += 1
                continue
            for rrset in reply.answer:
                if rrset.rdtype == rdtype:
                    results.extend(r.address for r in rrset)
        if not results and errors == 2:
            raise OSError("the daemon did not answer")
        return list(dict.fromkeys(results))
