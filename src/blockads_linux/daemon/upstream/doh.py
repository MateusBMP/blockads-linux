"""DNS over HTTPS (RFC 8484) with httpx over HTTP/2.

The request goes to ``https://<bootstrap-ip>/<path>`` with the provider's name
in ``Host`` (``:authority``), so the system resolver is never used.

The TLS name (SNI and certificate check) is pinned in the SSL context itself
(:class:`PinnedNameContext`), not left to httpx: httpcore < 0.17 (Debian 12)
silently ignores ``extensions={"sni_hostname": ...}`` and verifies the
certificate against the *IP*, so a wrong or attacker-chosen name passed.
``sni_hostname`` is still sent for newer httpx, where it agrees.
Testing showed that httpx pools connections by IP and checks the name only
when a connection is created, so each :class:`DohUpstream` owns its own
client and context: one per upstream identity (IP + TLS name), never shared,
and recreated when the configuration changes (by building a new upstream).

Hardening: ``trust_env=False`` (no proxy or netrc from the environment), no
redirects, no cookies, no ``User-Agent``, no compression; the reply must be
``200`` with ``application/dns-message`` and at most 64 KiB.
"""

from __future__ import annotations

import asyncio
import contextlib
import http.cookiejar
import ipaddress
import ssl
from urllib.parse import urlsplit

import dns.message
import httpx

from .base import Question, UpstreamError, check_response, tls_verify_error
from .dot import make_tls_context

MAX_RESPONSE = 65535
CONTENT_TYPE = "application/dns-message"


class _NoCookies(http.cookiejar.DefaultCookiePolicy):
    def set_ok(self, cookie: http.cookiejar.Cookie, request: object) -> bool:  # type: ignore[override]
        return False

    def return_ok(self, cookie: http.cookiejar.Cookie, request: object) -> bool:  # type: ignore[override]
        return False


class PinnedNameContext(ssl.SSLContext):
    """Client context that sends SNI for, and verifies, one fixed name.

    Whatever ``server_hostname`` the HTTP stack passes (httpcore < 0.17 passes
    the URL host, i.e. the bootstrap IP), the handshake uses ``pinned_name``.
    """

    pinned_name: str

    def wrap_socket(self, sock, server_side=False, do_handshake_on_connect=True,  # type: ignore[override]
                    suppress_ragged_eofs=True, server_hostname=None, session=None):
        return super().wrap_socket(sock, server_side, do_handshake_on_connect, suppress_ragged_eofs,
                                   self.pinned_name, session)

    def wrap_bio(self, incoming, outgoing, server_side=False, server_hostname=None,  # type: ignore[override]
                 session=None):
        return super().wrap_bio(incoming, outgoing, server_side, self.pinned_name, session)


def pinned_tls_context(server_name: str, cafile: str | None = None) -> PinnedNameContext:
    """Like :func:`make_tls_context` (h2 ALPN), but bound to ``server_name``."""
    context = PinnedNameContext(ssl.PROTOCOL_TLS_CLIENT)  # CERT_REQUIRED + check_hostname
    context.pinned_name = server_name
    context.verify_flags = make_tls_context().verify_flags
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    if cafile:
        context.load_verify_locations(cafile=cafile)
    else:
        context.load_default_certs()
    context.set_alpn_protocols(["h2", "http/1.1"])
    return context


def parse_doh_url(url: str) -> tuple[str, int, str]:
    """``(hostname, port, path)`` of an ``https://`` DoH URL (RFC 8484 template allowed)."""
    parts = urlsplit(url.replace("{?dns}", ""))
    if parts.scheme != "https" or not parts.hostname:
        raise ValueError(f"not an https DoH URL: {url!r}")
    if parts.username is not None or parts.password is not None or parts.fragment:
        raise ValueError(f"unsupported DoH URL: {url!r}")
    path = parts.path or "/dns-query"
    if parts.query:
        path += "?" + parts.query
    return parts.hostname, parts.port or 443, path


class DohUpstream:
    encrypted = True

    def __init__(self, url: str, address: str, *, cafile: str | None = None,
                 label: str | None = None, timeout: float = 3.0, keepalive: float = 30.0) -> None:
        self.server_name, self.port, path = parse_doh_url(url)
        self.address = str(ipaddress.ip_address(address))
        self.url = url
        self.label = label or url
        self.timeout = timeout
        host = f"[{self.address}]" if ":" in self.address else self.address
        self._request_url = f"https://{host}:{self.port}{path}"
        self._host = self.server_name if self.port == 443 else f"{self.server_name}:{self.port}"
        self._ssl_context = pinned_tls_context(self.server_name, cafile)
        self._keepalive = keepalive
        self._client: httpx.AsyncClient | None = None

    def _get_client(self) -> httpx.AsyncClient:
        """The client of this upstream identity, created on first use and after close()."""
        if self._client is None:
            client = httpx.AsyncClient(
                http2=True,
                verify=self._ssl_context,
                trust_env=False,
                follow_redirects=False,
                cookies=http.cookiejar.CookieJar(policy=_NoCookies()),
                timeout=httpx.Timeout(self.timeout),
                limits=httpx.Limits(max_connections=4, max_keepalive_connections=1, keepalive_expiry=self._keepalive),
            )
            client.headers.pop("User-Agent", None)
            client.headers["Accept-Encoding"] = "identity"
            client.headers["Accept"] = CONTENT_TYPE
            self._client = client
        return self._client

    async def exchange(self, question: Question) -> dns.message.Message:
        # RFC 8484 §4.1: ID 0, for HTTP-cache friendliness; the stream matches the reply.
        wire = question.to_wire(0, pad_block=128)
        # The deadline cancels a child task, never the caller: with httpcore
        # 1.0.2 + anyio (Ubuntu 24.04), cancelling the calling task through
        # asyncio.timeout() surfaced as a bare CancelledError.
        task = asyncio.ensure_future(self._post(wire))
        try:
            done, _ = await asyncio.wait((task,), timeout=self.timeout)
        except asyncio.CancelledError:
            task.cancel()
            raise
        if not done:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
            raise UpstreamError("timeout")
        return check_response(question, 0, task.result())

    async def _post(self, wire: bytes) -> bytes:
        headers = {"Host": self._host, "Content-Type": CONTENT_TYPE}
        try:
            async with self._get_client().stream("POST", self._request_url, content=wire, headers=headers,
                                           extensions={"sni_hostname": self.server_name}) as response:
                if response.status_code != 200:
                    raise UpstreamError(f"HTTP {response.status_code}")
                content_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
                if content_type != CONTENT_TYPE:
                    raise UpstreamError("unexpected content type")
                body = bytearray()
                async for chunk in response.aiter_raw():
                    body += chunk
                    if len(body) > MAX_RESPONSE:
                        raise UpstreamError("response too large")
                return bytes(body)
        except httpx.TimeoutException:
            raise UpstreamError("timeout") from None
        except (httpx.HTTPError, ssl.SSLError) as exc:
            # httpx wraps TLS failures (ConnectError from SSLCertVerificationError).
            raise tls_verify_error(exc) or UpstreamError(_describe(exc)) from None

    async def close(self) -> None:
        """Drop the connection pool; the next query opens a new one."""
        client, self._client = self._client, None
        if client is not None:
            await client.aclose()


def _describe(exc: BaseException) -> str:
    if isinstance(exc, ssl.SSLError):
        return f"TLS error: {exc.reason}"
    return type(exc).__name__
