"""DNS over TLS (RFC 7858): the stream transport plus a verified TLS session.

The connection goes to a configured IP address (never resolved through the
system), and the certificate is checked against the provider's name.
"""

from __future__ import annotations

import ssl

from .tcp import StreamUpstream

DOT_PORT = 853


def make_tls_context(cafile: str | None = None, alpn: tuple[str, ...] = ()) -> ssl.SSLContext:
    """Client context: system CA store (or ``cafile``), TLS >= 1.2, hostname check."""
    context = ssl.create_default_context(cafile=cafile)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    if alpn:
        context.set_alpn_protocols(list(alpn))
    return context


class DotUpstream(StreamUpstream):
    def __init__(self, address: str, server_name: str, port: int = DOT_PORT, *,
                 ssl_context: ssl.SSLContext | None = None, label: str | None = None, timeout: float = 3.0,
                 idle_timeout: float = 20.0) -> None:
        super().__init__(
            address, port,
            ssl_context=ssl_context if ssl_context is not None else make_tls_context(alpn=("dot",)),
            server_name=server_name,
            label=label or f"tls://{server_name}",
            timeout=timeout,
            idle_timeout=idle_timeout,
        )
