"""Upstream presets and upstream specifications.

The presets and their addresses come from blockads-android
``data/entities/DnsProvider.kt`` (``DnsProviders`` and ``getSecondaryIp``,
revision fc95d66a). Every encrypted upstream is reached at a fixed IP, never
by resolving its name through the system.

An :class:`UpstreamSpec` is the serializable description of one upstream
(protocol, IP, port, TLS name, path) and builds the transport object.
Specs can also be written as text:

* a preset name: ``quad9`` (DoH, plus the provider's plain DNS as fallback);
* ``sdns://...`` (plain, DoT and DoH stamps);
* ``udp://IP[:port]``, ``tcp://IP[:port]``;
* ``tls://IP[:port]#name`` and ``https://IP[:port]/path#name``: connect to
  IP, verify the certificate for ``name``.
"""

from __future__ import annotations

import ipaddress
import ssl
from dataclasses import dataclass
from urllib.parse import urlsplit

from .doh import DohUpstream
from .dot import DotUpstream
from .plain import UdpUpstream
from .stamps import Proto, StampError, parse_stamp, split_host_port
from .tcp import StreamUpstream

ENCRYPTED_TIMEOUT = 2.0
PLAIN_TIMEOUT = 1.5


@dataclass(frozen=True, slots=True)
class UpstreamSpec:
    protocol: str  # "udp" | "tcp" | "tls" | "https"
    address: str
    port: int
    name: str = ""  # TLS name (tls, https)
    path: str = ""  # https only

    def __post_init__(self) -> None:
        if self.protocol not in ("udp", "tcp", "tls", "https"):
            raise ValueError(f"unknown protocol {self.protocol!r}")
        ipaddress.ip_address(self.address)
        if not 0 < self.port < 65536:
            raise ValueError(f"bad port {self.port}")
        if self.protocol in ("tls", "https") and not self.name:
            raise ValueError(f"{self.protocol} upstream needs a TLS name")

    @property
    def encrypted(self) -> bool:
        return self.protocol in ("tls", "https")

    @property
    def label(self) -> str:
        """Display name; encrypted upstreams also show the IP they connect to."""
        if self.protocol == "https":
            port = "" if self.port == 443 else f":{self.port}"
            return f"https://{self.name}{port}{self.path or '/dns-query'} ({self.address})"
        if self.protocol == "tls":
            return f"tls://{self.name}" + ("" if self.port == 853 else f":{self.port}") + f" ({self.address})"
        host = f"[{self.address}]" if ":" in self.address else self.address
        return f"{self.protocol}://{host}" + ("" if self.port == 53 else f":{self.port}")

    def build(self, *, ssl_context: ssl.SSLContext | None = None, cafile: str | None = None,
              timeout: float | None = None):
        """The upstream; ``ssl_context`` applies to DoT, ``cafile`` to DoH (which pins its own context)."""
        if self.protocol == "https":
            port = "" if self.port == 443 else f":{self.port}"
            url = f"https://{self.name}{port}{self.path or '/dns-query'}"
            return DohUpstream(url, self.address, cafile=cafile, label=self.label,
                               timeout=timeout or ENCRYPTED_TIMEOUT)
        if self.protocol == "tls":
            return DotUpstream(self.address, self.name, self.port, ssl_context=ssl_context, label=self.label,
                               timeout=timeout or ENCRYPTED_TIMEOUT)
        if self.protocol == "tcp":
            return StreamUpstream(self.address, self.port, label=self.label, timeout=timeout or PLAIN_TIMEOUT)
        return UdpUpstream(self.address, self.port, label=self.label, timeout=timeout or PLAIN_TIMEOUT)


@dataclass(frozen=True, slots=True)
class Preset:
    id: str
    name: str
    addresses: tuple[str, ...]  # primary, secondary
    doh_url: str
    dot_name: str = ""

    def specs(self, protocol: str = "https") -> list[UpstreamSpec]:
        """One upstream per address, over ``protocol`` ("https", "tls" or "udp")."""
        if protocol == "https":
            name, port, path = _split_https(self.doh_url)
            return [UpstreamSpec("https", ip, port, name, path) for ip in self.addresses]
        if protocol == "tls":
            if not self.dot_name:
                raise ValueError(f"{self.name} has no DNS-over-TLS endpoint")
            return [UpstreamSpec("tls", ip, 853, self.dot_name) for ip in self.addresses]
        if protocol in ("udp", "tcp"):
            return [UpstreamSpec(protocol, ip, 53) for ip in self.addresses]
        raise ValueError(f"unknown protocol {protocol!r}")


PRESETS: dict[str, Preset] = {
    p.id: p
    for p in (
        Preset("quad9", "Quad9", ("9.9.9.9", "149.112.112.112"), "https://dns.quad9.net/dns-query", "dns.quad9.net"),
        Preset("adguard", "AdGuard DNS", ("94.140.14.14", "94.140.14.15"), "https://dns.adguard-dns.com/dns-query",
               "dns.adguard-dns.com"),
        Preset("cloudflare", "Cloudflare DNS", ("1.1.1.1", "1.0.0.1"), "https://cloudflare-dns.com/dns-query",
               "cloudflare-dns.com"),
        Preset("cloudflare_family", "Cloudflare Family", ("1.1.1.3", "1.0.0.3"),
               "https://family.cloudflare-dns.com/dns-query", "family.cloudflare-dns.com"),
        Preset("google", "Google DNS", ("8.8.8.8", "8.8.4.4"), "https://dns.google/dns-query", "dns.google"),
        Preset("opendns", "OpenDNS", ("208.67.222.222", "208.67.220.220"), "https://doh.opendns.com/dns-query"),
        Preset("opendns_family", "OpenDNS FamilyShield", ("208.67.222.123", "208.67.220.123"),
               "https://doh.familyshield.opendns.com/dns-query"),
        Preset("dnsbunker", "DNSBunker", ("185.250.250.61", "185.250.250.62"), "https://dnsbunker.org/dns-query"),
    )
}

DEFAULT_PRESET = "quad9"


def _split_https(url: str) -> tuple[str, int, str]:
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        raise ValueError(f"not an https URL: {url!r}")
    return parts.hostname, parts.port or 443, parts.path or "/dns-query"


def stamp_to_spec(text: str) -> UpstreamSpec:
    """An upstream from a plain, DoT or DoH stamp (with an IP address)."""
    stamp = parse_stamp(text)
    address = stamp.address or (split_host_port(stamp.bootstrap_ips[0], 0)[0] if stamp.bootstrap_ips else "")
    if not address:
        raise StampError("the stamp has no server IP address")
    if stamp.proto == Proto.PLAIN:
        return UpstreamSpec("udp", address, stamp.port)
    if stamp.proto == Proto.DOT:
        return UpstreamSpec("tls", address, stamp.port, stamp.hostname)
    if stamp.proto == Proto.DOH:
        path = stamp.path or "/dns-query"
        return UpstreamSpec("https", address, stamp.port, stamp.hostname, path if path.startswith("/") else "/" + path)
    raise StampError(f"{stamp.proto.name} stamps are not supported")


def parse_upstream(text: str) -> list[UpstreamSpec]:
    """Upstreams described by ``text`` (see the module docstring)."""
    text = text.strip()
    if text in PRESETS:
        return PRESETS[text].specs("https")
    if text.startswith("sdns://"):
        return [stamp_to_spec(text)]
    parts = urlsplit(text)
    scheme = parts.scheme
    if scheme not in ("udp", "tcp", "tls", "https") or not parts.hostname:
        raise ValueError(f"unrecognized upstream {text!r}")
    try:
        ipaddress.ip_address(parts.hostname)
    except ValueError:
        raise ValueError(f"{text!r}: connect to an IP address and give the TLS name after '#'") from None
    default_port = {"udp": 53, "tcp": 53, "tls": 853, "https": 443}[scheme]
    port = parts.port or default_port
    if scheme in ("udp", "tcp"):
        return [UpstreamSpec(scheme, parts.hostname, port)]
    if not parts.fragment:
        raise ValueError(f"{text!r}: add the TLS name after '#', e.g. tls://9.9.9.9#dns.quad9.net")
    return [UpstreamSpec(scheme, parts.hostname, port, parts.fragment, parts.path if scheme == "https" else "")]
