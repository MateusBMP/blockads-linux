"""The network's own DNS servers (the "System" preset and the
last-resort tier).

NetworkManager's ``DnsManager.Configuration`` and systemd-resolved's per-link
DNS come first (netmon.py, router.py); ``/etc/resolv.conf`` is the fallback
when neither is on the bus or neither has a usable server. Loopback and local addresses
are never used: they belong to another local resolver (resolved's stub,
dnsmasq) whose own upstream queries we already intercept, so forwarding to
it would loop.
"""

from __future__ import annotations

import ipaddress
import socket
from pathlib import Path

from .upstream.presets import UpstreamSpec

RESOLV_CONF = Path("/etc/resolv.conf")
MAX_SERVERS = 3  # glibc's MAXNS


def parse_resolv_conf(text: str) -> list[str]:
    """``nameserver`` addresses, in order, without duplicates (scope IDs kept)."""
    servers: list[str] = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 2 or fields[0] != "nameserver":
            continue
        address = fields[1]
        try:
            ipaddress.ip_address(address)
        except ValueError:
            continue
        if address not in servers:
            servers.append(address)
    return servers


def is_local_address(address: str) -> bool:
    """True for loopback, unspecified and multicast addresses and for this host's own."""
    ip = ipaddress.ip_address(address.split("%", 1)[0])
    if ip.is_loopback or ip.is_unspecified or ip.is_multicast:
        return True
    family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM | socket.SOCK_CLOEXEC) as sock:
        try:
            sock.bind((address, 0))  # succeeds only for an address assigned to this host
        except OSError:
            return False
    return True


def network_upstreams(path: Path = RESOLV_CONF) -> list[UpstreamSpec]:
    """Plain-DNS upstreams for the network's resolvers (empty if unreadable)."""
    try:
        text = path.read_text("utf-8", errors="replace")
    except OSError:
        return []
    servers = [a for a in parse_resolv_conf(text) if not is_local_address(a)]
    return [UpstreamSpec("udp", address, 53) for address in servers[:MAX_SERVERS]]
