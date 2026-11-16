"""Per-domain routes to the network's DNS servers (tier 1).

Built from a :class:`~.netmon.NetworkState`:

* every domain a link announces (search domains and routing-only ``~domain``)
  goes to that link's servers. That covers VPN split DNS and LAN search
  domains. When several links claim a domain, VPN links come first, then
  NetworkManager's priority order;
* local-only names follow the default DNS route (the network DNS, or the
  DNS of a full-tunnel VPN so they do not leak past it): single-label names, ``lan``, ``home.arpa``, ``local``, ``internal`` and the
  reverse zones of private, CGNAT, link-local and ULA addresses.

The longest matching domain wins. Loopback and this host's own addresses
are never used (forwarding to a local resolver would loop), so a link whose
servers are all local routes nowhere.

:attr:`Router.network` is the network DNS (tiers 2 and 6) and
:attr:`Router.vpn` the DNS of a VPN that owns the default DNS route (tier 3).
Without NetworkManager or resolved, the network DNS comes from
``/etc/resolv.conf``.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

from .netdns import MAX_SERVERS, RESOLV_CONF, is_local_address, network_upstreams
from .netmon import LinkDns, NetworkState
from .upstream.presets import UpstreamSpec

#: Names that only the local network can answer (RFC 6762, 8375, 6761, ICANN's .internal).
LOCAL_ZONES = ("lan", "home.arpa", "local", "internal")


def private_reverse_zones() -> tuple[str, ...]:
    """Reverse zones of RFC 1918, CGNAT (100.64/10), link-local and ULA addresses."""
    zones = ["10.in-addr.arpa", "168.192.in-addr.arpa", "254.169.in-addr.arpa"]
    zones += [f"{octet}.172.in-addr.arpa" for octet in range(16, 32)]
    zones += [f"{octet}.100.in-addr.arpa" for octet in range(64, 128)]
    zones += ["c.f.ip6.arpa", "d.f.ip6.arpa"]  # fc00::/7
    zones += [f"{nibble}.e.f.ip6.arpa" for nibble in "89ab"]  # fe80::/10
    return tuple(zones)


LOCAL_REVERSE_ZONES = private_reverse_zones()


@dataclass(frozen=True, slots=True)
class Route:
    domain: str
    servers: tuple[UpstreamSpec, ...]
    interface: str  # "" for the network DNS or a global resolved entry
    vpn: bool = False


class Router:
    def __init__(self, routes: Iterable[Route] = (), *, network: Sequence[UpstreamSpec] = (),
                 vpn: Sequence[UpstreamSpec] = (), local: Sequence[UpstreamSpec] = ()) -> None:
        self.routes = {route.domain: route for route in routes}
        self.network = tuple(network)
        self.vpn = tuple(vpn)
        self.local = tuple(local)  # single-label names
        self._depths = sorted({domain.count(".") + 1 for domain in self.routes}, reverse=True)

    def route(self, name: str) -> Route | None:
        """The route for ``name`` (lower case, no trailing dot), or None for the normal tiers."""
        labels = name.split(".") if name else []
        for depth in self._depths:
            if depth <= len(labels):
                route = self.routes.get(".".join(labels[-depth:]))
                if route is not None:
                    return route
        if self.local and len(labels) == 1:
            return Route(name, self.local, "", bool(self.vpn))
        return None

    @classmethod
    def from_state(cls, state: NetworkState, *, resolv_conf: Path = RESOLV_CONF,
                   is_local: Callable[[str], bool] = is_local_address) -> Router:
        def usable(link: LinkDns) -> tuple[UpstreamSpec, ...]:
            return tuple(UpstreamSpec("udp", address, 53) for address in link.servers if not is_local(address))

        links = [(link, usable(link)) for link in state.links]
        links = [(link, servers) for link, servers in links if servers]
        # Network DNS: the non-VPN links, default-route ones if any.
        plain = [entry for entry in links if not entry[0].vpn]
        network: list[UpstreamSpec] = []
        for _link, servers in [e for e in plain if e[0].default_route] or plain:
            network.extend(s for s in servers if s not in network)
        if not network:  # no manager on the bus, or one that leaves resolv.conf alone
            network = [s for s in network_upstreams(resolv_conf) if not is_local(s.address)]
        vpn: list[UpstreamSpec] = []
        for link, servers in links:
            if link.vpn and link.default_route:
                vpn.extend(s for s in servers if s not in vpn)
        network, vpn = network[:MAX_SERVERS], vpn[:MAX_SERVERS]

        # VPN links first, then priority (links come sorted by priority).
        claims: dict[str, list[tuple[LinkDns, tuple[UpstreamSpec, ...]]]] = {}
        for link, servers in sorted(links, key=lambda entry: not entry[0].vpn):
            for domain in link.domains:
                if domain:
                    claims.setdefault(domain, []).append((link, servers))
        routes = [_merge(domain, claimed) for domain, claimed in claims.items()]
        # Local names follow the default DNS route: through a full-tunnel VPN
        # they go to the VPN's DNS, not to the LAN it runs over.
        local = tuple(vpn or network)
        if local:
            routes += [Route(zone, local, "", bool(vpn)) for zone in LOCAL_ZONES + LOCAL_REVERSE_ZONES
                       if zone not in claims]
        return cls(routes, network=network, vpn=vpn, local=local)

def _merge(domain: str, claimed: list[tuple[LinkDns, tuple[UpstreamSpec, ...]]]) -> Route:
    servers: list[UpstreamSpec] = []
    for _link, specs in claimed:
        servers.extend(s for s in specs if s not in servers)
    first = claimed[0][0]
    return Route(domain, tuple(servers[:MAX_SERVERS]), first.interface, first.vpn)
