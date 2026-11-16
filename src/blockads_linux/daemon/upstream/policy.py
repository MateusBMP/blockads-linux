"""The upstream policy: which servers answer which question.

Tiers, in order:

1. ``route``: per-domain routes to a link's DNS (:mod:`..router`): VPN split
   DNS, LAN search domains, local names. A routed name goes *only* there:
   internal names must not leak to a public resolver;
2. ``captive``: NetworkManager reports a captive portal or limited
   connectivity → the network DNS first, so the login page resolves;
3. ``trusted``: the primary connection is a trusted network in "network DNS"
   mode → its DNS (filtering stays on; the configured servers follow);
   "encrypted only" wins over it;
4. ``vpn``: a VPN that owns the default DNS route → its DNS (option, on by
   default);
5. ``configured`` (Quad9 DoH by default, or the network's DNS for "system");
6. ``fallback`` (the preset's plain DNS);
7. ``network``: the network DNS as a last resort.

"Encrypted only" drops tiers 2, 3, 6 and 7; the clock rescue (``ntp-rescue``:
the preset's plain DNS, then the network's, NTP names only) replaces them.
Tiers 1 and 4 stay: they are the local network's or the VPN's own servers.

Transports are reused across network changes when their spec is unchanged;
:meth:`UpstreamPolicy.apply` returns the ones that are no longer needed so
the caller can close them.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

from ..netdns import RESOLV_CONF, is_local_address
from ..netmon import NetworkState
from ..resolver import Tier, Upstream
from ..router import Router
from .base import Question
from .presets import UpstreamSpec


@dataclass(frozen=True, slots=True)
class PolicyConfig:
    configured: tuple[UpstreamSpec, ...] = ()  # empty with system=True
    fallback: tuple[UpstreamSpec, ...] = ()
    rescue: tuple[UpstreamSpec, ...] = ()  # plain servers for the clock rescue (before the network's)
    system: bool = False  # "configured" is the network's own DNS
    encrypted_only: bool = False
    vpn_dns: bool = True  # tier 3
    network_tier: bool = True  # tier 7 (off when the user picked the fallback explicitly)
    #: NetworkManager connection UUIDs of trusted networks in "network_dns" mode (tier 3).
    network_dns_uuids: frozenset[str] = frozenset()
    #: (UUID, BSSID) of those pinned to one access point: trusted only through it.
    network_dns_pins: frozenset[tuple[str, str]] = frozenset()

    def __post_init__(self) -> None:
        for name in ("configured", "fallback", "rescue"):
            object.__setattr__(self, name, tuple(getattr(self, name)))
        object.__setattr__(self, "network_dns_uuids", frozenset(self.network_dns_uuids))
        object.__setattr__(self, "network_dns_pins",
                           frozenset((uuid, bssid.lower()) for uuid, bssid in self.network_dns_pins))
        if not self.configured and not self.system:
            raise ValueError("no configured upstream")
        if self.encrypted_only and (self.system or not all(spec.encrypted for spec in self.configured)):
            raise ValueError("encrypted only needs encrypted upstreams (DoH or DoT)")

    def trusts_network_dns(self, uuid: str, bssid: str) -> bool:
        if not uuid or uuid not in self.network_dns_uuids:
            return False
        pins = {pin for u, pin in self.network_dns_pins if u == uuid}
        return not pins or bssid.lower() in pins


class UpstreamPolicy:
    def __init__(self, config: PolicyConfig, state: NetworkState | None = None, *,
                 build: Callable[[UpstreamSpec], Upstream] = UpstreamSpec.build,
                 resolv_conf: Path = RESOLV_CONF,
                 is_local: Callable[[str], bool] = is_local_address) -> None:
        self.config = config
        self._build = build
        self._resolv_conf = resolv_conf
        self._is_local = is_local
        self._upstreams: dict[UpstreamSpec, Upstream] = {}
        self._fixed = set(config.configured) | set(config.fallback) | set(config.rescue)
        self.state = NetworkState("none")
        self.router = Router()
        self.tiers: tuple[Tier, ...] = ()
        self.captive_tiers: tuple[Tier, ...] = ()
        self.trusted_dns = False
        self.rescue: tuple[Tier, ...] = ()
        self.apply(state if state is not None else NetworkState("none"))

    def apply(self, state: NetworkState) -> list[Upstream]:
        """Adopt a new network state; return the transports no longer used."""
        config = self.config
        self.state = state
        self.router = Router.from_state(state, resolv_conf=self._resolv_conf, is_local=self._is_local)
        network = self.router.network
        used: set[UpstreamSpec] = set()
        tiers: list[tuple[str, Sequence[UpstreamSpec]]] = []
        self.trusted_dns = bool(network) and not config.encrypted_only and not config.system \
            and config.trusts_network_dns(state.primary_uuid, state.primary_bssid)
        if self.trusted_dns:
            tiers.append(("trusted", network))
        if config.vpn_dns and self.router.vpn:
            tiers.append(("vpn", self.router.vpn))
        tiers.append(("configured", network if config.system else config.configured))
        if not config.encrypted_only:
            tiers.append(("fallback", config.fallback))
            if not config.system and config.network_tier:
                tiers.append(("network", network))
        self.tiers = self._tiers(tiers, used)
        self.captive_tiers = ()
        if state.captive and not config.encrypted_only and network:
            self.captive_tiers = self._tiers([("captive", network), *tiers], used)
        self.rescue = ()
        if config.encrypted_only:
            self.rescue = self._tiers([("ntp-rescue", config.rescue + tuple(network))], used)
        for route in self.router.routes.values():
            used.update(route.servers)
        used.update(self.router.local)
        stale = [self._upstreams.pop(spec) for spec in list(self._upstreams)
                 if spec not in used and spec not in self._fixed]
        return stale

    def _tiers(self, tiers: Iterable[tuple[str, Sequence[UpstreamSpec]]], used: set[UpstreamSpec]) -> tuple[Tier, ...]:
        """Build tiers; a server already in an earlier tier is not tried again."""
        seen: set[UpstreamSpec] = set()
        result = []
        for name, specs in tiers:
            fresh = [spec for spec in dict.fromkeys(specs) if spec not in seen]
            seen.update(fresh)
            used.update(fresh)
            if fresh:
                result.append(Tier(name, [self._get(spec) for spec in fresh]))
        return tuple(result)

    def _get(self, spec: UpstreamSpec) -> Upstream:
        upstream = self._upstreams.get(spec)
        if upstream is None:
            upstream = self._upstreams[spec] = self._build(spec)
        return upstream

    # --- TierPolicy -----------------------------------------------------------

    def select(self, question: Question) -> tuple[Sequence[Tier], Sequence[Tier]]:
        route = self.router.route(question.name)
        if route is not None:
            return (Tier("route", [self._get(spec) for spec in route.servers]),), ()
        return (self.captive_tiers or self.tiers), self.rescue

    def upstreams(self) -> list[Upstream]:
        return list(self._upstreams.values())

    # --- status ---------------------------------------------------------------

    def summary(self) -> dict[str, object]:
        """For the status API: what the policy would use now (no names)."""
        tiers = self.captive_tiers or self.tiers
        return {
            "source": self.state.source,
            "captive": bool(self.captive_tiers),
            "trusted_dns": self.trusted_dns,
            "vpn": bool(self.router.vpn) and self.config.vpn_dns,
            "encrypted_only": self.config.encrypted_only,
            "routes": len(self.router.routes),
            "tiers": [{"name": t.name, "upstreams": [u.label for u in t.upstreams],
                       "encrypted": all(u.encrypted for u in t.upstreams)} for t in tiers],
        }
