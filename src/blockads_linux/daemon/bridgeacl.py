"""Source ACL for the bridge listener (``dns-bridge``).

``blockadsd-bridge.socket`` listens on ``0.0.0.0:154`` and ``[::]:154``. The
firewall admits only redirected (``ctstate DNAT``) packets to it; this is the
second layer: the daemon answers a source only when it lies in a subnet of an
interface matching ``bridge_interfaces``. Everything else is dropped silently
and counted.

Inputs, all re-read on refresh:

- the patterns come from ``/run/blockads-fw/state.json`` (what the helper
  actually applied). No state, an unreadable one, or ``bridge.status != "on"``
  means no pattern: everything is dropped (fail closed);
- IPv4 subnets come from the directly connected routes in
  ``/proc/self/net/route`` (no gateway, mask not ``/0``);
- IPv6 subnets come from ``/proc/self/net/if_inet6`` (global and site scope;
  link-local and host scope are never trusted, prefix ``/0`` neither).

``/proc/self/net`` rather than ``/proc/net``: the unit runs with
``ProcSubset=pid``, which hides the top-level ``/proc/net`` symlink.

A source that is not allowed triggers a refresh at most every
``min_refresh`` seconds (a container may have just appeared), and at once when
``state.json`` changed since the last read: the daemon starts before
``blockads-fw apply`` (``ExecStartPost``) writes it, so the first redirected
queries after a start must not wait out the rate limit (found in VM testing,
libvirt guests). An allowed source refreshes when the snapshot is older than
``max_age`` (a bridge may have gone).
"""

from __future__ import annotations

import ipaddress
import json
import logging
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path

from .health import FW_STATE_PATH

log = logging.getLogger(__name__)

PROC_ROUTE = Path("/proc/self/net/route")
PROC_IF_INET6 = Path("/proc/self/net/if_inet6")

_RTF_UP = 0x1
_RTF_GATEWAY = 0x2
_IPV6_SCOPE_HOST = 0x10
_IPV6_SCOPE_LINK = 0x20

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


def match_interface(name: str, patterns: Iterable[str]) -> bool:
    """iptables ``-i`` semantics: ``foo+`` matches every name starting with ``foo``."""
    for pattern in patterns:
        if pattern.endswith("+"):
            if name.startswith(pattern[:-1]):
                return True
        elif name == pattern:
            return True
    return False


def read_bridge_patterns(path: Path = FW_STATE_PATH) -> tuple[str, ...]:
    """Interface patterns of the bridge redirect ``blockads-fw`` applied (empty when off or unknown)."""
    try:
        state = json.loads(path.read_text("utf-8"))
    except FileNotFoundError:
        return ()
    except (OSError, ValueError) as exc:
        log.warning("cannot read %s: %s", path, exc)
        return ()
    if not isinstance(state, dict) or state.get("applied") is not True:
        return ()
    bridge = state.get("bridge")
    if not isinstance(bridge, dict) or bridge.get("status") != "on":
        return ()
    interfaces = bridge.get("interfaces")
    if not isinstance(interfaces, list):
        return ()
    return tuple(item for item in interfaces
                 if isinstance(item, str) and item.rstrip("+") and item not in ("lo", "lo+"))


def ipv4_subnets(text: str) -> list[tuple[str, ipaddress.IPv4Network]]:
    """``(interface, subnet)`` for each directly connected route in ``/proc/net/route`` text."""
    found = []
    for line in text.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 8:
            continue
        try:
            flags = int(fields[3], 16)
            dest = int.from_bytes(bytes.fromhex(fields[1]), "little")
            mask = int.from_bytes(bytes.fromhex(fields[7]), "little")
        except ValueError:
            continue
        if not flags & _RTF_UP or flags & _RTF_GATEWAY or mask == 0:
            continue
        try:
            net = ipaddress.IPv4Network((dest, bin(mask).count("1")), strict=False)
        except ValueError:
            continue
        found.append((fields[0], net))
    return found


def ipv6_subnets(text: str) -> list[tuple[str, ipaddress.IPv6Network]]:
    """``(interface, subnet)`` for each global/site address in ``/proc/net/if_inet6`` text."""
    found = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 6 or len(fields[0]) != 32:
            continue
        try:
            address = ipaddress.IPv6Address(int(fields[0], 16))
            prefix = int(fields[2], 16)
            scope = int(fields[3], 16)
        except ValueError:
            continue
        if scope & (_IPV6_SCOPE_HOST | _IPV6_SCOPE_LINK) or not 0 < prefix <= 128 or address.is_link_local:
            continue
        found.append((fields[5], ipaddress.IPv6Network((address, prefix), strict=False)))
    return found


def file_signature(path: Path) -> object:
    """(inode, mtime, size) of a file, or None: changes whenever the file is rewritten."""
    try:
        st = path.stat()
    except OSError:
        return None
    return st.st_ino, st.st_mtime_ns, st.st_size


def _read(path: Path) -> str:
    try:
        return path.read_text("ascii", errors="replace")
    except OSError:
        return ""


@dataclass(slots=True)
class AclStats:
    allowed: int = 0
    denied: int = 0
    refreshes: int = 0


@dataclass
class BridgeAcl:
    """Decides whether a source address may use the bridge listener."""

    patterns: Callable[[], tuple[str, ...]] = read_bridge_patterns
    #: Changes when the helper's state changes (default: stat of state.json).
    state_signature: Callable[[], object] = lambda: file_signature(FW_STATE_PATH)
    route_path: Path = PROC_ROUTE
    if_inet6_path: Path = PROC_IF_INET6
    min_refresh: float = 2.0
    max_age: float = 30.0
    clock: Callable[[], float] = time.monotonic
    stats: AclStats = field(default_factory=AclStats)
    networks: tuple[Network, ...] = ()
    interfaces: tuple[str, ...] = ()
    applied: tuple[str, ...] = ()
    _refreshed: float | None = None
    _seen_state: object = None

    def refresh(self) -> None:
        self._refreshed = self.clock()
        self._seen_state = self.state_signature()
        self.stats.refreshes += 1
        patterns = self.applied = tuple(self.patterns())
        networks: list[Network] = []
        interfaces: set[str] = set()
        if patterns:
            subnets: list[tuple[str, Network]] = [*ipv4_subnets(_read(self.route_path)),
                                                 *ipv6_subnets(_read(self.if_inet6_path))]
            for name, net in subnets:
                if name != "lo" and match_interface(name, patterns) and net not in networks:
                    networks.append(net)
                    interfaces.add(name)
        if tuple(networks) != self.networks:
            log.info("bridge clients: %d subnets on %d interfaces", len(networks), len(interfaces))
        self.networks = tuple(networks)
        self.interfaces = tuple(sorted(interfaces))

    def allows(self, host: str) -> bool:
        """True when ``host`` (a peer address, possibly with ``%scope``) may be answered."""
        try:
            address = ipaddress.ip_address(host.split("%", 1)[0])
        except ValueError:
            self.stats.denied += 1
            return False
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
            address = address.ipv4_mapped
        now = self.clock()
        if self._refreshed is None or now - self._refreshed >= self.max_age:
            self.refresh()
        if self._contains(address):
            self.stats.allowed += 1
            return True
        if now - self._refreshed >= self.min_refresh or self.state_signature() != self._seen_state:  # type: ignore[operator]
            self.refresh()
            if self._contains(address):
                self.stats.allowed += 1
                return True
        self.stats.denied += 1
        return False

    def summary(self) -> dict:
        """The status line for D-Bus: what the redirect covers and how many sources were answered/denied."""
        if self._refreshed is None or self.clock() - self._refreshed >= self.max_age:
            self.refresh()
        return {
            "patterns": list(self.applied),
            "interfaces": list(self.interfaces),
            "subnets": len(self.networks),
            "allowed": self.stats.allowed,
            "denied": self.stats.denied,
        }

    def _contains(self, address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        if address.is_loopback or address.is_unspecified or address.is_multicast:
            return False
        return any(address.version == net.version and address in net for net in self.networks)
