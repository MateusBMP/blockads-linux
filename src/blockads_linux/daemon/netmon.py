"""Network state from NetworkManager and systemd-resolved over D-Bus
.

REDIRECT hides where a query was originally sent, so the upstream policy
rebuilds the intent from what the network managers know:

* NetworkManager: ``Connectivity`` (captive portal), ``Metered`` (for the
  updater), the primary connection's UUID (trusted networks), active VPNs
  and ``DnsManager.Configuration`` (per-interface servers and domains);
* systemd-resolved: per-link DNS servers, domains and ``DefaultRoute``, used
  when NetworkManager is not running (systemd-networkd, other managers).

:func:`read_state` turns the properties into a :class:`NetworkState`. It reads
them through a :class:`PropertySource`, so the parsing is tested against
recorded property fixtures without a bus; :class:`DBusProperties` is the real
source and :class:`NetworkMonitor` watches for changes and resume.

Server addresses are reported as configured, local ones included; the
policy layer drops loopback and this host's own addresses.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass, field, replace
from enum import IntEnum
from typing import Any, Protocol
from urllib.parse import urlsplit

from jeepney import DBusAddress, DBusErrorResponse, Properties, new_method_call
from jeepney.wrappers import unwrap_msg
from jeepney.bus_messages import MatchRule, message_bus
from jeepney.io.asyncio import open_dbus_router
from jeepney.low_level import HeaderFields, Message

log = logging.getLogger("blockadsd.netmon")

NM_BUS = "org.freedesktop.NetworkManager"
NM_PATH = "/org/freedesktop/NetworkManager"
NM_IFACE = "org.freedesktop.NetworkManager"
NM_DNS_PATH = "/org/freedesktop/NetworkManager/DnsManager"
NM_DNS_IFACE = "org.freedesktop.NetworkManager.DnsManager"
NM_ACTIVE_IFACE = "org.freedesktop.NetworkManager.Connection.Active"
NM_DEVICE_IFACE = "org.freedesktop.NetworkManager.Device"
RESOLVED_BUS = "org.freedesktop.resolve1"
RESOLVED_PATH = "/org/freedesktop/resolve1"
RESOLVED_IFACE = "org.freedesktop.resolve1.Manager"
RESOLVED_LINK_IFACE = "org.freedesktop.resolve1.Link"
LOGIND_BUS = "org.freedesktop.login1"
LOGIND_PATH = "/org/freedesktop/login1"
LOGIND_IFACE = "org.freedesktop.login1.Manager"
PROPERTIES_IFACE = "org.freedesktop.DBus.Properties"

NM_ACTIVATED = 2  # NMActiveConnectionState
VPN_TYPES = frozenset({"vpn", "wireguard"})  # connection types that count as a VPN


class Connectivity(IntEnum):
    UNKNOWN = 0
    NONE = 1
    PORTAL = 2
    LIMITED = 3
    FULL = 4


class Metered(IntEnum):
    UNKNOWN = 0
    YES = 1
    NO = 2
    GUESS_YES = 3
    GUESS_NO = 4

    @property
    def metered(self) -> bool:
        return self in (Metered.YES, Metered.GUESS_YES)


@dataclass(frozen=True, slots=True)
class LinkDns:
    """DNS configuration of one interface (or ``""`` for global resolved DNS)."""

    interface: str
    servers: tuple[str, ...]  # IPv6 link-local ones carry "%interface"
    search: tuple[str, ...] = ()  # search domains (also routed to this link)
    routes: tuple[str, ...] = ()  # routing-only domains ("~corp.example"), without "~"
    default_route: bool = True  # may answer names no domain routes elsewhere
    vpn: bool = False
    priority: int = 0  # NetworkManager: lower wins; 0 when unknown

    @property
    def domains(self) -> tuple[str, ...]:
        """Every domain routed to this link (search and routing-only); "" is the root."""
        return self.search + tuple(d for d in self.routes if d not in self.search)


@dataclass(frozen=True, slots=True)
class NetworkState:
    source: str  # "networkmanager" | "resolved" | "none"
    connectivity: Connectivity = Connectivity.UNKNOWN
    metered: Metered = Metered.UNKNOWN
    primary_uuid: str = ""
    primary_name: str = ""  # the connection's id ("Home Wi-Fi"), for the Networks page
    primary_type: str = ""  # NetworkManager connection type ("802-11-wireless", "802-3-ethernet", "vpn", ...)
    vpn_active: bool = False
    connectivity_check_host: str = ""  # NetworkManager's probe host (internal allowlist)
    links: tuple[LinkDns, ...] = field(default=())
    #: NetworkManager actually probes (ConnectivityCheckEnabled and ...Available).
    connectivity_checked: bool = True
    #: NetworkManager's DnsManager.Mode ("systemd-resolved", "dnsmasq", "default", ...).
    dns_mode: str = ""
    #: Interfaces of NetworkManager's VPN connections (WireGuard, tun of a VPN plugin).
    vpn_interfaces: frozenset[str] = frozenset()
    #: systemd-resolved's global DNSOverTLS ("yes", "opportunistic", "no"; "" without resolved).
    #: "yes" sends its queries over port 853, past the port-53 redirect (bypass warning).
    resolved_dot: str = ""

    @property
    def captive(self) -> bool:
        """A captive portal or limited connectivity: the login page needs network DNS.

        PORTAL only comes from a real check. LIMITED without checking is NM's
        guess from its own state: an interface it does not manage (ifupdown,
        networkd) gives CONNECTED_LOCAL -> LIMITED on a perfectly normal
        network, so it does not count (seen on Debian 12).
        """
        if self.connectivity is Connectivity.PORTAL:
            return True
        return self.connectivity is Connectivity.LIMITED and self.connectivity_checked


class PropertySource(Protocol):
    async def get_all(self, bus: str, path: str, interface: str) -> Mapping[str, Any] | None:
        """All properties as plain values, or None if the object or service is missing."""
        ...

    async def call(self, bus: str, path: str, interface: str, method: str,
                   signature: str, args: tuple[Any, ...]) -> tuple[Any, ...] | None: ...


# --- parsing -----------------------------------------------------------------


def normalize_domain(domain: str) -> str | None:
    """Lower-case, without the trailing dot; "" for the root ("." or "~."); None if bad."""
    name = domain.strip().rstrip(".").lower()
    if not name:
        return ""
    if len(name) > 253 or any(not 0 < len(label) < 64 for label in name.split(".")):
        return None
    return name


def scoped_address(address: str, interface: str) -> str | None:
    """Validate an address; add ``%interface`` to unscoped IPv6 link-local ones."""
    text = address.strip()
    try:
        ip = ipaddress.ip_address(text.split("%", 1)[0])
    except ValueError:
        return None
    if ip.version == 6 and ip.is_link_local and "%" not in text:
        return f"{text}%{interface}" if interface else None
    return text


def _split_domains(domains: Iterable[str]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    search: list[str] = []
    routes: list[str] = []
    for raw in domains:
        routing = raw.startswith("~")
        name = normalize_domain(raw[1:] if routing else raw)
        if name is None:
            continue
        target = routes if routing or name == "" else search
        if name not in target:
            target.append(name)
    return tuple(search), tuple(routes)


def _servers(addresses: Iterable[str], interface: str) -> tuple[str, ...]:
    result: list[str] = []
    for address in addresses:
        scoped = scoped_address(address, interface)
        if scoped is not None and scoped not in result:
            result.append(scoped)
    return tuple(result)


async def read_state(source: PropertySource,
                     if_name: Callable[[int], str] | None = None) -> NetworkState:
    """NetworkManager's view if it runs, else resolved's, else an empty state.

    ``if_name`` maps resolved's interface indexes to names (default: this host's).
    """
    state = await _read_state(source, if_name)
    manager = await source.get_all(RESOLVED_BUS, RESOLVED_PATH, RESOLVED_IFACE)
    dot = str((manager or {}).get("DNSOverTLS", ""))
    return replace(state, resolved_dot=dot) if dot in ("yes", "opportunistic", "no") else state


async def _read_state(source: PropertySource, if_name: Callable[[int], str] | None) -> NetworkState:
    nm = await _read_networkmanager(source)
    resolved = None
    if nm is None or not nm.links or nm.dns_mode == "systemd-resolved":
        resolved = await _read_resolved(source, if_name or _interface_name)
    if nm is None:
        return resolved or NetworkState("none")
    if resolved is not None and resolved.links:
        # NetworkManager manages no DNS at all (Ubuntu Server: networkd owns the
        # NIC), or pushes its DNS into resolved: resolved has the whole picture,
        # NetworkManager's own links included. Keep NM's connectivity, metering
        # and connection types (seen on Ubuntu 24.04).
        links = tuple(replace(link, vpn=link.vpn or link.interface in nm.vpn_interfaces) for link in resolved.links)
        return replace(nm, source="networkmanager+resolved", links=links)
    return nm


async def _read_networkmanager(source: PropertySource) -> NetworkState | None:
    nm = await source.get_all(NM_BUS, NM_PATH, NM_IFACE)
    if nm is None:
        return None
    dns = await source.get_all(NM_BUS, NM_DNS_PATH, NM_DNS_IFACE) or {}
    # interface -> (connection type, owns a default route)
    interfaces: dict[str, tuple[str, bool]] = {}
    vpn_active = False
    vpn_default = False  # a VPN-plugin connection owns a default route
    primary_uuid = primary_name = primary_type = ""
    primary = str(nm.get("PrimaryConnection", "/"))
    for path in nm.get("ActiveConnections", ()):
        active = await source.get_all(NM_BUS, path, NM_ACTIVE_IFACE)
        if not active or int(active.get("State", 0)) != NM_ACTIVATED:
            continue
        kind = "vpn" if active.get("Vpn") else str(active.get("Type", ""))
        default = bool(active.get("Default")) or bool(active.get("Default6"))
        if kind in VPN_TYPES:
            vpn_active = True
        if path == primary:
            primary_uuid = str(active.get("Uuid", ""))
            primary_name = str(active.get("Id", ""))
            primary_type = kind
        if kind == "vpn":
            # A VPN plugin's Devices is the device it runs over (wlan0), not
            # its tunnel; its DNS entries carry the "vpn" flag instead.
            vpn_default = vpn_default or default
            continue
        for device_path in active.get("Devices", ()):
            device = await source.get_all(NM_BUS, device_path, NM_DEVICE_IFACE)
            if not device:
                continue
            for name in {str(device.get("IpInterface", "")), str(device.get("Interface", ""))} - {""}:
                interfaces.setdefault(name, (kind, default))
    links = []
    for entry in dns.get("Configuration", ()):
        interface = str(entry.get("interface", ""))
        kind, default = interfaces.get(interface, ("", False))
        search, routes = _split_domains(str(d) for d in entry.get("domains", ()))
        vpn = bool(entry.get("vpn")) or kind in VPN_TYPES
        if entry.get("vpn"):
            default = vpn_default
        links.append(LinkDns(
            interface=interface,
            servers=_servers((str(a) for a in entry.get("nameservers", ())), interface),
            search=search,
            routes=routes,
            default_route=default or "" in routes or not interfaces,
            vpn=vpn,
            priority=int(entry.get("priority", 0)),
        ))
    links.sort(key=lambda link: link.priority)  # stable: keeps NetworkManager's order on ties
    return NetworkState(
        "networkmanager",
        metered=_enum(Metered, nm.get("Metered")),
        primary_uuid=primary_uuid,
        primary_name=primary_name,
        primary_type=primary_type,
        vpn_active=vpn_active,
        connectivity_check_host=urlsplit(str(nm.get("ConnectivityCheckUri", ""))).hostname or "",
        links=tuple(links),
        # NetworkManager managing no connection derives Connectivity from its own
        # idle state: it says nothing about the real network.
        connectivity=_enum(Connectivity, nm.get("Connectivity")) if interfaces else Connectivity.UNKNOWN,
        # Missing on NetworkManager < 1.10/1.16: assume it checks (the old meaning).
        connectivity_checked=(bool(nm.get("ConnectivityCheckEnabled", True))
                              and bool(nm.get("ConnectivityCheckAvailable", True))),
        dns_mode=str(dns.get("Mode", "")),
        vpn_interfaces=frozenset(name for name, (kind, _) in interfaces.items() if kind in VPN_TYPES)
        | frozenset(link.interface for link in links if link.vpn),
    )


async def _read_resolved(source: PropertySource, if_name: Callable[[int], str]) -> NetworkState | None:
    manager = await source.get_all(RESOLVED_BUS, RESOLVED_PATH, RESOLVED_IFACE)
    if manager is None:
        return None
    servers: dict[int, list[str]] = {}
    for ifindex, family, raw in manager.get("DNS", ()):
        try:
            address = str(ipaddress.ip_address(bytes(raw)))
        except ValueError:
            continue
        if family not in (socket.AF_INET, socket.AF_INET6):
            continue
        servers.setdefault(int(ifindex), []).append(address)
    domains: dict[int, list[str]] = {}
    for ifindex, domain, routing_only in manager.get("Domains", ()):
        domains.setdefault(int(ifindex), []).append(("~" if routing_only else "") + str(domain))
    links = []
    for ifindex in sorted(set(servers) | set(domains)):
        name = if_name(ifindex) if ifindex else ""
        default = True
        if ifindex:
            reply = await source.call(RESOLVED_BUS, RESOLVED_PATH, RESOLVED_IFACE, "GetLink", "i", (ifindex,))
            link = await source.get_all(RESOLVED_BUS, reply[0], RESOLVED_LINK_IFACE) if reply else None
            if link is not None and "DefaultRoute" in link:
                default = bool(link["DefaultRoute"])
        search, routes = _split_domains(domains.get(ifindex, ()))
        if not ifindex and not servers.get(ifindex):
            continue  # global domains without global servers route nowhere
        links.append(LinkDns(name, _servers(servers.get(ifindex, ()), name), search, routes,
                             default_route=default or "" in routes))
    return NetworkState("resolved", links=tuple(links))


def _interface_name(ifindex: int) -> str:
    if not ifindex:
        return ""
    try:
        return socket.if_indextoname(ifindex)
    except OSError:
        return f"if{ifindex}"


def _enum(kind: type[IntEnum], value: Any) -> Any:
    try:
        return kind(int(value))
    except (TypeError, ValueError):
        return kind(0)


# --- D-Bus --------------------------------------------------------------------


def unwrap(value: Any, signature: str = "v") -> Any:
    """jeepney's ``(signature, value)`` variants -> plain Python values."""
    if signature == "v":
        inner_sig, inner = value
        return unwrap(inner, inner_sig)
    if signature.startswith("a{"):
        value_sig = signature[3:-1]
        return {k: unwrap(v, value_sig) for k, v in value.items()}
    if signature.startswith("a") and signature[1] in "v{(":
        return [unwrap(v, signature[1:]) for v in value]
    if signature.startswith("a") and signature[1] == "a":
        return [unwrap(v, signature[1:]) for v in value]
    return value


class DBusProperties:
    """:class:`PropertySource` over a jeepney asyncio router."""

    def __init__(self, router: Any, timeout: float = 2.0) -> None:
        self.router = router
        self.timeout = timeout

    async def _send(self, message: Any) -> Any | None:
        try:
            async with asyncio.timeout(self.timeout):
                reply = await self.router.send_and_get_reply(message)
        except (TimeoutError, OSError):
            return None
        try:
            return unwrap_msg(reply)
        except DBusErrorResponse:
            return None

    async def get_all(self, bus: str, path: str, interface: str) -> Mapping[str, Any] | None:
        body = await self._send(Properties(DBusAddress(path, bus, interface)).get_all())
        if body is None:
            return None
        return {key: unwrap(value) for key, value in body[0].items()}

    async def call(self, bus: str, path: str, interface: str, method: str,
                   signature: str, args: tuple[Any, ...]) -> tuple[Any, ...] | None:
        body = await self._send(new_method_call(DBusAddress(path, bus, interface), method, signature, args))
        return tuple(body) if body is not None else None


ChangeHandler = Callable[[NetworkState, str], Awaitable[None] | None]


class NetworkMonitor:
    """Keeps :attr:`state` current and reports changes and resume.

    ``on_change(state, reason)`` runs with reason ``"network"`` when the state
    differs from the last one, and ``"resume"`` after every resume from sleep
    (logind ``PrepareForSleep(false)``), changed or not. Signals arriving
    within ``debounce`` seconds are folded into one re-read. If the bus goes
    away the monitor reconnects with backoff; :attr:`state` keeps its last
    value meanwhile.
    """

    def __init__(self, on_change: ChangeHandler | None = None, *, bus: str = "SYSTEM",
                 debounce: float = 0.5, retry: float = 5.0) -> None:
        self.on_change = on_change
        self.bus = bus
        self.debounce = debounce
        self.retry = retry
        self.state = NetworkState("none")
        self.ready = asyncio.Event()  # set after the first read

    async def run(self) -> None:
        delay = 0.5
        while True:
            try:
                await self._session()
                delay = 0.5
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # the bus went away; keep the last state
                log.warning("D-Bus monitor: %s; retrying", type(exc).__name__)
            self.ready.set()
            await asyncio.sleep(delay)
            delay = min(delay * 2, self.retry)

    async def _session(self) -> None:
        rules = [
            MatchRule(type="signal", interface=PROPERTIES_IFACE, member="PropertiesChanged",
                      sender=NM_BUS, path_namespace=NM_PATH),
            MatchRule(type="signal", interface=PROPERTIES_IFACE, member="PropertiesChanged",
                      sender=RESOLVED_BUS, path_namespace=RESOLVED_PATH),
            MatchRule(type="signal", sender="org.freedesktop.DBus", interface="org.freedesktop.DBus",
                      member="NameOwnerChanged"),
            MatchRule(type="signal", sender=LOGIND_BUS, interface=LOGIND_IFACE, member="PrepareForSleep",
                      path=LOGIND_PATH),
        ]
        async with open_dbus_router(self.bus) as router:
            queue: asyncio.Queue[Any] = asyncio.Queue(256)
            # The bus filters by sender. Locally, signals carry the sender's
            # unique name (":1.42"), which jeepney's MatchRule would compare
            # with the well-known name, so take every signal; _reason() sorts them.
            with router.filter(MatchRule(type="signal"), queue=queue):
                for rule in rules:
                    await router.send_and_get_reply(message_bus.AddMatch(rule))
                source = DBusProperties(router)
                await self._refresh(source, "network", initial=True)
                await self._watch(queue, source)

    async def _watch(self, queue: asyncio.Queue[Any], source: PropertySource) -> None:
        while True:
            reason = _reason(await queue.get())
            if reason is None:
                continue
            # Fold a burst of signals into one re-read; a resume in it wins.
            loop = asyncio.get_running_loop()
            until = loop.time() + self.debounce
            while (remaining := until - loop.time()) > 0:
                try:
                    async with asyncio.timeout(remaining):
                        message = await queue.get()
                except TimeoutError:
                    break
                if _reason(message) == "resume":
                    reason = "resume"
            await self._refresh(source, reason)

    async def _refresh(self, source: PropertySource, reason: str, *, initial: bool = False) -> None:
        state = await read_state(source)
        changed = state != self.state
        self.state = state
        self.ready.set()
        if initial and not changed:
            return
        if (changed or reason == "resume") and self.on_change is not None:
            try:
                result = self.on_change(state, reason)
                if result is not None:
                    await result
            except Exception:
                log.exception("network change handler failed")


#: PropertiesChanged on these interfaces can change the state; others (access
#: point strength, device statistics) arrive often and are ignored.
WATCHED_INTERFACES = frozenset({NM_IFACE, NM_DNS_IFACE, NM_ACTIVE_IFACE, RESOLVED_IFACE, RESOLVED_LINK_IFACE})


def _reason(message: Message) -> str | None:
    """"resume", "network", or None for a signal that changes nothing we read."""
    member = message.header.fields.get(HeaderFields.member)
    body = message.body or ()
    if member == "PrepareForSleep":
        return "resume" if body and not body[0] else None
    if member == "NameOwnerChanged":
        return "network" if body and body[0] in (NM_BUS, RESOLVED_BUS) else None
    if member == "PropertiesChanged":
        return "network" if body and body[0] in WATCHED_INTERFACES else None
    return None
