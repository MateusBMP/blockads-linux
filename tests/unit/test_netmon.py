"""Tests for daemon.netmon (NetworkManager / resolved state over D-Bus)."""

import asyncio
import json
import socket
from pathlib import Path

import pytest

from blockads_linux.daemon import netmon
from blockads_linux.daemon.netmon import (
    Connectivity,
    LinkDns,
    Metered,
    NetworkMonitor,
    NetworkState,
    normalize_domain,
    read_state,
    scoped_address,
    unwrap,
)

from .dbus_fake import FakeService, have_dbus_daemon, private_bus

FIXTURES = Path(__file__).parent.parent / "fixtures" / "netmon"
NM = netmon.NM_BUS
RESOLVED = netmon.RESOLVED_BUS


def run(coro):
    return asyncio.run(coro)


class FixtureSource:
    """PropertySource over recorded data (tools/record_netmon.py format)."""

    def __init__(self, data):
        self.data = data

    async def get_all(self, bus, path, interface):
        return self.data.get("get_all", {}).get(f"{bus} {path} {interface}")

    async def call(self, bus, path, interface, method, signature, args):
        result = self.data.get("call", {}).get(f"{bus} {path} {interface} {method} {json.dumps(list(args))}")
        return tuple(result) if result is not None else None

    def if_name(self, index):
        return self.data.get("if_names", {}).get(str(index), f"if{index}")


def state_of(data):
    source = FixtureSource(data)
    return run(read_state(source, source.if_name))


def nm_data(*, connectivity=4, metered=2, active=(), dns=(), primary=1):
    """NetworkManager objects: active = [(type, default, interface, vpn_flag)]."""
    base = f"{NM} /org/freedesktop/NetworkManager"
    data = {
        f"{base} {netmon.NM_IFACE}": {
            "Connectivity": connectivity, "Metered": metered,
            "PrimaryConnection": f"/org/freedesktop/NetworkManager/ActiveConnection/{primary}",
            "ActiveConnections": [f"/org/freedesktop/NetworkManager/ActiveConnection/{i}"
                                  for i in range(1, len(active) + 1)],
            "ConnectivityCheckUri": "http://check.example.org/status.txt",
        },
        f"{base}/DnsManager {netmon.NM_DNS_IFACE}": {"Configuration": list(dns)},
    }
    for i, (kind, default, interface, vpn) in enumerate(active, 1):
        data[f"{base}/ActiveConnection/{i} {netmon.NM_ACTIVE_IFACE}"] = {
            "Type": kind, "Vpn": vpn, "Default": default, "Default6": False, "State": 2,
            "Uuid": f"uuid-{i}", "Devices": [f"/org/freedesktop/NetworkManager/Devices/{i}"],
        }
        data[f"{base}/Devices/{i} {netmon.NM_DEVICE_IFACE}"] = {"Interface": interface, "IpInterface": interface}
    return {"get_all": data}


# --- helpers ------------------------------------------------------------------


@pytest.mark.parametrize("raw, expected", [
    ("Corp.Example.", "corp.example"), (".", ""), ("", ""), ("a..b", None), ("x" * 64 + ".com", None),
])
def test_normalize_domain(raw, expected):
    assert normalize_domain(raw) == expected


def test_scoped_address():
    assert scoped_address("192.168.1.1", "eth0") == "192.168.1.1"
    assert scoped_address("fe80::1", "eth0") == "fe80::1%eth0"
    assert scoped_address("fe80::1%wlan0", "eth0") == "fe80::1%wlan0"
    assert scoped_address("fe80::1", "") is None  # unusable without an interface
    assert scoped_address("2001:db8::1", "eth0") == "2001:db8::1"
    assert scoped_address("bogus", "eth0") is None


def test_unwrap_variants():
    assert unwrap(("u", 4)) == 4
    assert unwrap(("aa{sv}", [{"vpn": ("b", True), "nameservers": ("as", ["10.0.0.1"])}])) == [
        {"vpn": True, "nameservers": ["10.0.0.1"]}]
    assert unwrap(("a(iiay)", [(2, 2, b"\n\0\0\1")])) == [(2, 2, b"\n\0\0\1")]


def test_metered():
    assert Metered.YES.metered and Metered.GUESS_YES.metered
    assert not Metered.NO.metered and not Metered.GUESS_NO.metered and not Metered.UNKNOWN.metered


# --- NetworkManager -----------------------------------------------------------


def test_recorded_wifi_with_unrelated_tun():
    """Recorded on a Manjaro laptop (NM 1.58): Wi-Fi plus a non-default tun device."""
    state = state_of(json.loads((FIXTURES / "nm_wifi_tun.json").read_text()))
    assert state == NetworkState(
        "networkmanager", Connectivity.FULL, Metered.GUESS_NO,
        primary_uuid="00000000-0000-4000-8000-000000000003", primary_type="802-11-wireless", vpn_active=False,
        connectivity_check_host="ping.manjaro.org",
        links=(LinkDns("wlp0s20f3", ("192.168.0.1",), default_route=True, priority=100),),
        dns_mode="default")
    assert not state.captive


def test_vpn_split_dns():
    state = state_of(nm_data(
        active=[("802-3-ethernet", True, "eth0", False), ("vpn", False, "tun0", True)],
        dns=[
            {"interface": "eth0", "nameservers": ["192.168.1.1", "fe80::1"], "domains": ["lan"],
             "priority": 100, "vpn": False},
            {"interface": "tun0", "nameservers": ["10.8.0.1"], "domains": ["~Corp.Example.", "corp.example"],
             "priority": 50, "vpn": True},
        ]))
    assert state.vpn_active
    assert state.connectivity_check_host == "check.example.org"
    vpn, lan = state.links
    assert vpn == LinkDns("tun0", ("10.8.0.1",), search=("corp.example",), routes=("corp.example",),
                          default_route=False, vpn=True, priority=50)
    assert vpn.domains == ("corp.example",)
    assert lan == LinkDns("eth0", ("192.168.1.1", "fe80::1%eth0"), search=("lan",), default_route=True,
                          priority=100)


def test_full_tunnel_openvpn_runs_over_the_wifi_device():
    """A VPN plugin's active connection lists the Wi-Fi device, not tun0."""
    state = state_of(nm_data(
        active=[("802-11-wireless", False, "wlan0", False), ("vpn", True, "wlan0", True)],
        dns=[{"interface": "tun0", "nameservers": ["10.8.0.1"], "priority": 50, "vpn": True},
             {"interface": "wlan0", "nameservers": ["192.168.0.1"], "priority": 600, "vpn": False}]))
    tun, wlan = state.links
    assert tun.vpn and tun.default_route
    assert not wlan.vpn and not wlan.default_route


def test_full_tunnel_wireguard():
    state = state_of(nm_data(
        active=[("802-11-wireless", False, "wlan0", False), ("wireguard", True, "wg0", False)],
        dns=[{"interface": "wg0", "nameservers": ["10.2.0.1"], "domains": ["~."], "priority": -50, "vpn": False},
             {"interface": "wlan0", "nameservers": ["192.168.0.1"], "priority": 600, "vpn": False}]))
    assert state.vpn_active
    wg, wlan = state.links  # sorted by priority
    assert wg.vpn and wg.default_route and wg.routes == ("",)
    assert not wlan.default_route and not wlan.vpn


def test_captive_portal_and_metered():
    state = state_of(nm_data(connectivity=2, metered=1, active=[("802-11-wireless", True, "wlan0", False)],
                             dns=[{"interface": "wlan0", "nameservers": ["10.0.0.1"]}]))
    assert state.captive and state.metered.metered
    wired = [("802-3-ethernet", True, "eth0", False)]
    assert state_of(nm_data(connectivity=3, active=wired)).captive
    assert not state_of(nm_data(connectivity=1, active=wired)).captive
    # NetworkManager managing no connection: its Connectivity is only its idle state.
    assert not state_of(nm_data(connectivity=2)).captive


def test_limited_without_connectivity_checking_is_not_captive():
    # Debian 12 with ifupdown: NM sees the NIC as external, state CONNECTED_LOCAL,
    # checking disabled -> Connectivity LIMITED on a normal network.
    def nm(connectivity, enabled, available):
        data = nm_data(connectivity=connectivity, active=[("802-3-ethernet", True, "eth0", False)])
        main = data["get_all"][f"{NM} /org/freedesktop/NetworkManager {netmon.NM_IFACE}"]
        main.update(ConnectivityCheckEnabled=enabled, ConnectivityCheckAvailable=available)
        return state_of(data)
    assert not nm(3, False, False).captive
    assert not nm(3, True, False).captive  # no URI configured
    assert nm(3, True, True).captive
    assert nm(2, False, False).captive  # PORTAL only ever comes from a real check


def test_inactive_connections_and_bad_values_are_ignored():
    data = nm_data(connectivity=99, active=[("vpn", True, "tun0", True)],
                   dns=[{"interface": "eth9", "nameservers": ["not-an-ip", "fe80::5", "10.0.0.1", "10.0.0.1"],
                         "domains": ["ok.example", "bad..domain"]}])
    data["get_all"][f"{NM} /org/freedesktop/NetworkManager/ActiveConnection/1 {netmon.NM_ACTIVE_IFACE}"]["State"] = 1
    state = state_of(data)
    assert state.connectivity is Connectivity.UNKNOWN
    assert not state.vpn_active
    assert state.links == (LinkDns("eth9", ("fe80::5%eth9", "10.0.0.1"), search=("ok.example",),
                                   default_route=True),)


def test_missing_dns_manager():
    data = nm_data(active=[("802-3-ethernet", True, "eth0", False)])
    del data["get_all"][f"{NM} /org/freedesktop/NetworkManager/DnsManager {netmon.NM_DNS_IFACE}"]
    assert state_of(data).links == ()


# --- resolved -----------------------------------------------------------------


def resolved_data():
    manager = {
        "DNS": [[0, socket.AF_INET, [9, 9, 9, 9]],
                [2, socket.AF_INET, [192, 168, 1, 1]],
                [2, socket.AF_INET6, [0xfe, 0x80] + [0] * 13 + [1]],
                [5, socket.AF_INET, [10, 8, 0, 1]],
                [6, 99, [1, 2, 3, 4]]],
        "Domains": [[2, "lan", False], [5, "corp.example", True], [0, "global.example", False]],
    }
    base = f"{RESOLVED} /org/freedesktop/resolve1"
    return {
        "get_all": {
            f"{base} {netmon.RESOLVED_IFACE}": manager,
            f"{base}/link/_32 {netmon.RESOLVED_LINK_IFACE}": {"DefaultRoute": True},
            f"{base}/link/_35 {netmon.RESOLVED_LINK_IFACE}": {"DefaultRoute": False},
        },
        "call": {
            f"{base} {netmon.RESOLVED_IFACE} GetLink [2]": ["/org/freedesktop/resolve1/link/_32"],
            f"{base} {netmon.RESOLVED_IFACE} GetLink [5]": ["/org/freedesktop/resolve1/link/_35"],
        },
        "if_names": {"2": "eth0", "5": "wg0", "6": "eth1"},
    }


def test_resolved_without_networkmanager():
    state = state_of(resolved_data())
    assert state.source == "resolved"
    assert state.connectivity is Connectivity.UNKNOWN
    assert state.links == (
        LinkDns("", ("9.9.9.9",), search=("global.example",), default_route=True),
        LinkDns("eth0", ("192.168.1.1", "fe80::1%eth0"), search=("lan",), default_route=True),
        LinkDns("wg0", ("10.8.0.1",), routes=("corp.example",), default_route=False),
    )


def merged(nm, resolved):
    data = {key: dict(value) for key, value in resolved.items()}
    data["get_all"].update(nm["get_all"])
    return data


def test_networkmanager_managing_nothing_uses_resolved_links():
    # Ubuntu Server: NetworkManager runs, networkd owns the NIC; NM's DNS config is empty.
    state = state_of(merged(nm_data(connectivity=3), resolved_data()))
    assert state.source == "networkmanager+resolved"
    assert [link.interface for link in state.links] == ["", "eth0", "wg0"]
    assert state.connectivity is Connectivity.UNKNOWN and not state.captive


def test_networkmanager_over_resolved_takes_resolved_links_and_nm_types():
    nm = nm_data(active=[("802-3-ethernet", True, "eth0", False), ("wireguard", False, "wg0", False)],
                 dns=[{"interface": "eth0", "nameservers": ["192.168.1.1"]}])
    nm["get_all"][f"{NM} /org/freedesktop/NetworkManager/DnsManager {netmon.NM_DNS_IFACE}"]["Mode"] = \
        "systemd-resolved"
    state = state_of(merged(nm, resolved_data()))
    assert state.source == "networkmanager+resolved" and state.connectivity is Connectivity.FULL
    links = {link.interface: link for link in state.links}
    assert links["wg0"].vpn and links["wg0"].routes == ("corp.example",)  # type from NM, routes from resolved
    assert not links["eth0"].vpn and links["eth0"].search == ("lan",)
    assert state.vpn_active


def test_networkmanager_with_its_own_dns_is_used_alone():
    nm = nm_data(active=[("802-3-ethernet", True, "eth0", False)],
                 dns=[{"interface": "eth0", "nameservers": ["192.168.1.1"]}])
    state = state_of(merged(nm, resolved_data()))  # Mode "" / "default": NM's own view
    assert state.source == "networkmanager" and [link.interface for link in state.links] == ["eth0"]


def test_nothing_on_the_bus():
    assert state_of({}) == NetworkState("none")


# --- the monitor over a real (private) bus ------------------------------------

needs_bus = pytest.mark.skipif(not have_dbus_daemon(), reason="dbus-daemon not installed")
NM_PATH = "/org/freedesktop/NetworkManager"


def populate_nm(fake):
    fake.objects[(NM_PATH, netmon.NM_IFACE)] = {
        "Connectivity": ("u", 4), "Metered": ("u", 2),
        "PrimaryConnection": ("o", f"{NM_PATH}/ActiveConnection/1"),
        "ActiveConnections": ("ao", [f"{NM_PATH}/ActiveConnection/1"]),
        "ConnectivityCheckUri": ("s", "http://check.example.org/"),
    }
    fake.objects[(f"{NM_PATH}/ActiveConnection/1", netmon.NM_ACTIVE_IFACE)] = {
        "Type": ("s", "802-3-ethernet"), "Vpn": ("b", False), "Default": ("b", True), "Default6": ("b", False),
        "State": ("u", 2), "Uuid": ("s", "uuid-1"), "Devices": ("ao", [f"{NM_PATH}/Devices/1"]),
    }
    fake.objects[(f"{NM_PATH}/Devices/1", netmon.NM_DEVICE_IFACE)] = {
        "Interface": ("s", "eth0"), "IpInterface": ("s", "eth0")}
    fake.objects[(f"{NM_PATH}/DnsManager", netmon.NM_DNS_IFACE)] = {"Configuration": ("aa{sv}", [
        {"interface": ("s", "eth0"), "nameservers": ("as", ["192.168.1.1"]), "priority": ("i", 100),
         "vpn": ("b", False)}])}


async def wait_for(events, count, timeout=5.0):
    async with asyncio.timeout(timeout):
        while len(events) < count:
            await asyncio.sleep(0.01)


@needs_bus
def test_monitor_reads_and_follows_changes():
    async def scenario(address):
        events = []
        async with FakeService(address, [NM, netmon.LOGIND_BUS]) as fake:
            populate_nm(fake)
            monitor = NetworkMonitor(lambda state, reason: events.append((state, reason)),
                                     bus=address, debounce=0.05)
            task = asyncio.create_task(monitor.run())
            try:
                async with asyncio.timeout(5):
                    await monitor.ready.wait()
                assert monitor.state.links[0].servers == ("192.168.1.1",)
                assert events and events[0][1] == "network"  # first read differs from "none"
                # A burst of changes -> one re-read.
                await fake.changed(NM_PATH, netmon.NM_IFACE, Connectivity=("u", 2))
                await fake.changed(NM_PATH, netmon.NM_IFACE, Metered=("u", 1))
                await wait_for(events, 2)
                await asyncio.sleep(0.2)
                assert len(events) == 2
                assert events[1][0].captive and events[1][0].metered is Metered.YES
                # Signals on unwatched interfaces cost nothing.
                calls = fake.calls
                await fake.changed(f"{NM_PATH}/AccessPoint/1", "org.freedesktop.NetworkManager.AccessPoint",
                                   Strength=("y", 40))
                await asyncio.sleep(0.2)
                assert fake.calls == calls and len(events) == 2
                # Resume is reported even when nothing changed; going to sleep is not.
                await fake.signal(netmon.LOGIND_PATH, netmon.LOGIND_IFACE, "PrepareForSleep", "b", (True,))
                await asyncio.sleep(0.2)
                assert len(events) == 2
                await fake.signal(netmon.LOGIND_PATH, netmon.LOGIND_IFACE, "PrepareForSleep", "b", (False,))
                await wait_for(events, 3)
                assert events[2][1] == "resume" and events[2][0] == events[1][0]
                # A property change that leaves the state equal is not reported.
                await fake.changed(NM_PATH, netmon.NM_IFACE, Metered=("u", 1))
                await asyncio.sleep(0.2)
                assert len(events) == 3
            finally:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)

    with private_bus() as address:
        run(scenario(address))


@needs_bus
def test_monitor_survives_networkmanager_restart():
    async def scenario(address):
        events = []
        monitor = NetworkMonitor(lambda state, reason: events.append(state), bus=address, debounce=0.05)
        task = asyncio.create_task(monitor.run())
        try:
            async with asyncio.timeout(5):
                await monitor.ready.wait()
            assert monitor.state == NetworkState("none")  # nothing on the bus yet
            async with FakeService(address, [NM]) as fake:
                populate_nm(fake)
                await wait_for(events, 1)  # NameOwnerChanged -> re-read
                assert monitor.state.source == "networkmanager"
            await wait_for(events, 2)  # NetworkManager left the bus
            assert monitor.state == NetworkState("none")
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    with private_bus() as address:
        run(scenario(address))


def test_monitor_retries_without_a_bus():
    async def scenario():
        monitor = NetworkMonitor(bus="unix:path=/nonexistent/blockads-test-bus", retry=0.05)
        task = asyncio.create_task(monitor.run())
        async with asyncio.timeout(2):
            await monitor.ready.wait()  # ready (with the empty state) even without a bus
        assert monitor.state == NetworkState("none")
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)

    run(scenario())


def test_resolved_dns_over_tls_mode():
    data = resolved_data()
    key = next(k for k in data["get_all"] if k.endswith(netmon.RESOLVED_IFACE))
    assert state_of(data).resolved_dot == ""  # property missing (old resolved)
    data["get_all"][key] = {**data["get_all"][key], "DNSOverTLS": "yes"}
    assert state_of(data).resolved_dot == "yes"
    data["get_all"][key]["DNSOverTLS"] = "bogus"
    assert state_of(data).resolved_dot == ""


# --- Wi-Fi access point (trusted networks pinned to a BSSID) ----------------------


def wifi_data(bssid, kind="802-11-wireless"):
    data = nm_data(active=[(kind, True, "wlan0", False)])
    base = f"{NM} /org/freedesktop/NetworkManager"
    data["get_all"][f"{base}/Devices/1 {netmon.NM_WIRELESS_IFACE}"] = {
        "ActiveAccessPoint": "/org/freedesktop/NetworkManager/AccessPoint/7", "Bitrate": 300000}
    data["get_all"][f"{base}/AccessPoint/7 {netmon.NM_AP_IFACE}"] = {"HwAddress": bssid, "Strength": 70}
    return data


def test_primary_bssid():
    assert state_of(wifi_data("AA:BB:CC:DD:EE:01")).primary_bssid == "aa:bb:cc:dd:ee:01"
    assert state_of(wifi_data("00:00:00:00:00:00")).primary_bssid == ""  # NetworkManager's "unknown"
    assert state_of(wifi_data("garbage")).primary_bssid == ""
    assert state_of(wifi_data("aa:bb:cc:dd:ee:01", kind="802-3-ethernet")).primary_bssid == ""
    no_ap = wifi_data("aa:bb:cc:dd:ee:01")
    no_ap["get_all"][f"{NM} /org/freedesktop/NetworkManager/Devices/1 {netmon.NM_WIRELESS_IFACE}"] = {
        "ActiveAccessPoint": "/"}
    assert state_of(no_ap).primary_bssid == ""
    # Roaming to another access point is a state change.
    assert state_of(wifi_data("aa:bb:cc:dd:ee:01")) != state_of(wifi_data("aa:bb:cc:dd:ee:02"))


def test_reason_for_wireless_signals():
    from types import SimpleNamespace

    from jeepney.low_level import HeaderFields

    def signal(interface, changed):
        return SimpleNamespace(header=SimpleNamespace(fields={HeaderFields.member: "PropertiesChanged"}),
                               body=(interface, changed, []))

    assert netmon._reason(signal(netmon.NM_WIRELESS_IFACE, {"ActiveAccessPoint": ("o", "/x")})) == "network"
    assert netmon._reason(signal(netmon.NM_WIRELESS_IFACE, {"Bitrate": ("u", 1)})) is None
    assert netmon._reason(signal(netmon.NM_AP_IFACE, {"Strength": ("y", 1)})) is None
