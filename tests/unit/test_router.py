"""Tests for daemon.router (tier 1: per-domain routes to the network's DNS)."""

from pathlib import Path

from blockads_linux.daemon.netmon import LinkDns, NetworkState
from blockads_linux.daemon.router import LOCAL_REVERSE_ZONES, Router
from blockads_linux.daemon.upstream.presets import UpstreamSpec

LOCAL = {"127.0.0.53", "192.168.1.50"}  # resolved's stub, and "our own" LAN address


def udp(*addresses):
    return tuple(UpstreamSpec("udp", a, 53) for a in addresses)


def router(*links, source="networkmanager", resolv_conf=None, tmp_path=None):
    state = NetworkState(source, links=tuple(links))
    kwargs = {"is_local": lambda address: address.split("%")[0] in LOCAL}
    if resolv_conf is not None:
        path = tmp_path / "resolv.conf"
        path.write_text(resolv_conf)
        kwargs["resolv_conf"] = path
    else:
        kwargs["resolv_conf"] = Path("/nonexistent/resolv.conf")
    return Router.from_state(state, **kwargs)


ETH = LinkDns("eth0", ("192.168.1.1", "fe80::1%eth0"), search=("lan",), default_route=True, priority=100)
SPLIT_VPN = LinkDns("tun0", ("10.8.0.1",), search=("corp.example",), routes=("corp.example", "10.in-addr.arpa"),
                    default_route=False, vpn=True, priority=50)


def test_home_network():
    r = router(ETH)
    assert r.network == udp("192.168.1.1", "fe80::1%eth0")
    assert r.vpn == ()
    for name in ("printer.lan", "nas.home.arpa", "box.local", "svc.internal", "nas",
                 "1.1.168.192.in-addr.arpa", "4.3.2.1.20.172.in-addr.arpa", "1.0.64.100.in-addr.arpa",
                 "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa"):
        route = r.route(name)
        assert route is not None and route.servers == r.network, name
    for name in ("example.com", "lan.example.com", "1.1.1.1.in-addr.arpa", "1.32.172.in-addr.arpa",
                 "1.0.0.128.100.in-addr.arpa", ""):
        assert r.route(name) is None, name


def test_vpn_split_dns_wins_over_the_lan():
    r = router(SPLIT_VPN, ETH)
    route = r.route("git.corp.example")
    assert route.servers == udp("10.8.0.1") and route.vpn and route.interface == "tun0"
    assert r.route("corp.example").servers == udp("10.8.0.1")
    assert r.route("5.4.3.10.in-addr.arpa").servers == udp("10.8.0.1")  # the VPN claimed 10/8 reverse
    assert r.route("printer.lan").servers == r.network
    assert r.route("example.com") is None
    assert r.vpn == ()  # split tunnel: no default DNS route
    assert r.network == udp("192.168.1.1", "fe80::1%eth0")


def test_longest_domain_wins():
    a = LinkDns("tun0", ("10.8.0.1",), routes=("example.com",), default_route=False, vpn=True)
    b = LinkDns("tun1", ("10.9.0.1",), routes=("eu.example.com",), default_route=False, vpn=True)
    r = router(a, b, ETH)
    assert r.route("x.eu.example.com").interface == "tun1"
    assert r.route("eu.example.com").interface == "tun1"
    assert r.route("us.example.com").interface == "tun0"
    assert r.route("notexample.com") is None


def test_shared_domain_merges_servers_vpn_first():
    lan = LinkDns("eth0", ("192.168.1.1",), search=("corp.example",), default_route=True, priority=100)
    vpn = LinkDns("tun0", ("10.8.0.1",), routes=("corp.example",), default_route=False, vpn=True, priority=50)
    r = router(lan, vpn)
    route = r.route("corp.example")
    assert route.servers == udp("10.8.0.1", "192.168.1.1") and route.vpn


def test_full_tunnel_vpn_keeps_local_names_inside():
    vpn = LinkDns("wg0", ("10.2.0.1",), routes=("",), default_route=True, vpn=True, priority=-50)
    wlan = LinkDns("wlan0", ("192.168.0.1",), default_route=False, priority=600)
    r = router(vpn, wlan)
    assert r.vpn == udp("10.2.0.1")
    assert r.network == udp("192.168.0.1")  # still the LAN, for a captive portal
    assert r.route("printer.lan").servers == udp("10.2.0.1")
    assert r.route("nas").servers == udp("10.2.0.1")
    assert r.route("example.com") is None


def test_local_servers_are_never_used():
    stub = LinkDns("eth0", ("127.0.0.53", "192.168.1.50"), search=("lan",), default_route=True)
    r = router(stub)
    assert r.network == () and r.local == ()
    assert r.route("printer.lan") is None and r.route("nas") is None
    mixed = LinkDns("eth0", ("127.0.0.53", "192.168.1.1"), default_route=True)
    assert router(mixed).network == udp("192.168.1.1")


def test_no_default_route_uses_every_plain_link():
    a = LinkDns("eth0", ("192.168.1.1",), default_route=False)
    b = LinkDns("eth1", ("192.168.2.1",), default_route=False)
    assert router(a, b).network == udp("192.168.1.1", "192.168.2.1")


def test_resolv_conf_without_a_network_manager(tmp_path):
    r = router(source="none", resolv_conf="nameserver 127.0.0.53\nnameserver 192.168.7.1\n", tmp_path=tmp_path)
    assert r.network == udp("192.168.7.1")
    assert r.route("printer.lan").servers == udp("192.168.7.1")


def test_at_most_three_servers():
    link = LinkDns("eth0", tuple(f"192.168.1.{i}" for i in range(1, 6)), search=("lan",), default_route=True)
    r = router(link)
    assert len(r.network) == 3 and len(r.route("x.lan").servers) == 3


def test_reverse_zones():
    assert len(LOCAL_REVERSE_ZONES) == len(set(LOCAL_REVERSE_ZONES)) == 3 + 16 + 64 + 2 + 4
    assert "31.172.in-addr.arpa" in LOCAL_REVERSE_ZONES and "15.172.in-addr.arpa" not in LOCAL_REVERSE_ZONES
    assert "127.100.in-addr.arpa" in LOCAL_REVERSE_ZONES and "128.100.in-addr.arpa" not in LOCAL_REVERSE_ZONES


def test_empty_router():
    r = Router()
    assert r.route("nas") is None and r.route("x.lan") is None
