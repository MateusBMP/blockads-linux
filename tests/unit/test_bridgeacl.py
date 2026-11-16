"""Tests for daemon.bridgeacl and the server's guarded (bridge) listeners."""

import asyncio
import json

import dns.message

from blockads_linux.daemon.bridgeacl import (
    BridgeAcl,
    ipv4_subnets,
    ipv6_subnets,
    match_interface,
    read_bridge_patterns,
)
from blockads_linux.daemon.health import self_targets
from blockads_linux.daemon.pipeline import Pipeline
from blockads_linux.daemon.server import DnsServer

from .fakes import FakeResolver
from .test_server import bind_free, tcp_ask, udp_ask

ROUTE = """\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
wlan0\t00000000\t0100A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0
wlan0\t0000A8C0\t00000000\t0001\t0\t0\t600\t00FFFFFF\t0\t0\t0
docker0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0
br-1a2b\t000012AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0
virbr0\t007AA8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0
docker0\t0A0B0C0D\t01000A0A\t0003\t0\t0\t0\t00FFFFFF\t0\t0\t0
docker1\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0
garbage
"""
# 172.17.0.0/16 docker0, 172.18.0.0/16 br-1a2b, 192.168.122.0/24 virbr0;
# a gatewayed route and a /0 on bridges are never trusted.

IF_INET6 = """\
00000000000000000000000000000001 01 80 10 80       lo
fe80000000000000afea36dded18555a 03 40 20 80    wlan0
fe800000000000000000000000000001 04 40 20 80  docker0
fd00000000000000000000000000dc01 04 40 00 80  docker0
20010db8000000010000000000000001 05 30 00 80   wlan0
20010db8000000020000000000000001 06 00 00 80  docker0
"""


def write_state(path, status="on", interfaces=("docker0", "br-+"), applied=True):
    path.write_text(json.dumps({"applied": applied, "families": {"ipv4": {"status": "active"}},
                                "bridge": {"status": status, "interfaces": list(interfaces)}}))


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def make_acl(tmp_path, patterns=("docker0", "br-+"), clock=None):
    route = tmp_path / "route"
    inet6 = tmp_path / "if_inet6"
    route.write_text(ROUTE)
    inet6.write_text(IF_INET6)
    current = {"patterns": tuple(patterns)}
    acl = BridgeAcl(patterns=lambda: current["patterns"], route_path=route, if_inet6_path=inet6,
                    clock=clock or Clock())
    return acl, current, route


def test_match_interface_uses_iptables_wildcards():
    assert match_interface("docker0", ["docker0"])
    assert not match_interface("docker01", ["docker0"])
    assert match_interface("br-1a2b", ["br-+"])
    assert match_interface("br-", ["br-+"])
    assert not match_interface("virbr0", ["br-+"])
    assert not match_interface("eth0", [])


def test_ipv4_subnets_keep_only_connected_routes():
    found = {(name, str(net)) for name, net in ipv4_subnets(ROUTE)}
    assert found == {("wlan0", "192.168.0.0/24"), ("docker0", "172.17.0.0/16"),
                     ("br-1a2b", "172.18.0.0/16"), ("virbr0", "192.168.122.0/24")}


def test_ipv6_subnets_skip_link_and_host_scope():
    found = {(name, str(net)) for name, net in ipv6_subnets(IF_INET6)}
    assert found == {("docker0", "fd00::/64"), ("wlan0", "2001:db8::/48")}  # /0 is never trusted


def test_patterns_come_from_the_applied_state(tmp_path):
    path = tmp_path / "state.json"
    assert read_bridge_patterns(path) == ()  # missing: fail closed
    write_state(path)
    assert read_bridge_patterns(path) == ("docker0", "br-+")
    write_state(path, status="off")
    assert read_bridge_patterns(path) == ()
    write_state(path, applied=False)
    assert read_bridge_patterns(path) == ()
    write_state(path, interfaces=("lo", "lo+", "+", "", 7, "virbr+"))
    assert read_bridge_patterns(path) == ("virbr+",)
    path.write_text("{not json")
    assert read_bridge_patterns(path) == ()
    path.write_text("[]")
    assert read_bridge_patterns(path) == ()


def test_allows_only_sources_inside_matching_bridges(tmp_path):
    acl, _, _ = make_acl(tmp_path)
    assert acl.allows("172.17.0.2")
    assert acl.allows("172.18.5.9")
    assert acl.allows("fd00::42")
    assert acl.allows("::ffff:172.17.0.3")  # v4-mapped
    assert not acl.allows("192.168.0.20")  # LAN
    assert not acl.allows("192.168.122.10")  # virbr0 not configured
    assert not acl.allows("2001:db8::5")
    assert not acl.allows("fe80::1%docker0")  # link-local never trusted
    assert not acl.allows("127.0.0.1")
    assert not acl.allows("::1")
    assert not acl.allows("not an address")
    assert acl.interfaces == ("br-1a2b", "docker0")
    assert acl.stats.allowed == 4 and acl.stats.denied == 7


def test_summary_reports_coverage_and_counts(tmp_path):
    clock = Clock()
    acl, current, _ = make_acl(tmp_path, clock=clock)
    assert acl.summary() == {"patterns": ["docker0", "br-+"], "interfaces": ["br-1a2b", "docker0"],
                             "subnets": len(acl.networks), "allowed": 0, "denied": 0}
    acl.allows("172.17.0.2")
    acl.allows("192.168.0.20")
    current["patterns"] = ()  # redirect turned off: seen once the snapshot is stale
    assert acl.summary()["allowed"] == 1 and acl.summary()["denied"] == 1
    assert acl.summary()["patterns"] == ["docker0", "br-+"]
    clock.now += acl.max_age
    assert acl.summary()["patterns"] == [] and acl.summary()["interfaces"] == []


def test_no_patterns_denies_everything(tmp_path):
    acl, _, _ = make_acl(tmp_path, patterns=())
    assert not acl.allows("172.17.0.2")
    assert acl.networks == ()


def test_unknown_source_refresh_is_rate_limited(tmp_path):
    clock = Clock()
    acl, current, route = make_acl(tmp_path, patterns=("docker0",), clock=clock)
    assert not acl.allows("172.18.0.2")
    refreshes = acl.stats.refreshes
    current["patterns"] = ("docker0", "br-+")  # a new bridge appears
    clock.now += 0.5
    assert not acl.allows("172.18.0.2")  # too soon: no refresh
    assert acl.stats.refreshes == refreshes
    clock.now += 2.0
    assert acl.allows("172.18.0.2")
    assert acl.stats.refreshes == refreshes + 1


def test_state_change_refreshes_at_once(tmp_path):
    """The daemon starts before blockads-fw apply writes state.json (found in VM testing)."""
    from blockads_linux.daemon.bridgeacl import file_signature, read_bridge_patterns

    state = tmp_path / "state.json"
    route = tmp_path / "route"
    route.write_text(ROUTE)
    clock = Clock()
    acl = BridgeAcl(patterns=lambda: read_bridge_patterns(state), state_signature=lambda: file_signature(state),
                    route_path=route, if_inet6_path=tmp_path / "none", clock=clock)
    acl.refresh()  # at start: no state yet -> fail closed
    assert not acl.allows("172.17.0.2")
    clock.now += 0.5  # well inside min_refresh
    write_state(state)
    assert acl.allows("172.17.0.2")
    refreshes = acl.stats.refreshes
    clock.now += 0.1
    assert not acl.allows("203.0.113.9")  # unchanged state: still rate-limited
    assert acl.stats.refreshes == refreshes


def test_known_source_is_rechecked_after_max_age(tmp_path):
    clock = Clock()
    acl, current, route = make_acl(tmp_path, clock=clock)
    assert acl.allows("172.17.0.2")
    route.write_text(ROUTE.replace("docker0\t000011AC", "gone0\t000011AC"))  # docker0 removed
    clock.now += 10
    assert acl.allows("172.17.0.2")  # snapshot still fresh
    clock.now += 30
    assert not acl.allows("172.17.0.2")


def test_unreadable_proc_files_deny(tmp_path):
    acl = BridgeAcl(patterns=lambda: ("docker0",), route_path=tmp_path / "missing",
                    if_inet6_path=tmp_path / "missing6", clock=Clock())
    assert not acl.allows("172.17.0.2")


# --- server integration -----------------------------------------------------


def query_wire():
    return dns.message.make_query("example.com", "A").to_wire()


def run(coro):
    return asyncio.run(coro)


def test_guarded_listener_drops_denied_sources_silently():
    async def main():
        server = DnsServer(Pipeline(FakeResolver()))
        open_socks = bind_free()
        guarded_socks = bind_free()
        decisions = []

        def deny(host):
            decisions.append(host)
            return False

        await server.start(open_socks)
        await server.start(guarded_socks, acl=deny)
        try:
            open_port = open_socks[0].getsockname()[1]
            guarded_port = guarded_socks[0].getsockname()[1]
            assert await udp_ask(open_port, query_wire()) is not None
            assert await udp_ask(guarded_port, query_wire(), timeout=0.3) is None
            try:
                replies = await tcp_ask(guarded_port, query_wire(), timeout=0.5)
            except (ConnectionError, OSError, asyncio.IncompleteReadError):
                replies = None
            assert not replies
            assert server.stats.acl_dropped == 2
            assert decisions == ["127.0.0.1", "127.0.0.1"]
            # The watchdog never probes the guarded listener (it would be denied).
            targets = self_targets(server.probe_addresses)
            assert targets == [("127.0.0.1", open_port)]
            assert len(server.addresses) == 4
        finally:
            await server.close()

    run(main())


def test_guarded_listener_answers_allowed_sources_and_fails_closed():
    async def main():
        server = DnsServer(Pipeline(FakeResolver()))
        allowed = bind_free()
        broken = bind_free()

        def boom(host):
            raise RuntimeError("bug")

        await server.start(allowed, acl=lambda host: host == "127.0.0.1")
        await server.start(broken, acl=boom)
        try:
            port = allowed[0].getsockname()[1]
            assert await udp_ask(port, query_wire()) is not None
            assert await tcp_ask(port, query_wire())
            assert await udp_ask(broken[0].getsockname()[1], query_wire(), timeout=0.3) is None
            assert server.stats.acl_dropped == 1
        finally:
            await server.close()

    run(main())
