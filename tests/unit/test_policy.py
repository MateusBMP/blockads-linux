"""Tests for daemon.upstream.policy (tier selection per question and network state)."""

import asyncio
from pathlib import Path

import dns.message
import dns.rdatatype
import pytest

from blockads_linux.daemon.netmon import Connectivity, LinkDns, NetworkState
from blockads_linux.daemon.resolver import Forwarder
from blockads_linux.daemon.upstream.base import CertificateTimeError, Question, UpstreamError
from blockads_linux.daemon.upstream.policy import PolicyConfig, UpstreamPolicy
from blockads_linux.daemon.upstream.presets import PRESETS, UpstreamSpec

DOH = PRESETS["quad9"].specs("https")
PLAIN = PRESETS["quad9"].specs("udp")
NO_RESOLV = Path("/nonexistent/resolv.conf")


class FakeUpstream:
    def __init__(self, spec):
        self.spec = spec
        self.label = spec.label
        self.encrypted = spec.encrypted
        self.closed = False
        self.error = None
        self.asked = []

    async def exchange(self, question):
        self.asked.append(question.name)
        if self.error is not None:
            raise self.error
        reply = dns.message.make_response(question.to_message(1))
        return reply

    async def close(self):
        self.closed = True


def udp(address):
    return UpstreamSpec("udp", address, 53)


ETH = LinkDns("eth0", ("192.168.1.1",), search=("lan",), default_route=True, priority=100)
SPLIT = LinkDns("tun0", ("10.8.0.1",), routes=("corp.example",), default_route=False, vpn=True, priority=50)
FULL = LinkDns("wg0", ("10.2.0.1",), routes=("",), default_route=True, vpn=True, priority=-50)
WLAN = LinkDns("wlan0", ("192.168.0.1",), default_route=False, priority=600)


def state(*links, connectivity=Connectivity.FULL):
    return NetworkState("networkmanager", connectivity=connectivity, links=tuple(links))


def policy(state_=None, **config):
    config.setdefault("configured", DOH)
    config.setdefault("fallback", () if config.get("encrypted_only") else PLAIN)
    return UpstreamPolicy(PolicyConfig(**config), state_, build=FakeUpstream, resolv_conf=NO_RESOLV,
                          is_local=lambda address: address.startswith("127."))


def plan(p, name="example.com"):
    tiers, rescue = p.select(Question.make(name, dns.rdatatype.A))
    return ([(t.name, [u.spec.address for u in t.upstreams]) for t in tiers],
            [(t.name, [u.spec.address for u in t.upstreams]) for t in rescue])


DOH_IPS = [s.address for s in DOH]
PLAIN_IPS = [s.address for s in PLAIN]


def test_home_network_tiers():
    p = policy(state(ETH))
    assert plan(p) == ([("configured", DOH_IPS), ("fallback", PLAIN_IPS), ("network", ["192.168.1.1"])], [])
    assert plan(p, "printer.lan") == ([("route", ["192.168.1.1"])], [])
    assert plan(p, "nas") == ([("route", ["192.168.1.1"])], [])


def test_split_vpn_routes_only_its_domains():
    p = policy(state(SPLIT, ETH))
    assert plan(p, "git.corp.example") == ([("route", ["10.8.0.1"])], [])
    assert plan(p)[0][0] == ("configured", DOH_IPS)  # no VPN tier: it does not own the default route


def test_full_tunnel_vpn_tier():
    p = policy(state(FULL, WLAN))
    assert plan(p)[0] == [("vpn", ["10.2.0.1"]), ("configured", DOH_IPS), ("fallback", PLAIN_IPS),
                          ("network", ["192.168.0.1"])]
    assert plan(policy(state(FULL, WLAN), vpn_dns=False))[0][0] == ("configured", DOH_IPS)


def test_captive_portal_puts_network_dns_first():
    p = policy(state(ETH, connectivity=Connectivity.PORTAL))
    assert plan(p)[0] == [("captive", ["192.168.1.1"]), ("configured", DOH_IPS), ("fallback", PLAIN_IPS)]
    assert p.summary()["captive"]


def test_encrypted_only():
    p = policy(state(ETH, connectivity=Connectivity.PORTAL), encrypted_only=True, rescue=PLAIN)
    assert plan(p) == ([("configured", DOH_IPS)], [("ntp-rescue", PLAIN_IPS + ["192.168.1.1"])])
    assert plan(p, "printer.lan") == ([("route", ["192.168.1.1"])], [])  # tier 1 stays
    full = policy(state(FULL, WLAN), encrypted_only=True, rescue=PLAIN)
    assert plan(full)[0] == [("vpn", ["10.2.0.1"]), ("configured", DOH_IPS)]  # tier 3 stays
    summary = p.summary()
    assert summary["encrypted_only"] and not summary["captive"]
    assert summary["tiers"] == [{"name": "configured", "upstreams": [s.label for s in DOH], "encrypted": True}]


def test_system_preset_uses_the_network_dns():
    p = policy(state(ETH), configured=(), system=True, fallback=())
    assert plan(p) == ([("configured", ["192.168.1.1"])], [])
    offline = policy(state(), configured=(), system=True, fallback=())
    assert plan(offline) == ([], [])


def test_config_validation():
    with pytest.raises(ValueError):
        PolicyConfig()
    with pytest.raises(ValueError):
        PolicyConfig(configured=PLAIN, encrypted_only=True)
    with pytest.raises(ValueError):
        PolicyConfig(system=True, encrypted_only=True)


def test_duplicate_servers_are_tried_once():
    lan_is_quad9 = LinkDns("eth0", (PLAIN[0].address,), default_route=True)
    p = policy(state(lan_is_quad9))
    assert plan(p)[0] == [("configured", DOH_IPS), ("fallback", PLAIN_IPS)]


def test_apply_reuses_and_releases_transports():
    p = policy(state(ETH))
    lan = p.tiers[-1].upstreams[0]
    configured = p.tiers[0].upstreams[0]
    route = p.select(Question.make("printer.lan", dns.rdatatype.A))[0][0].upstreams[0]
    assert route is lan  # one transport per server
    assert p.apply(state(ETH)) == []
    assert p.tiers[-1].upstreams[0] is lan and p.tiers[0].upstreams[0] is configured
    stale = p.apply(state(WLAN))
    assert stale == [lan]
    assert configured in p.upstreams() and lan not in p.upstreams()


def test_forwarder_uses_the_policy():
    async def scenario():
        p = policy(state(SPLIT, ETH))
        forwarder = Forwarder(policy=p)
        await forwarder.resolve(Question.make("git.corp.example", dns.rdatatype.A))
        assert forwarder.active.tier == "route" and not forwarder.active.encrypted
        vpn = p.select(Question.make("git.corp.example", dns.rdatatype.A))[0][0].upstreams[0]
        assert vpn.asked == ["git.corp.example"]
        result = await forwarder.resolve(Question.make("example.com", dns.rdatatype.A))
        assert result.tier == "configured" and forwarder.active.encrypted
        # A routed name never falls through to the public tiers.
        vpn.error = UpstreamError("down")
        with pytest.raises(Exception):
            await forwarder.resolve(Question.make("other.corp.example", dns.rdatatype.A))
        assert all("other.corp.example" not in u.asked for u in p.tiers[0].upstreams)
        # Network change: stale transports are forgotten and closed.
        stale = p.apply(state(ETH))
        forwarder.forget(stale)
        await forwarder.reset()
        assert vpn in stale and all(u.closed for u in p.upstreams())
        assert all(h.label != vpn.label for h in forwarder.health)

    asyncio.run(scenario())


def test_clock_rescue_through_the_policy():
    async def scenario():
        p = policy(state(ETH), encrypted_only=True, rescue=PLAIN)
        for upstream in p.tiers[0].upstreams:
            upstream.error = CertificateTimeError("certificate is not yet valid")
        forwarder = Forwarder(policy=p, ntp_names=lambda name: name == "pool.ntp.org")
        result = await forwarder.resolve(Question.make("pool.ntp.org", dns.rdatatype.A))
        assert result.tier == "ntp-rescue"
        with pytest.raises(Exception):
            await forwarder.resolve(Question.make("example.com", dns.rdatatype.A))

    asyncio.run(scenario())


# --- trusted networks ---------------------------------------------------------

HOME = "11111111-2222-4333-8444-555555555555"


def test_trusted_network_dns_comes_first():
    trusted = NetworkState("networkmanager", connectivity=Connectivity.FULL, primary_uuid=HOME, links=(ETH,))
    p = policy(trusted, network_dns_uuids={HOME})
    assert p.trusted_dns
    assert [t.name for t in p.tiers] == ["trusted", "configured", "fallback"]
    assert [u.spec for u in p.tiers[0].upstreams] == [udp("192.168.1.1")]
    assert p.summary()["trusted_dns"] is True
    # Another connection: the normal tiers.
    other = NetworkState("networkmanager", connectivity=Connectivity.FULL, primary_uuid="other", links=(ETH,))
    p.apply(other)
    assert not p.trusted_dns and p.tiers[0].name == "configured"


def test_trusted_network_dns_yields_to_encrypted_only_and_vpn():
    trusted = NetworkState("networkmanager", connectivity=Connectivity.FULL, primary_uuid=HOME, links=(ETH,))
    p = policy(trusted, network_dns_uuids={HOME}, encrypted_only=True)
    assert not p.trusted_dns and p.tiers[0].name == "configured"
    # A full-tunnel VPN becomes the primary connection in NetworkManager; if it
    # does not, its DNS still comes right after the trusted network's.
    with_vpn = NetworkState("networkmanager", connectivity=Connectivity.FULL, primary_uuid=HOME, links=(ETH, FULL))
    p = policy(with_vpn, network_dns_uuids={HOME})
    assert [t.name for t in p.tiers][:2] == ["trusted", "vpn"]


def test_trusted_network_without_dns_servers():
    empty = NetworkState("networkmanager", connectivity=Connectivity.FULL, primary_uuid=HOME)
    p = policy(empty, network_dns_uuids={HOME})
    assert not p.trusted_dns and p.tiers[0].name == "configured"
