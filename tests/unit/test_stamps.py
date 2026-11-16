"""Tests for upstream.stamps and upstream.presets.

Stamp vectors ported from blockads-android ``tunnel/internal/dns/stamp_test.go``
(revision fc95d66a); the two real stamps come from ``DnsProvider.kt``.
"""

import pytest

from blockads_linux.daemon.upstream.doh import DohUpstream
from blockads_linux.daemon.upstream.dot import DotUpstream
from blockads_linux.daemon.upstream.plain import UdpUpstream
from blockads_linux.daemon.upstream.presets import PRESETS, UpstreamSpec, parse_upstream, stamp_to_spec
from blockads_linux.daemon.upstream.stamps import (
    PROP_DNSSEC,
    PROP_NO_LOG,
    Proto,
    Stamp,
    StampError,
    parse_stamp,
    split_host_port,
)
from blockads_linux.daemon.upstream.tcp import StreamUpstream

CLOUDFLARE_STAMP = "sdns://AgMAAAAAAAAABzEuMS4xLjEAEmNsb3VkZmxhcmUtZG5zLmNvbQovZG5zLXF1ZXJ5"
ADGUARD_DOQ_STAMP = "sdns://BAEAAAAAAAAADDk0LjE0MC4xNC4xNAATZG5zLmFkZ3VhcmQtZG5zLmNvbQ"


def test_round_trip_doh():
    stamp = Stamp(Proto.DOH, PROP_DNSSEC | PROP_NO_LOG, "1.1.1.1:443", provider_name="cloudflare-dns.com",
                  path="/dns-query")
    info = parse_stamp(stamp.to_string())
    assert info.proto == Proto.DOH and info.url == "https://cloudflare-dns.com/dns-query"
    assert info.dnssec and info.no_log and not info.no_filter
    assert info.address == "1.1.1.1" and info.port == 443


def test_round_trip_doq():
    stamp = Stamp(Proto.DOQ, PROP_DNSSEC, "94.140.14.14:853", provider_name="dns.adguard-dns.com")
    info = parse_stamp(stamp.to_string())
    assert info.proto == Proto.DOQ and info.url == "quic://dns.adguard-dns.com"


def test_round_trip_dot():
    stamp = Stamp(Proto.DOT, PROP_DNSSEC, "9.9.9.9:853", provider_name="dns.quad9.net")
    info = parse_stamp(stamp.to_string())
    assert info.proto == Proto.DOT and info.url == "dns.quad9.net" and info.port == 853


def test_round_trip_plain():
    info = parse_stamp(Stamp(Proto.PLAIN, server_addr="8.8.8.8").to_string())
    assert info.proto == Proto.PLAIN and info.address == "8.8.8.8" and info.port == 53


@pytest.mark.parametrize(
    "text",
    [
        "http://example.com",
        "sdns://invalidbase64!@#$",
        "sdns://AQID",  # too short
        "sdns://",
        "sdns://" + "A" * 5000,
        "sdns://AAAAAAAAAAAABzguOC44LjgAAA",  # plain stamp "8.8.8.8" + 2 trailing bytes
        "sdns://Bw",  # unknown protocol 0x07
        "sdns://AAAAAAAAAAAAB2V4YW1wbGU",  # plain stamp whose address is a name
    ],
)
def test_invalid_stamps(text):
    with pytest.raises(StampError):
        parse_stamp(text)


def test_real_cloudflare_stamp():
    stamp = parse_stamp(CLOUDFLARE_STAMP)
    assert stamp.proto == Proto.DOH and stamp.props == 3
    assert (stamp.address, stamp.hostname, stamp.path, stamp.hashes) == ("1.1.1.1", "cloudflare-dns.com", "/dns-query", ())
    assert stamp.to_string() == CLOUDFLARE_STAMP  # the encoder matches go-dnsstamps byte for byte


def test_real_adguard_doq_stamp():
    stamp = parse_stamp(ADGUARD_DOQ_STAMP)
    assert stamp.proto == Proto.DOQ and stamp.dnssec and stamp.address == "94.140.14.14"
    assert stamp.to_string() == ADGUARD_DOQ_STAMP
    with pytest.raises(StampError, match="DOQ"):
        stamp_to_spec(ADGUARD_DOQ_STAMP)


def test_hashes_bootstrap_and_ipv6():
    stamp = Stamp(Proto.DOH, 0, "[2606:4700::1111]:8443", (b"\x01" * 32, b"\x02" * 32), "doh.example:8443",
                  "/q", ("192.0.2.1", "[2001:db8::1]"))
    parsed = parse_stamp(stamp.to_string())
    assert parsed == stamp
    assert parsed.address == "2606:4700::1111" and parsed.port == 8443 and parsed.hostname == "doh.example"
    spec = stamp_to_spec(stamp.to_string())
    assert spec == UpstreamSpec("https", "2606:4700::1111", 8443, "doh.example", "/q")


def test_stamp_without_address_uses_bootstrap_ip():
    stamp = Stamp(Proto.DOT, 0, "", provider_name="dot.example", bootstrap_ips=("192.0.2.53",))
    assert stamp_to_spec(stamp.to_string()) == UpstreamSpec("tls", "192.0.2.53", 853, "dot.example")
    with pytest.raises(StampError, match="no server IP"):
        stamp_to_spec(Stamp(Proto.DOT, 0, "", provider_name="dot.example").to_string())


def test_split_host_port():
    assert split_host_port("1.2.3.4", 53) == ("1.2.3.4", 53)
    assert split_host_port("1.2.3.4:5353", 53) == ("1.2.3.4", 5353)
    assert split_host_port("[::1]:853", 53) == ("::1", 853)
    assert split_host_port("2001:db8::1", 53) == ("2001:db8::1", 53)
    for bad in ("1.2.3.4:x", "[::1", "1.2.3.4:70000", "[::1]x"):
        with pytest.raises(StampError):
            split_host_port(bad, 53)


# --- presets and specs -------------------------------------------------------


def test_default_preset_is_quad9_doh_with_two_ips():
    specs = PRESETS["quad9"].specs()
    assert [s.address for s in specs] == ["9.9.9.9", "149.112.112.112"]
    assert {(s.protocol, s.name, s.port, s.path) for s in specs} == {("https", "dns.quad9.net", 443, "/dns-query")}
    assert [s.label for s in specs] == ["https://dns.quad9.net/dns-query (9.9.9.9)",
                                    "https://dns.quad9.net/dns-query (149.112.112.112)"]
    assert [s.protocol for s in PRESETS["quad9"].specs("udp")] == ["udp", "udp"]
    with pytest.raises(ValueError, match="TLS"):
        PRESETS["opendns"].specs("tls")


def test_every_preset_is_well_formed():
    for preset in PRESETS.values():
        assert len(preset.specs()) == 2
        if preset.dot_name:
            assert len(preset.specs("tls")) == 2


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("udp://9.9.9.9", [UpstreamSpec("udp", "9.9.9.9", 53)]),
        ("udp://[2620:fe::fe]:5353", [UpstreamSpec("udp", "2620:fe::fe", 5353)]),
        ("tcp://192.0.2.1", [UpstreamSpec("tcp", "192.0.2.1", 53)]),
        ("tls://9.9.9.9#dns.quad9.net", [UpstreamSpec("tls", "9.9.9.9", 853, "dns.quad9.net")]),
        ("https://9.9.9.9/dns-query#dns.quad9.net", [UpstreamSpec("https", "9.9.9.9", 443, "dns.quad9.net", "/dns-query")]),
        (CLOUDFLARE_STAMP, [UpstreamSpec("https", "1.1.1.1", 443, "cloudflare-dns.com", "/dns-query")]),
    ],
)
def test_parse_upstream(text, expected):
    assert parse_upstream(text) == expected


@pytest.mark.parametrize(
    "text",
    ["https://dns.quad9.net/dns-query", "tls://9.9.9.9", "ftp://9.9.9.9", "udp://", "nonsense", "quad10"],
)
def test_parse_upstream_rejects(text):
    with pytest.raises(ValueError):
        parse_upstream(text)


def test_spec_validation_and_build():
    with pytest.raises(ValueError):
        UpstreamSpec("https", "9.9.9.9", 443)  # no TLS name
    with pytest.raises(ValueError):
        UpstreamSpec("udp", "dns.example", 53)  # not an IP
    assert isinstance(UpstreamSpec("udp", "9.9.9.9", 53).build(), UdpUpstream)
    assert type(UpstreamSpec("tcp", "9.9.9.9", 53).build()) is StreamUpstream
    assert isinstance(UpstreamSpec("tls", "9.9.9.9", 853, "dns.quad9.net").build(), DotUpstream)
    doh = UpstreamSpec("https", "9.9.9.9", 443, "dns.quad9.net", "/dns-query").build()
    assert isinstance(doh, DohUpstream) and doh.label == "https://dns.quad9.net/dns-query (9.9.9.9)"
    assert doh.encrypted
