"""Tests for filters.parser.

The first table is copied verbatim from upstream
tunnel/internal/trie/compiler_test.go (TestParseDomainLine, rev fc95d66a):
parity with blockads-android is the contract.
"""

import io
import ipaddress
import random

import pytest

from blockads_linux.filters.parser import (
    ListRule,
    RuleKind,
    go_fields,
    go_to_lower,
    go_trim_space,
    iter_binary_lines,
    iter_list_rules,
    parse_domain_line,
    parse_list_line,
)

UPSTREAM_CASES = [
    # Adblock-style network rules
    ("||ads.example.com^", "ads.example.com"),
    ("||Ads.Example.COM^", "ads.example.com"),
    ("||ads.example.com", "ads.example.com"),
    ("||ads.example.com^|", "ads.example.com"),
    ("||ads.example.com/path", ""),
    ("||ads.example.com^?x", ""),
    ("||*.example.com^", "example.com"),
    ("||ads.example.com^$important", "ads.example.com"),
    ("||ads.example.com^$all", "ads.example.com"),
    # Scoped rules with $domain= or $third-party are rejected
    ("||ads.example.com^$third-party", ""),
    ("||ads.example.com^$domain=foo.com", ""),
    ("||ads.example.com$third-party", ""),
    ("@@||ads.example.com^", ""),
    ("@@ads.example.com", ""),
    # Hosts-file lines
    ("0.0.0.0 ads.example.com", "ads.example.com"),
    ("127.0.0.1 ads.example.com", "ads.example.com"),
    ("0.0.0.0  ads.example.com", "ads.example.com"),
    ("0.0.0.0 ads.example.com # tracker", "ads.example.com"),
    ("0.0.0.0 ads.example.com#tracker", "ads.example.com"),
    ("0.0.0.0 ADS.Example.com", "ads.example.com"),
    ("0.0.0.0\tads.example.com", ""),  # tab separator isn't recognized
    ("::1 ads.example.com", ""),  # IPv6 sinks aren't recognized
    ("0.0.0.0 localhost", ""),
    ("127.0.0.1 localhost", ""),
    ("0.0.0.0 localhost.localdomain", ""),
    ("0.0.0.0 local", ""),
    ("0.0.0.0 broadcasthost", ""),
    ("0.0.0.0 0.0.0.0", ""),
    ("0.0.0.0", ""),
    # Plain domain lists and wildcards
    ("ads.example.com", "ads.example.com"),
    ("  ads.example.com  ", "ads.example.com"),
    ("ADS.EXAMPLE.COM", "ads.example.com"),
    ("*.example.com", "example.com"),
    ("*.telemetry.001-studio.com", "telemetry.001-studio.com"),
    ("*.0-02.net", "0-02.net"),
    ("ads.example.com # tracker", ""),  # inline comments only work on hosts lines
    ("localhost", ""),
    ("example", ""),
    ("1.2.3.4", ""),
    ("2001:db8::1", ""),
    # Trailing/leading dots are invalid hostname labels
    ("ads.example.com.", ""),
    ("0.0.0.0 ads.example.com.", ""),
    (".example.com", ""),
    # dnsmasq format
    ("server=/adikteev.com/", "adikteev.com"),
    ("address=/beacon.krxd.net/0.0.0.0", "beacon.krxd.net"),
    # TLD wildcard rules (e.g. from spam-tlds.txt)
    ("||*.actor^", "actor"),
    ("||*.africa^$denyallow=nation.africa", "africa"),
    # Comments and cosmetic rules
    ("", ""),
    ("# comment", ""),
    ("! comment", ""),
    ("##.ad-banner", ""),
    ("example.com##.ad", ""),
    ("$removeparam=pjclid", ""),
]


@pytest.mark.parametrize(("line", "want"), UPSTREAM_CASES)
def test_parse_domain_line_matches_upstream(line, want):
    assert parse_domain_line(line) == want


@pytest.mark.parametrize(
    ("line", "want"),
    [
        # Go-semantics details that Python built-ins would get wrong.
        ("　ads.example.com ", "ads.example.com"),  # unicode.IsSpace trimmed
        ("ads.example.com\x1c", ""),  # \x1c is whitespace in Python, not in Go
        ("||İnstagram.com^", "instagram.com"),  # Go simple case mapping: U+0130 -> "i"
        ("||Kelvin.example^", "kelvin.example"),  # KELVIN SIGN lowercases to "k"
        ("0.0.0.0 a.example b.example", "a.example"),  # strings.Fields splits on EM SPACE
        # Option handling details.
        ("||a.example^$important,dnstype=AAAA", "a.example"),
        ("||a.example^$ctag=device_pc|device_mac", "a.example"),
        ("||a.example^$badfilter", ""),
        ("||a.example^$dnsrewrite=1.2.3.4", ""),
        ("||a.example^$removeparam=/x/", ""),  # '/' rejected before options are read
        ("||a.example^$,", "a.example"),  # empty options are allowed
        # IP literal handling.
        ("010.1.1.1", "010.1.1.1"),  # leading zeros: not an IP for Go >= 1.17
        ("1.2.3", "1.2.3"),
        ("0.0.0.0 256.1.1.1", "256.1.1.1"),
        # dnsmasq without the closing slash keeps the raw line (then rejected).
        ("server=/example.com", ""),
        # Labels.
        ("_dmarc.example.com", ""),  # leading underscore
        ("a_b.example.com", "a_b.example.com"),
        ("xn--bcher-kva.example", "xn--bcher-kva.example"),
        ("bücher.example", ""),  # non-ASCII is rejected, punycode is not
    ],
)
def test_go_semantics_edge_cases(line, want):
    assert parse_domain_line(line) == want


def test_go_helpers():
    assert go_trim_space("\t\n x \v\f\r") == "x"
    assert go_trim_space("\x1cx\x1c") == "\x1cx\x1c"
    assert go_to_lower("ABCİ") == "abci"
    assert go_fields("  a \t b　c  ") == ["a", "b", "c"]
    assert go_fields("   ") == []


@pytest.mark.parametrize(
    ("line", "rule"),
    [
        ("||ads.example^", ListRule(RuleKind.BLOCK, "ads.example")),
        ("||ads.example^$important", ListRule(RuleKind.BLOCK, "ads.example", important=True)),
        ("@@||allowed.example^", ListRule(RuleKind.EXCEPTION, "allowed.example")),
        ("@@allowed.example", ListRule(RuleKind.EXCEPTION, "allowed.example")),
        ("@@||allowed.example^$important", ListRule(RuleKind.EXCEPTION, "allowed.example")),
        ("@@||allowed.example^$third-party", None),  # scoped: not a DNS exception
        ("@@||allowed.example/path", None),
        ("@@@@x.example", None),
        ("  @@||Allowed.Example^  ", ListRule(RuleKind.EXCEPTION, "allowed.example")),
        ("example.com##.ad", None),
        ("! comment", None),
    ],
)
def test_parse_list_line(line, rule):
    assert parse_list_line(line) == rule


def test_upstream_round_trip_list():
    """Upstream TestCompileLoadRoundTrip: 5 unique domains (+ our exception)."""
    lines = [
        "! Title: test list",
        "# hosts section",
        "0.0.0.0 tracker.example.com",
        "127.0.0.1 localhost",
        "||ads.example.org^",
        "||ADS.example.org^",  # duplicate after lowercasing
        "@@||allowed.example.net^",
        "metrics.example.net",
        "*.wild.example.io",
        "server=/dnsmasq.example.dev/",
        "",
    ]
    rules = list(iter_list_rules(lines))
    blocks = {r.domain for r in rules if r.kind is RuleKind.BLOCK}
    exceptions = {r.domain for r in rules if r.kind is RuleKind.EXCEPTION}
    assert blocks == {
        "tracker.example.com",
        "ads.example.org",
        "metrics.example.net",
        "wild.example.io",
        "dnsmasq.example.dev",
    }
    assert exceptions == {"allowed.example.net"}


def test_upstream_cosmetic_only_lines_yield_one_domain():
    """Upstream TestCompileFilterListSidecarsAndCosmeticOnly: 1 DNS domain."""
    lines = [
        "||ads.example.com^",
        "##.generic-banner",
        "vnexpress.net##.top-ad",
        "example.com##+js(set-constant, ads, false)",
        "||service.hotstar.com^*/preroll?",
        "/pagead.js$script",
    ]
    assert [r.domain for r in iter_list_rules(lines)] == ["ads.example.com"]


def test_iter_binary_lines_streams_crlf_and_invalid_utf8():
    data = b"||a.example^\r\n0.0.0.0 b.example\n\xff\xfe.example\nc.example"
    lines = list(iter_binary_lines(io.BytesIO(data)))
    assert lines[0] == "||a.example^"
    assert "�" in lines[2]
    domains = [r.domain for r in iter_list_rules(lines)]
    assert domains == ["a.example", "b.example", "c.example"]


def test_long_lines_are_skipped():
    assert parse_list_line("a" * (1024 * 1024 + 1) + ".example") is None


def test_fuzz_invariants():
    """Port of upstream FuzzParseDomainLine invariants, with a fixed seed."""
    rng = random.Random(1234)
    alphabet = "abcXYZ019.-_*|^$@#!/ \t:,=~İ　\x1c"
    seeds = ["||ads.example.com^", "0.0.0.0 ads.example.com # c", "*.x.com", "@@||a.b^", "::1 a.b", "1.2.3.4"]
    samples = seeds + ["".join(rng.choice(alphabet) for _ in range(rng.randint(0, 24))) for _ in range(20000)]
    for line in samples:
        domain = parse_domain_line(line)
        if not domain:
            continue
        assert domain == domain.strip()
        assert domain.isascii() and domain == domain.lower()
        with pytest.raises(ValueError):
            ipaddress.ip_address(domain)
