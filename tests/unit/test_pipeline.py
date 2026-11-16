"""Tests for daemon.pipeline and daemon.safesearch.

Vectors ported from blockads-android (revision fc95d66a):
``tunnel/dns_server_test.go`` (TestServeDNSPipeline), ``tunnel/dns_order_test.go``
(TestDNSPathParity and the standalone side of TestDNSPathParityKnownDivergence)
and ``tunnel/internal/safesearch/safesearch_test.go``.
"""

import asyncio
import hashlib
import random

import dns.message
import dns.rcode
import dns.rdatatype
import pytest

from blockads_linux.daemon.pipeline import FIREFOX_CANARY, Pipeline, Policy, PreferredIP, Verdict
from blockads_linux.daemon.responses import BlockMode, InvalidQuery, parse_query, render
from blockads_linux.daemon.safesearch import safesearch_target, youtube_target
from blockads_linux.filters.artifact import ArtifactBuilder, LoadedArtifact
from blockads_linux.filters.custom_rules import CustomRuleSet, parse_rules
from blockads_linux.filters.matcher import FilterList, FilterMatcher
from blockads_linux.filters.parser import iter_list_rules

from .fakes import DEFAULT_A, DEFAULT_AAAA, FakeResolver

def build_list(tmp_path, list_id, rank, *lines):
    builder = ArtifactBuilder()
    builder.add_rules(iter_list_rules(lines))
    info = builder.write(tmp_path, source_sha256=hashlib.sha256(list_id.encode()).digest(), compiled_at=1)
    return FilterList(list_id, rank, LoadedArtifact.open(tmp_path / info.name))


@pytest.fixture
def lists(tmp_path):
    """Upstream's test tries: "ads" blocks ads.example.com, "malware" evil.example."""
    return FilterMatcher([
        build_list(tmp_path, "ads", 1, "||ads.example.com^", "cloak.trackerco.net"),
        build_list(tmp_path, "malware", 0, "evil.example"),
    ])


def custom(text="", whitelist=()):
    return CustomRuleSet.build(parse_rules(text), whitelist)


def ask(pipeline, name, rdtype="A", **query_kw):
    message = dns.message.make_query(name, rdtype, **query_kw)
    message.id = 0x1234
    query = parse_query(message.to_wire())
    reply, event = asyncio.run(pipeline.handle(query))
    # Every reply must render, and round-trip like a client would see it.
    wire = render(reply, query.udp_limit)
    return dns.message.from_wire(wire), event


def ips(reply):
    return ",".join(r.address for rrset in reply.answer if rrset.rdtype in (1, 28) for r in rrset)


def make(policy=None, **resolver_kw):
    return Pipeline(FakeResolver(**resolver_kw), policy or Policy())


# --- upstream TestServeDNSPipeline -------------------------------------------------


def test_forward():
    reply, event = ask(make(), "clean.example")
    assert reply.id == 0x1234 and reply.rcode() == dns.rcode.NOERROR and ips(reply) == DEFAULT_A
    assert event.verdict is Verdict.FORWARDED and event.reason == "" and event.upstream == "fake"
    assert event.answers == (DEFAULT_A,)


def test_doh_bootstrap_blocked():
    reply, event = ask(make(Policy(doh_blocklist=frozenset({"dns.google"}))), "dns.google")
    assert ips(reply) == "0.0.0.0"
    assert event.verdict is Verdict.BLOCKED and event.reason == "doh_bypass_protection"


def test_doh_blocklist_matches_parents_and_is_off_when_empty():
    _, event = ask(make(Policy(doh_blocklist=frozenset({"dns.google"}))), "x.dns.google")
    assert event.reason == "doh_bypass_protection"
    reply, event = ask(make(), "dns.google")
    assert ips(reply) == DEFAULT_A and event.verdict is Verdict.FORWARDED


def test_custom_block_aaaa():
    reply, event = ask(make(Policy(custom=custom("blocked.example"))), "blocked.example", "AAAA")
    assert ips(reply) == "::" and event.verdict is Verdict.BLOCKED and event.reason == "custom"


def test_custom_block_mx_is_nodata():
    reply, event = ask(make(Policy(custom=custom("blocked.example"))), "blocked.example", "MX")
    assert reply.rcode() == dns.rcode.NOERROR and not reply.answer
    assert reply.authority[0].rdtype == dns.rdatatype.SOA
    assert event.verdict is Verdict.BLOCKED and event.reason == "custom"


def test_custom_block_nxdomain_and_refused_modes():
    nx_policy = Policy(custom=custom("blocked.example"), block_mode=BlockMode.NXDOMAIN)
    reply, event = ask(make(nx_policy), "blocked.example")
    assert reply.rcode() == dns.rcode.NXDOMAIN and event.rcode == dns.rcode.NXDOMAIN and event.blocked
    refused_policy = Policy(custom=custom("blocked.example"), block_mode=BlockMode.REFUSED)
    reply, event = ask(make(refused_policy), "blocked.example")
    assert reply.rcode() == dns.rcode.REFUSED and event.blocked


def test_custom_allow_beats_lists(lists):
    reply, event = ask(make(Policy(matcher=lists, custom=custom("@@||ads.example.com^"))), "ads.example.com")
    assert ips(reply) == DEFAULT_A and event.verdict is Verdict.FORWARDED and event.reason == "custom_allow"


def test_whitelist_beats_lists(lists):
    reply, event = ask(make(Policy(matcher=lists, custom=custom(whitelist=["ads.example.com"]))), "x.ads.example.com")
    assert ips(reply) == DEFAULT_A and event.reason == "whitelist"


def test_custom_block_beats_lists(lists):
    _, event = ask(make(Policy(matcher=lists, custom=custom("ads.example.com"))), "ads.example.com")
    assert event.reason == "custom"


def test_ad_list(lists):
    reply, event = ask(make(Policy(matcher=lists)), "x.ads.example.com")
    assert ips(reply) == "0.0.0.0" and event.verdict is Verdict.BLOCKED and event.reason == "ads"


def test_security_list(lists):
    reply, event = ask(make(Policy(matcher=lists)), "evil.example")
    assert ips(reply) == "0.0.0.0" and event.reason == "malware"


def test_all_lists_reported_security_first(tmp_path):
    matcher = FilterMatcher([
        build_list(tmp_path, "ads", 1, "both.example"),
        build_list(tmp_path, "malware", 0, "both.example"),
    ])
    _, event = ask(make(Policy(matcher=matcher)), "both.example")
    assert event.reason == "malware,ads"


def test_safesearch_answer():
    pipeline = make(Policy(safesearch=True), answers={("forcesafesearch.google.com", "A"): [("A", "216.239.38.120")]})
    reply, event = ask(pipeline, "www.google.com")
    assert ips(reply) == "216.239.38.120"
    assert event.verdict is Verdict.LOCAL and event.reason == "safesearch" and event.answers == ("216.239.38.120",)
    assert pipeline.resolver.calls == [("forcesafesearch.google.com", "A")]  # www.google.com is never forwarded


def test_safesearch_lazy_resolve():
    reply, event = ask(make(Policy(safesearch=True)), "www.bing.com")
    assert ips(reply) == DEFAULT_A and event.reason == "safesearch"


def test_safesearch_resolve_failure_forwards():
    pipeline = make(Policy(safesearch=True), dead={"forcesafesearch.google.com"})
    reply, event = ask(pipeline, "www.google.com")
    assert ips(reply) == DEFAULT_A and event.verdict is Verdict.FORWARDED


def test_youtube_answer_and_failure():
    answers = {("restrict.youtube.com", "A"): [("A", "216.239.38.119")]}
    reply, event = ask(make(Policy(youtube_restricted=True), answers=answers), "www.youtube.com")
    assert ips(reply) == "216.239.38.119" and event.reason == "youtube_restricted"
    reply, event = ask(make(Policy(youtube_restricted=True), dead={"restrict.youtube.com"}), "www.youtube.com")
    assert ips(reply) == DEFAULT_A and event.verdict is Verdict.FORWARDED


def test_upstream_block_detected():
    reply, event = ask(make(answers={("clean.example", "A"): [("A", "0.0.0.0")]}), "clean.example")
    assert ips(reply) == "0.0.0.0" and event.verdict is Verdict.BLOCKED and event.reason == "upstream_dns"


def test_resolver_failure_is_servfail():
    reply, event = ask(make(dead={"*"}), "clean.example")
    assert reply.rcode() == dns.rcode.SERVFAIL and reply.question[0].name.to_text() == "clean.example."
    assert event.verdict is Verdict.FAILED and event.reason == "upstream_failed"


@pytest.mark.parametrize(
    ("preference", "name", "rdtype", "answers", "expected", "verdict"),
    [
        (PreferredIP.AUTO, "clean.example", "AAAA", None, DEFAULT_AAAA, Verdict.FORWARDED),
        (PreferredIP.IPV4, "clean.example", "AAAA", None, "", Verdict.LOCAL),
        (PreferredIP.IPV4, "clean.example", "A", None, DEFAULT_A, Verdict.FORWARDED),
        (PreferredIP.IPV6, "clean.example", "A", None, "", Verdict.LOCAL),
        (PreferredIP.IPV6, "ipv4only.example", "A", {("ipv4only.example", "AAAA"): []}, DEFAULT_A, Verdict.FORWARDED),
        (PreferredIP.IPV6, "nullv6.example", "A", {("nullv6.example", "AAAA"): [("AAAA", "::")]}, DEFAULT_A,
         Verdict.FORWARDED),
        (PreferredIP.IPV6, "clean.example", "AAAA", None, DEFAULT_AAAA, Verdict.FORWARDED),
    ],
)
def test_preferred_ip_type(preference, name, rdtype, answers, expected, verdict):
    reply, event = ask(make(Policy(preferred_ip=preference), answers=answers), name, rdtype)
    assert reply.rcode() == dns.rcode.NOERROR and ips(reply) == expected
    assert event.verdict is verdict
    if verdict is Verdict.LOCAL:
        assert event.reason == "preferred_ip"


def test_preferred_ipv6_does_not_resolve_blocked_names(lists):
    pipeline = make(Policy(matcher=lists, preferred_ip=PreferredIP.IPV6))
    _, event = ask(pipeline, "ads.example.com")
    assert event.blocked and pipeline.resolver.calls == []


# --- upstream dns_order_test.go: the standalone (root mode) order ----------------


def test_order_custom_block_beats_safesearch():
    _, event = ask(make(Policy(safesearch=True, custom=custom("www.google.com"))), "www.google.com")
    assert event.blocked and event.reason == "custom"


def test_order_custom_allow_skips_safesearch():
    pipeline = make(Policy(safesearch=True, custom=custom("@@www.google.com")))
    reply, event = ask(pipeline, "www.google.com")
    assert ips(reply) == DEFAULT_A and event.reason == "custom_allow"
    assert pipeline.resolver.calls == [("www.google.com", "A")]


def test_order_doh_list_beats_custom_allow():
    policy = Policy(doh_blocklist=frozenset({"dns.google"}), custom=custom("@@dns.google"))
    _, event = ask(make(policy), "dns.google")
    assert event.reason == "doh_bypass_protection"


def test_order_safesearch_beats_lists(tmp_path):
    matcher = FilterMatcher([build_list(tmp_path, "ads", 1, "google.com")])
    _, event = ask(make(Policy(matcher=matcher, safesearch=True)), "www.google.com")
    assert event.reason == "safesearch"


# --- our additions -----------------------------------------------------------------


NONCE = "00112233445566778899aabbccddeeff"


def test_probe_is_echoed_and_never_logged():
    pipeline = make(Policy(paused=True, custom=custom("invalid")))
    reply, event = ask(pipeline, f"{NONCE}.probe.blockads-linux.invalid", "TXT")
    assert reply.answer[0][0].strings == (f"blockads-linux:{NONCE}".encode(),) and reply.answer[0].ttl == 0
    assert event is None and pipeline.resolver.calls == []
    reply, event = ask(pipeline, f"{NONCE}.probe.blockads-linux.invalid", "A")
    assert reply.rcode() == dns.rcode.NOERROR and not reply.answer and event is None


def test_probe_case_is_normalized_but_echoed_question_kept():
    reply, _ = ask(make(), f"{NONCE.upper()}.Probe.BlockAds-Linux.Invalid", "TXT")
    assert reply.answer[0][0].strings == (f"blockads-linux:{NONCE}".encode(),)
    assert str(reply.question[0].name).startswith(NONCE.upper())


def test_other_invalid_names_are_nxdomain():
    pipeline = make()
    reply, event = ask(pipeline, "anything.invalid")
    assert reply.rcode() == dns.rcode.NXDOMAIN and event.verdict is Verdict.LOCAL and event.reason == "invalid_tld"
    assert pipeline.resolver.calls == []


def test_firefox_canary_even_when_paused():
    for policy in (Policy(), Policy(paused=True)):
        reply, event = ask(make(policy), FIREFOX_CANARY)
        assert reply.rcode() == dns.rcode.NXDOMAIN and event.reason == "doh_canary"


def test_paused_forwards_unfiltered(lists):
    policy = Policy(matcher=lists, paused=True, custom=custom("blocked.example"), safesearch=True)
    for name in ("ads.example.com", "blocked.example", "www.google.com"):
        reply, event = ask(make(policy), name)
        assert ips(reply) == DEFAULT_A and event.verdict is Verdict.FORWARDED and event.reason == "paused"


def test_internal_allowlist_is_exact(lists):
    policy = Policy(matcher=lists, internal_allow=frozenset({"ads.example.com"}))
    _, event = ask(make(policy), "ads.example.com")
    assert event.verdict is Verdict.FORWARDED and event.reason == "internal_allow"
    _, event = ask(make(policy), "x.ads.example.com")
    assert event.blocked


def test_subdomains_only_rule():
    policy = Policy(custom=custom("*.example.org"))
    assert ask(make(policy), "a.example.org")[1].blocked
    assert not ask(make(policy), "example.org")[1].blocked


@pytest.mark.parametrize("rdtype", ["AAAA", "HTTPS", "SVCB"])
def test_safesearch_hides_aaaa_and_https_hints(rdtype):
    pipeline = make(Policy(safesearch=True))
    reply, event = ask(pipeline, "www.google.com", rdtype)
    assert reply.rcode() == dns.rcode.NOERROR and not reply.answer and event.reason == "safesearch"
    assert pipeline.resolver.calls == []


def test_safesearch_leaves_other_types_alone():
    pipeline = make(Policy(safesearch=True))
    _, event = ask(pipeline, "www.google.com", "MX")
    assert event.verdict is Verdict.FORWARDED and pipeline.resolver.calls == [("www.google.com", "MX")]


def test_safesearch_null_target_falls_through():
    answers = {("forcesafesearch.google.com", "A"): [("A", "0.0.0.0")]}
    reply, event = ask(make(Policy(safesearch=True), answers=answers), "www.google.com")
    assert ips(reply) == DEFAULT_A and event.verdict is Verdict.FORWARDED


def test_safesearch_follows_cname_chain_and_ttl():
    answers = {("strict.bing.com", "A"): [
        ("strict.bing.com.", "CNAME", "strict.edge.example."),
        ("strict.edge.example.", "A", "203.0.113.7"),
    ]}
    reply, _ = ask(make(Policy(safesearch=True), answers=answers), "www.bing.com")
    assert ips(reply) == "203.0.113.7" and reply.answer[0].ttl == 300
    assert reply.answer[0].name.to_text() == "www.bing.com."


def cloaked_answers():
    return {("tracker.example.com", "A"): [
        ("tracker.example.com.", "CNAME", "cloak.trackerco.net."),
        ("cloak.trackerco.net.", "A", "192.0.2.9"),
    ]}


def test_cname_cloaking_is_blocked(lists):
    reply, event = ask(make(Policy(matcher=lists), answers=cloaked_answers()), "tracker.example.com")
    assert ips(reply) == "0.0.0.0" and event.blocked and event.reason == "cname:ads" and event.upstream == "fake"


def test_cname_cloaking_exemptions(lists):
    off = Policy(matcher=lists, cname_check=False)
    target_allowed = Policy(matcher=lists, custom=custom("@@cloak.trackerco.net"))
    name_allowed = Policy(matcher=lists, custom=custom("@@tracker.example.com"))
    for policy in (off, target_allowed, name_allowed):
        reply, event = ask(make(policy, answers=cloaked_answers()), "tracker.example.com")
        assert ips(reply) == "192.0.2.9" and event.verdict is Verdict.FORWARDED


def test_cname_target_custom_block():
    policy = Policy(custom=custom("trackerco.net"))
    _, event = ask(make(policy, answers=cloaked_answers()), "tracker.example.com")
    assert event.reason == "cname:custom"


def test_block_ttl_is_configurable():
    reply, _ = ask(make(Policy(custom=custom("blocked.example"), block_ttl=60)), "blocked.example")
    assert reply.answer[0].ttl == 60
    with pytest.raises(ValueError):
        Policy(block_ttl=-1)


def test_question_case_kept_in_every_kind_of_answer(lists):
    policy = Policy(matcher=lists, safesearch=True)
    for name in ("Ads.Example.COM", "Clean.Example", "WWW.Google.Com", "X.Invalid"):
        message = dns.message.make_query(name, "A")
        wire = message.to_wire()
        query = parse_query(wire)
        reply, _ = asyncio.run(make(policy).handle(query))
        out = render(reply)
        assert out[12 : len(wire)] == wire[12:]  # the question bytes, exactly


def test_internal_error_is_servfail():
    class Exploding(FilterMatcher):
        def match(self, domain):
            raise KeyError(domain)

    reply, event = ask(make(Policy(matcher=Exploding())), "clean.example")
    assert reply.rcode() == dns.rcode.SERVFAIL
    assert event.verdict is Verdict.FAILED and event.reason == "internal_error"


def test_events_measure_time():
    _, event = ask(make(), "clean.example")
    assert event.elapsed_ms >= 0 and event.name == "clean.example" and event.qtype == dns.rdatatype.A


def test_fuzz_every_query_gets_one_renderable_reply(lists):
    """Upstream FuzzServeDNS, seeded: block-all, NXDOMAIN and SafeSearch setups."""
    block_all = Policy(custom=custom("\n".join(["com", "net", "org", "example", "invalid", "arpa"])))
    setups = [
        make(block_all),
        make(Policy(custom=block_all.custom, block_mode=BlockMode.NXDOMAIN)),
        make(Policy(matcher=lists, safesearch=True, youtube_restricted=True)),
        make(Policy(), dead={"*"}),
    ]
    rng = random.Random(42)
    labels = ["ads", "example", "com", "www", "google", "youtube", "a\\ b", "semi\\;colon", "x\\000y", "Weird", "net"]
    types = ["A", "AAAA", "MX", "TXT", "HTTPS", "SVCB", "ANY", "CNAME", "PTR", "SOA", "NS", "CAA"]
    for _ in range(300):
        name = ".".join(rng.choice(labels) for _ in range(rng.randint(1, 4)))
        rdtype = rng.choice(types)
        kwargs = rng.choice([{}, {"use_edns": 0, "want_dnssec": True}, {"use_edns": 0, "payload": 512}])
        message = dns.message.make_query(name, rdtype, **kwargs)
        try:
            query = parse_query(message.to_wire())
        except InvalidQuery:
            continue
        for pipeline in setups:
            reply, _event = asyncio.run(pipeline.handle(query))
            assert dns.message.from_wire(render(reply, query.udp_limit)).id == message.id


# --- upstream safesearch_test.go ------------------------------------------------------


def normalized(name):
    return name.lower().rstrip(".")


@pytest.mark.parametrize(
    ("name", "target"),
    [
        ("google.com", "forcesafesearch.google.com"),
        ("www.google.com", "forcesafesearch.google.com"),
        ("google.co.uk", "forcesafesearch.google.com"),
        ("www.google.co.uk", "forcesafesearch.google.com"),
        ("WWW.Google.COM", "forcesafesearch.google.com"),
        ("www.google.com.", "forcesafesearch.google.com"),
        ("www.google.de", "forcesafesearch.google.com"),
        ("www.google.com.br", "forcesafesearch.google.com"),
        ("google.cat", "forcesafesearch.google.com"),
        ("bing.com", "strict.bing.com"),
        ("www.bing.com", "strict.bing.com"),
        ("cn.bing.com", "strict.bing.com"),
        ("a.b.bing.com", "strict.bing.com"),
        # Non-search Google hosts are left alone.
        ("mail.google.com", None),
        ("maps.google.co.uk", None),
        ("news.google.com", None),
        ("www.news.google.com", None),
        ("forcesafesearch.google.com", None),
        ("googleapis.com", None),
        ("notgoogle.com", None),
        ("bing.co", None),
        ("notbing.com", None),
        ("xbing.com", None),
        ("bing.com.evil", None),
        ("example.com", None),
        ("", None),
        # Upstream's known over-match bug (TestCheckGoogleOverMatch), fixed here.
        ("google.internal", None),
        ("google.evil.example", None),
        ("www.google.lan", None),
        ("google", None),
        ("www.google", None),
    ],
)
def test_safesearch_target(name, target):
    assert safesearch_target(normalized(name)) == target


@pytest.mark.parametrize(
    ("name", "restricted"),
    [
        ("youtube.com", True),
        ("www.youtube.com", True),
        ("m.youtube.com", True),
        ("WWW.YOUTUBE.COM", True),
        ("youtube-nocookie.com", True),
        ("www.youtube-nocookie.com", True),
        ("youtube.googleapis.com", True),
        ("youtubei.googleapis.com", True),
        ("notyoutube.com", False),
        ("youtube.com.evil.example", False),
        ("googleapis.com", False),
        ("example.com", False),
    ],
)
def test_youtube_target(name, restricted):
    assert youtube_target(normalized(name)) == ("restrict.youtube.com" if restricted else None)


def test_safesearch_only_rewrites_address_queries_when_enabled():
    # Disabled by default (upstream TestCheckDisabledByDefault).
    pipeline = make()
    _, event = ask(pipeline, "www.google.com")
    assert event.verdict is Verdict.FORWARDED
    # YouTube restriction is independent of SafeSearch.
    _, event = ask(make(Policy(youtube_restricted=True)), "www.google.com")
    assert event.verdict is Verdict.FORWARDED


def test_doh_lookups_are_counted_when_the_block_is_off():
    pipeline = make(Policy(doh_watch=frozenset({"dns.google"})))
    reply, event = ask(pipeline, "x.dns.google")
    assert ips(reply) == DEFAULT_A and event.verdict is Verdict.FORWARDED
    ask(pipeline, "clean.example")
    assert pipeline.doh_lookups == 1 and pipeline.doh_last > 0
