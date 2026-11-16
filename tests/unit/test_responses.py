"""Tests for daemon.responses: query validation and synthesized answers."""

import random
import struct

import dns.edns
import dns.flags
import dns.message
import dns.name
import dns.opcode
import dns.rcode
import dns.rdatatype
import dns.rrset
import dns.tsigkeyring
import pytest

from blockads_linux.daemon.responses import (
    MAX_QUERY_SIZE,
    MAX_UDP_PAYLOAD,
    BlockMode,
    InvalidQuery,
    address_reply,
    addresses,
    blocked_reply,
    forwarded_reply,
    is_invalid_tld,
    is_upstream_blocked,
    normalize_name,
    nxdomain_reply,
    parse_query,
    probe_nonce,
    render,
    txt_reply,
)


def wire_query(name="example.com", rdtype="A", *, edns=None, payload=1232, dnssec=False, qid=0x1234, flags=None):
    # make_query enables EDNS as soon as any EDNS parameter is given.
    extra = {"use_edns": edns, "payload": payload, "want_dnssec": dnssec} if edns is not None else {}
    message = dns.message.make_query(name, rdtype, **extra)
    message.id = qid
    if flags is not None:
        message.flags = flags
    return message.to_wire()


def query(name="example.com", rdtype="A", **kw):
    return parse_query(wire_query(name, rdtype, **kw))


def reply_of(message):
    """Round-trip through the wire, as a client would see it."""
    return dns.message.from_wire(render(message))


def rejected(wire):
    with pytest.raises(InvalidQuery) as info:
        parse_query(wire)
    return info.value


# --- parsing and validation -------------------------------------------------


def test_parse_valid_query():
    q = query("WwW.Example.COM", "AAAA", edns=0, payload=4096, dnssec=True)
    assert q.name == "www.example.com"
    assert q.qtype == dns.rdatatype.AAAA
    assert q.id == 0x1234
    assert str(q.qname) == "WwW.Example.COM."
    assert q.edns and q.dnssec_ok
    assert q.udp_limit == MAX_UDP_PAYLOAD


@pytest.mark.parametrize(("edns", "payload", "limit"), [(None, 0, 512), (0, 4096, 1232), (0, 1000, 1000), (0, 100, 512)])
def test_udp_limit(edns, payload, limit):
    assert query(edns=edns, payload=payload).udp_limit == limit


def test_runt_and_responses_are_dropped():
    assert rejected(b"\x12\x34\x01").response is None
    response = dns.message.make_response(dns.message.make_query("example.com", "A"))
    assert rejected(response.to_wire()).response is None


def header_of(reply):
    qid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", reply[:12])
    return qid, flags, (qd, an, ns, ar)


def test_other_opcodes_get_notimp():
    wire = bytearray(wire_query())
    wire[2] = (wire[2] & 0x87) | (dns.opcode.NOTIFY << 3)
    qid, flags, counts = header_of(rejected(bytes(wire)).response)
    assert qid == 0x1234 and flags & 0x8000 and flags & 0xF == dns.rcode.NOTIMP
    assert (flags >> 11) & 0xF == dns.opcode.NOTIFY
    assert counts == (0, 0, 0, 0)


@pytest.mark.parametrize("counts", [(0, 0, 0, 0), (2, 0, 0, 0), (1, 1, 0, 0), (1, 0, 1, 0)])
def test_bad_counts_get_formerr(counts):
    wire = wire_query()
    wire = wire[:4] + struct.pack("!HHHH", *counts) + wire[12:]
    _, flags, _ = header_of(rejected(wire).response)
    assert flags & 0xF == dns.rcode.FORMERR


@pytest.mark.parametrize(
    "tail",
    [
        b"",  # no question at all
        b"\x07example",  # truncated name
        b"\xc0\x0c\x00\x01\x00\x01",  # pointer loop to itself
        b"\x07example\x03com\x00\x00\x01",  # truncated qclass
    ],
)
def test_malformed_questions_get_formerr(tail):
    wire = wire_query()[:12] + tail
    _, flags, _ = header_of(rejected(wire).response)
    assert flags & 0xF == dns.rcode.FORMERR


def test_trailing_junk_gets_formerr():
    _, flags, _ = header_of(rejected(wire_query() + b"junk").response)
    assert flags & 0xF == dns.rcode.FORMERR


def test_oversized_query_gets_formerr():
    wire = wire_query() + b"\0" * MAX_QUERY_SIZE
    _, flags, _ = header_of(rejected(wire).response)
    assert flags & 0xF == dns.rcode.FORMERR


@pytest.mark.parametrize("rdtype", ["AXFR", "IXFR", "TKEY", "TSIG", "MAILA", "MAILB", "OPT"])
def test_meta_types_are_refused(rdtype):
    reply = dns.message.from_wire(rejected(wire_query("example.com", rdtype)).response)
    assert reply.rcode() == dns.rcode.REFUSED
    assert reply.question[0].rdtype == dns.rdatatype.from_text(rdtype)


def test_any_is_served():
    assert query("example.com", "ANY").qtype == dns.rdatatype.ANY


def test_non_in_class_is_refused():
    message = dns.message.make_query("version.bind", "TXT", rdclass="CH")
    reply = dns.message.from_wire(rejected(message.to_wire()).response)
    assert reply.rcode() == dns.rcode.REFUSED
    assert reply.question[0].rdclass == dns.rdataclass.CH


def test_edns_version_1_gets_badvers():
    # Patch the OPT version byte by hand: dnspython 2.3 (Debian 12) ignores
    # make_query(use_edns=1) and writes version 0.
    wire = bytearray(dns.message.make_query("example.com", "A", use_edns=0).to_wire())
    # OPT RR, last 11 bytes: root name(1) TYPE(2) CLASS(2) TTL(4) RDLEN(2) = 0,
    # where TTL = ext-rcode(1) version(1) flags(2).
    assert wire[-11] == 0 and wire[-10:-8] == b"\x00\x29" and wire[-2:] == b"\x00\x00"
    wire[-5] = 1
    reply = dns.message.from_wire(rejected(bytes(wire)).response)
    assert reply.rcode() == dns.rcode.BADVERS
    assert reply.edns == 0


def test_signed_queries_are_refused():
    message = dns.message.make_query("example.com", "A")
    message.use_tsig(dns.tsigkeyring.from_text({"k.": "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA="}), keyname="k.")
    _, flags, _ = header_of(rejected(message.to_wire()).response)
    assert flags & 0xF == dns.rcode.REFUSED


def test_error_reply_keeps_rd_and_cd():
    wire = wire_query(flags=dns.flags.RD | dns.flags.CD)
    wire = wire[:4] + struct.pack("!H", 0) + wire[6:]  # QDCOUNT=0
    _, flags, _ = header_of(rejected(wire).response)
    assert flags & dns.flags.RD and flags & dns.flags.CD and flags & dns.flags.RA


def test_random_mutations_never_escape():
    """Fuzz: any byte soup either parses or raises InvalidQuery."""
    rng = random.Random(1234)
    seeds = [wire_query(), wire_query("a.b.c.example", "HTTPS", edns=0, dnssec=True), wire_query("x" * 63, "TXT")]
    for _ in range(4000):
        wire = bytearray(rng.choice(seeds))
        for _ in range(rng.randint(1, 6)):
            action = rng.random()
            if action < 0.6 and wire:
                wire[rng.randrange(len(wire))] = rng.randrange(256)
            elif action < 0.8:
                wire.insert(rng.randrange(len(wire) + 1), rng.randrange(256))
            elif wire:
                del wire[rng.randrange(len(wire)) :]
        try:
            parsed = parse_query(bytes(wire))
        except InvalidQuery as exc:
            if exc.response is not None:
                assert len(exc.response) >= 12
            continue
        # A query that parses must also be answerable.
        render(blocked_reply(parsed), parsed.udp_limit)


# --- names ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("wire_name", "text"),
    [
        (b"\x03WWW\x07Example\x03COM\x00", "www.example.com"),
        (b"\x00", ""),
        (b"\x03a.b\x03com\x00", "a\\.b.com"),  # a dot inside a label stays escaped
        (b"\x02\xffZ\x00", "\\255z"),
        (b"\x04_dns\x03com\x00", "_dns.com"),
    ],
)
def test_normalize_name(wire_name, text):
    name, _ = dns.name.from_wire(wire_name, 0)
    assert normalize_name(name) == text


def test_probe_nonce_and_invalid_tld():
    nonce = "0123456789abcdef" * 2
    assert probe_nonce(f"{nonce}.probe.blockads-linux.invalid") == nonce
    assert probe_nonce(f"x{nonce}.probe.blockads-linux.invalid") is None
    assert probe_nonce(f"{nonce[:-1]}.probe.blockads-linux.invalid") is None
    assert probe_nonce("probe.blockads-linux.invalid") is None
    assert is_invalid_tld("invalid") and is_invalid_tld("foo.invalid")
    assert not is_invalid_tld("invalid.com") and not is_invalid_tld("notinvalid")


# --- synthesized answers ----------------------------------------------------


def test_blocked_a_and_aaaa():
    a = reply_of(blocked_reply(query("ads.example", "A")))
    assert a.rcode() == dns.rcode.NOERROR
    assert [(r.address, a.answer[0].ttl) for r in a.answer[0]] == [("0.0.0.0", 10)]
    aaaa = reply_of(blocked_reply(query("ads.example", "AAAA"), ttl=30))
    assert [(r.address, aaaa.answer[0].ttl) for r in aaaa.answer[0]] == [("::", 30)]


@pytest.mark.parametrize("rdtype", ["MX", "HTTPS", "TXT", "CNAME", "ANY"])
def test_blocked_other_types_are_nodata_with_soa(rdtype):
    q = query("Ads.Example", rdtype)
    reply = reply_of(blocked_reply(q))
    assert reply.rcode() == dns.rcode.NOERROR
    assert not reply.answer
    (soa_rrset,) = reply.authority
    soa = soa_rrset[0]
    assert soa_rrset.rdtype == dns.rdatatype.SOA and soa_rrset.ttl == 10 and soa.minimum == 10
    assert soa_rrset.name == q.qname
    assert str(soa.mname).endswith(".invalid.")


def test_blocked_nxdomain_and_refused_modes():
    nx = reply_of(blocked_reply(query("ads.example", "A"), BlockMode.NXDOMAIN, ttl=10))
    assert nx.rcode() == dns.rcode.NXDOMAIN and not nx.answer
    assert nx.authority[0].rdtype == dns.rdatatype.SOA and nx.authority[0].ttl == 10
    refused = reply_of(blocked_reply(query("ads.example", "A"), BlockMode.REFUSED))
    assert refused.rcode() == dns.rcode.REFUSED and not refused.answer and not refused.authority


def test_reply_header_flags():
    q = parse_query(wire_query(flags=dns.flags.RD | dns.flags.CD | dns.flags.AD))
    wire = render(blocked_reply(q))
    qid, flags, counts = header_of(wire)
    assert qid == 0x1234
    assert flags & dns.flags.QR and flags & dns.flags.RA and flags & dns.flags.RD and flags & dns.flags.CD
    assert not flags & (dns.flags.AA | dns.flags.TC | dns.flags.AD)
    assert counts == (1, 1, 0, 0)


def test_question_case_is_kept_0x20():
    wire = wire_query("DoUbLeClIcK.NeT", "A")
    q = parse_query(wire)
    out = render(blocked_reply(q))
    question_bytes = wire[12:]  # no EDNS: the question is the rest of the query
    assert out[12 : 12 + len(question_bytes)] == question_bytes
    # The answer owner is a compression pointer to the question name.
    assert out[12 + len(question_bytes) : 12 + len(question_bytes) + 2] == b"\xc0\x0c"


def test_edns_is_mirrored():
    with_edns = reply_of(blocked_reply(query(edns=0, payload=4096, dnssec=True)))
    assert with_edns.edns == 0 and with_edns.payload == MAX_UDP_PAYLOAD
    assert with_edns.ednsflags & dns.flags.DO
    without = reply_of(blocked_reply(query()))
    assert without.edns == -1


def test_address_reply_filters_by_family():
    q = query("www.google.com", "A")
    reply = reply_of(address_reply(q, ["2001:db8::1", "216.239.38.120"], 300))
    assert [r.address for r in reply.answer[0]] == ["216.239.38.120"]
    empty = reply_of(address_reply(query("www.google.com", "AAAA"), ["216.239.38.120"], 300))
    assert not empty.answer and empty.authority[0].rdtype == dns.rdatatype.SOA


def test_txt_and_nxdomain_replies():
    txt = reply_of(txt_reply(query("x.invalid", "TXT"), "blockads-linux:abc"))
    assert txt.answer[0][0].strings == (b"blockads-linux:abc",) and txt.answer[0].ttl == 0
    assert reply_of(nxdomain_reply(query("x.invalid"))).rcode() == dns.rcode.NXDOMAIN


# --- rendering and forwarding -------------------------------------------------


def big_upstream_answer(q, count=60):
    upstream = dns.message.make_response(q.message)
    for i in range(count):
        upstream.answer.append(dns.rrset.from_text(q.qname, 300, "IN", "TXT", '"%s"' % ("x" * 100 + str(i))))
    return upstream


def test_render_truncates_to_the_limit():
    q = query("example.com", "TXT")
    reply = forwarded_reply(q, big_upstream_answer(q))
    wire = render(reply, q.udp_limit)
    assert len(wire) <= 512
    short = dns.message.from_wire(wire)
    assert short.flags & dns.flags.TC and not short.answer and short.question == q.message.question
    full = dns.message.from_wire(render(reply))  # TCP: everything fits
    assert not full.flags & dns.flags.TC and len(full.answer[0]) == 60


def test_render_truncation_keeps_edns():
    q = query("example.com", "TXT", edns=0, payload=1232, dnssec=True)
    short = dns.message.from_wire(render(forwarded_reply(q, big_upstream_answer(q)), q.udp_limit))
    assert short.flags & dns.flags.TC and short.edns == 0 and short.ednsflags & dns.flags.DO


def upstream_for(q, *records, rcode=dns.rcode.NOERROR, flags=0, name=None):
    upstream = dns.message.make_query(name or q.qname, q.qtype, use_edns=0)
    upstream.id = 0x9999
    upstream = dns.message.make_response(upstream)
    upstream.flags |= flags
    upstream.set_rcode(rcode)
    for record in records:
        upstream.answer.append(dns.rrset.from_text(name or q.qname, 300, "IN", *record))
    upstream.use_edns(0, 0, 4096, options=[dns.edns.ECSOption("192.0.2.0", 24)])
    return upstream


def test_forwarded_reply_readdresses_the_answer():
    q = query("WwW.Example.Com", "A", flags=dns.flags.RD)
    upstream = upstream_for(q, ("A", "192.0.2.1"), flags=dns.flags.AA | dns.flags.AD, name="www.example.com.")
    wire = render(forwarded_reply(q, upstream), q.udp_limit)
    reply = dns.message.from_wire(wire)
    assert reply.id == 0x1234
    assert str(reply.question[0].name) == "WwW.Example.Com."
    assert [r.address for r in reply.answer[0]] == ["192.0.2.1"]
    assert not reply.flags & (dns.flags.AA | dns.flags.AD)  # no AA; AD only on request
    assert reply.edns == -1  # the client sent no EDNS: the upstream OPT/ECS is dropped
    assert b"WwW" in wire


def test_forwarded_reply_ad_and_edns_options():
    q = query("example.com", "A", edns=0, dnssec=True)
    reply = reply_of(forwarded_reply(q, upstream_for(q, ("A", "192.0.2.1"), flags=dns.flags.AD)))
    assert reply.flags & dns.flags.AD
    assert reply.edns == 0 and not reply.options  # the upstream's ECS option is gone


def test_forwarded_reply_extended_rcode_becomes_servfail():
    q = query("example.com", "A", edns=0)
    upstream = upstream_for(q, ("A", "192.0.2.1"))
    upstream.set_rcode(dns.rcode.BADCOOKIE)
    reply = reply_of(forwarded_reply(q, upstream))
    assert reply.rcode() == dns.rcode.SERVFAIL and not reply.answer


def test_forwarded_reply_keeps_nxdomain_and_authority():
    q = query("nope.example", "A")
    upstream = upstream_for(q, rcode=dns.rcode.NXDOMAIN)
    upstream.authority.append(
        dns.rrset.from_text("example.", 300, "IN", "SOA", "ns. host. 1 2 3 4 5")
    )
    reply = reply_of(forwarded_reply(q, upstream))
    assert reply.rcode() == dns.rcode.NXDOMAIN and reply.authority[0].rdtype == dns.rdatatype.SOA


@pytest.mark.parametrize(
    ("records", "blocked"),
    [
        ([("A", "0.0.0.0")], True),
        ([("AAAA", "::")], True),
        ([("A", "0.0.0.0"), ("A", "0.0.0.0")], True),
        ([("A", "0.0.0.0"), ("A", "192.0.2.1")], False),
        ([("A", "192.0.2.1")], False),
        ([("CNAME", "other.example.")], False),
        ([], False),
    ],
)
def test_is_upstream_blocked(records, blocked):
    q = query("x.example", "A")
    upstream = dns.message.make_response(q.message)
    for record in records:
        upstream.answer.append(dns.rrset.from_text(q.qname, 300, "IN", *record))
    assert is_upstream_blocked(upstream) is blocked


def test_nxdomain_is_not_upstream_blocked():
    q = query("x.example", "A")
    assert not is_upstream_blocked(upstream_for(q, rcode=dns.rcode.NXDOMAIN))


def test_addresses():
    q = query("x.example", "A")
    upstream = upstream_for(q, ("A", "192.0.2.1"), ("A", "192.0.2.2"))
    assert addresses(upstream) == [("192.0.2.1", 300), ("192.0.2.2", 300)]
    assert addresses(upstream, dns.rdatatype.AAAA) == []
