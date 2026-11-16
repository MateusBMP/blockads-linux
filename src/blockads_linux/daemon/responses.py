"""Client query validation and the answers the daemon builds itself.

dnspython is used only as a wire codec. The rules:

* Only ordinary queries are served: QR=0, opcode QUERY, exactly one question
  of class IN, no answer or authority records, at most ``MAX_QUERY_SIZE``
  bytes, EDNS version 0. Responses (QR=1) and runts are dropped without a
  reply, so the daemon can never take part in a reply loop. Other malformed
  queries get FORMERR, NOTIMP, REFUSED or BADVERS.
* Synthesized answers copy the client's question, case included (0x20
  randomization); answer owners compress to it.
* Blocked answers: A -> ``0.0.0.0``, AAAA -> ``::``, any other type -> NODATA
  with a SOA, so downstream negative caching lasts only the block TTL (10 s by
  default). NXDOMAIN (also with a SOA) and REFUSED are selectable.
* EDNS is mirrored: an EDNS client gets an OPT record (our payload size, DO
  echoed as RFC 3225 requires); a client without EDNS never does. A UDP answer
  that does not fit the client's size is replaced by a truncated one (TC=1),
  so the client retries over TCP.
"""

from __future__ import annotations

import enum
import ipaddress
import re
import struct
from collections.abc import Iterable
from dataclasses import dataclass

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset
from dns.rdtypes.ANY.SOA import SOA
from dns.rdtypes.ANY.TXT import TXT
from dns.rdtypes.IN.A import A
from dns.rdtypes.IN.AAAA import AAAA

HEADER = struct.Struct("!HHHHHH")
HEADER_SIZE = HEADER.size
#: Largest query accepted on any transport (real queries are a few hundred bytes).
MAX_QUERY_SIZE = 4096
MIN_UDP_PAYLOAD = 512
#: Our EDNS UDP payload size, towards clients and upstreams (DNS flag day 2020).
MAX_UDP_PAYLOAD = 1232
MAX_TCP_MESSAGE = 65535
DEFAULT_BLOCK_TTL = 10

IN = dns.rdataclass.IN
TYPE_A = dns.rdatatype.A
TYPE_AAAA = dns.rdatatype.AAAA
TYPE_TXT = dns.rdatatype.TXT
TYPE_SOA = dns.rdatatype.SOA

_QR = 0x8000
_OPCODE_MASK = 0x7800
_RD = 0x0100
_RA = 0x0080
_CD = 0x0010

#: Meta and transfer types we never serve: 0, OPT, TKEY, TSIG, IXFR, AXFR,
#: MAILB, MAILA. ANY (255) is forwarded; upstreams answer it per RFC 8482.
REFUSED_QTYPES = frozenset({0, 41, 249, 250, 251, 252, 253, 254})

SOA_MNAME = dns.name.from_text("blocked.blockads-linux.invalid.")
SOA_RNAME = dns.name.from_text("hostmaster.blockads-linux.invalid.")

#: Health/commit-confirm probe: ``TXT <nonce>.probe.blockads-linux.invalid``.
PROBE_ZONE = "probe.blockads-linux.invalid"
PROBE_ANSWER_PREFIX = "blockads-linux:"
_PROBE_RE = re.compile(r"([0-9a-f]{32})\." + re.escape(PROBE_ZONE))

_NULL_ADDRESSES = frozenset({ipaddress.IPv4Address("0.0.0.0"), ipaddress.IPv6Address("::")})


class BlockMode(enum.Enum):
    """How blocked names are answered (the "response type" setting)."""

    NULL_IP = "null_ip"  # A 0.0.0.0, AAAA ::, other types NODATA + SOA (default)
    NXDOMAIN = "nxdomain"
    REFUSED = "refused"


class InvalidQuery(Exception):
    """The input is not a query we serve.

    ``response`` is the wire reply to send, or ``None`` to drop the input.
    """

    def __init__(self, reason: str, response: bytes | None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.response = response


def normalize_name(name: dns.name.Name) -> str:
    """Lowercase presentation form without the final dot; ``""`` for the root.

    Label bytes that are not printable ASCII, and special characters such as a
    dot inside a label, stay escaped (``\\DDD``, ``\\.``), so an unusual name
    can never alias an ordinary one.
    """
    if name.labels in ((), (b"",)):
        return ""
    return name.to_text(omit_final_dot=True).lower()


@dataclass(frozen=True, slots=True)
class Query:
    """A validated client query."""

    message: dns.message.Message
    name: str  # normalize_name(qname)
    qtype: int

    @property
    def qname(self) -> dns.name.Name:
        """The question name exactly as the client sent it (case included)."""
        return self.message.question[0].name

    @property
    def id(self) -> int:
        return self.message.id

    @property
    def edns(self) -> bool:
        return self.message.edns >= 0

    @property
    def dnssec_ok(self) -> bool:
        return self.message.edns >= 0 and bool(self.message.ednsflags & dns.flags.DO)

    @property
    def checking_disabled(self) -> bool:
        return bool(self.message.flags & dns.flags.CD)

    @property
    def udp_limit(self) -> int:
        """Largest UDP answer this client accepts (512 without EDNS)."""
        if self.message.edns < 0:
            return MIN_UDP_PAYLOAD
        return max(MIN_UDP_PAYLOAD, min(self.message.payload, MAX_UDP_PAYLOAD))


def header_reply(wire: bytes, rcode: int) -> bytes:
    """A header-only reply (no sections) for input dnspython cannot decode."""
    qid, flags = struct.unpack_from("!HH", wire)
    flags = _QR | (flags & (_OPCODE_MASK | _RD | _CD)) | _RA | (rcode & 0xF)
    return HEADER.pack(qid, flags, 0, 0, 0, 0)


def parse_query(wire: bytes) -> Query:
    """Validate a client query. Raises :class:`InvalidQuery`."""
    if len(wire) < HEADER_SIZE:
        raise InvalidQuery("short header", None)
    _qid, flags, qdcount, ancount, nscount, _arcount = HEADER.unpack_from(wire)
    if flags & _QR:
        raise InvalidQuery("not a query", None)
    if len(wire) > MAX_QUERY_SIZE:
        raise InvalidQuery("query too large", header_reply(wire, dns.rcode.FORMERR))
    if flags & _OPCODE_MASK:
        raise InvalidQuery("opcode not implemented", header_reply(wire, dns.rcode.NOTIMP))
    if qdcount != 1 or ancount or nscount:
        raise InvalidQuery("bad section counts", header_reply(wire, dns.rcode.FORMERR))
    try:
        message = dns.message.from_wire(wire)
    except dns.message.UnknownTSIGKey:
        raise InvalidQuery("signed query", header_reply(wire, dns.rcode.REFUSED)) from None
    except Exception:  # dnspython raises many types for malformed input
        raise InvalidQuery("malformed query", header_reply(wire, dns.rcode.FORMERR)) from None
    if message.edns > 0:
        reply = make_reply(message)
        reply.set_rcode(dns.rcode.BADVERS)
        raise InvalidQuery("unsupported EDNS version", render(reply, MIN_UDP_PAYLOAD))
    question = message.question[0]
    if question.rdclass != IN or question.rdtype in REFUSED_QTYPES:
        raise InvalidQuery("class or type not served", render(make_reply(message, dns.rcode.REFUSED), MIN_UDP_PAYLOAD))
    return Query(message, normalize_name(question.name), int(question.rdtype))


def make_reply(query: dns.message.Message, rcode: int = dns.rcode.NOERROR) -> dns.message.Message:
    """An empty reply: same ID and question, RD/CD copied, RA set, EDNS mirrored."""
    reply = dns.message.Message(id=query.id)
    reply.flags = dns.flags.QR | dns.flags.RA | (query.flags & (dns.flags.RD | dns.flags.CD))
    reply.question = list(query.question)
    if query.edns >= 0:
        reply.use_edns(0, query.ednsflags & dns.flags.DO, MAX_UDP_PAYLOAD)
    reply.set_rcode(rcode)
    return reply


def error_reply(query: Query, rcode: int) -> dns.message.Message:
    return make_reply(query.message, rcode)


def _soa(owner: dns.name.Name, ttl: int) -> dns.rrset.RRset:
    rdata = SOA(IN, TYPE_SOA, SOA_MNAME, SOA_RNAME, 1, 1800, 900, 604800, ttl)
    return dns.rrset.from_rdata(owner, ttl, rdata)


def nodata_reply(query: Query, ttl: int = DEFAULT_BLOCK_TTL) -> dns.message.Message:
    """NOERROR with no answer; the SOA bounds negative caching to ``ttl``."""
    reply = make_reply(query.message)
    reply.authority.append(_soa(query.qname, ttl))
    return reply


def nxdomain_reply(query: Query, ttl: int = DEFAULT_BLOCK_TTL) -> dns.message.Message:
    reply = make_reply(query.message, dns.rcode.NXDOMAIN)
    reply.authority.append(_soa(query.qname, ttl))
    return reply


def address_reply(query: Query, addresses: Iterable[str], ttl: int) -> dns.message.Message:
    """Answer with the given addresses of the query's type; NODATA if none fits."""
    reply = make_reply(query.message)
    rdatas = []
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if query.qtype == TYPE_A and ip.version == 4:
            rdatas.append(A(IN, TYPE_A, str(ip)))
        elif query.qtype == TYPE_AAAA and ip.version == 6:
            rdatas.append(AAAA(IN, TYPE_AAAA, str(ip)))
    if not rdatas:
        reply.authority.append(_soa(query.qname, ttl))
        return reply
    reply.answer.append(dns.rrset.from_rdata_list(query.qname, ttl, rdatas))
    return reply


def txt_reply(query: Query, text: str, ttl: int = 0) -> dns.message.Message:
    reply = make_reply(query.message)
    rdata = TXT(IN, TYPE_TXT, [text.encode("ascii")])
    reply.answer.append(dns.rrset.from_rdata(query.qname, ttl, rdata))
    return reply


def blocked_reply(query: Query, mode: BlockMode = BlockMode.NULL_IP, ttl: int = DEFAULT_BLOCK_TTL) -> dns.message.Message:
    if mode is BlockMode.NXDOMAIN:
        return nxdomain_reply(query, ttl)
    if mode is BlockMode.REFUSED:
        return make_reply(query.message, dns.rcode.REFUSED)
    if query.qtype == TYPE_A:
        return address_reply(query, ("0.0.0.0",), ttl)
    if query.qtype == TYPE_AAAA:
        return address_reply(query, ("::",), ttl)
    return nodata_reply(query, ttl)


def forwarded_reply(query: Query, upstream: dns.message.Message) -> dns.message.Message:
    """Re-address an upstream answer to the client.

    The client's ID, question (case included), RD/CD bits and EDNS state are
    used; the upstream's OPT record (cookies, ECS, padding) never reaches the
    client. AD is passed on only if the client asked for DNSSEC data (DO or
    AD, RFC 6840 §5.8); AA is never set, since this is a forwarder. An
    extended RCODE belongs to our own upstream exchange and becomes SERVFAIL.
    """
    rcode = upstream.rcode()
    if rcode > 15:
        return make_reply(query.message, dns.rcode.SERVFAIL)
    reply = make_reply(query.message, rcode)
    keep = dns.flags.TC
    if query.dnssec_ok or query.message.flags & dns.flags.AD:
        keep |= dns.flags.AD
    reply.flags |= upstream.flags & keep
    reply.answer = list(upstream.answer)
    reply.authority = list(upstream.authority)
    reply.additional = list(upstream.additional)
    return reply


def render(message: dns.message.Message, limit: int = MAX_TCP_MESSAGE) -> bytes:
    """Wire form of ``message``; truncated (TC=1, question only) above ``limit``."""
    try:
        return message.to_wire(max_size=limit)
    except dns.exception.TooBig:
        short = dns.message.Message(id=message.id)
        short.flags = message.flags | dns.flags.TC
        short.question = list(message.question)
        if message.edns >= 0:
            short.use_edns(0, message.ednsflags & dns.flags.DO, message.payload)
        short.set_rcode(message.rcode())
        return short.to_wire(max_size=MAX_TCP_MESSAGE)


def addresses(message: dns.message.Message, rdtype: int | None = None) -> list[tuple[str, int]]:
    """``(address, ttl)`` of the A/AAAA records in the answer section."""
    found = []
    for rrset in message.answer:
        if rrset.rdtype in (TYPE_A, TYPE_AAAA) and (rdtype is None or rrset.rdtype == rdtype):
            found.extend((rdata.address, rrset.ttl) for rdata in rrset)
    return found


def is_upstream_blocked(message: dns.message.Message) -> bool:
    """Port of upstream ``isUpstreamBlocked``: every A/AAAA answer is a null IP.

    Answers without address records (NXDOMAIN, NODATA, CNAME-only) and mixed
    null/real answers are not flagged.
    """
    found = addresses(message)
    return bool(found) and all(ipaddress.ip_address(address) in _NULL_ADDRESSES for address, _ in found)


def probe_nonce(name: str) -> str | None:
    """The nonce of a probe name (``<32 hex>.probe.blockads-linux.invalid``)."""
    match = _PROBE_RE.fullmatch(name)
    return match.group(1) if match else None


def is_invalid_tld(name: str) -> bool:
    """RFC 6761 ``.invalid`` names, which are always answered locally."""
    return name == "invalid" or name.endswith(".invalid")
