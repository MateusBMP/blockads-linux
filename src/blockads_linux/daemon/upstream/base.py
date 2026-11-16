"""Types shared by the query pipeline, the resolver and the upstream transports."""

from __future__ import annotations

import ssl
from dataclasses import dataclass
from typing import Protocol

import dns.edns
import dns.flags
import dns.message
import dns.name
import dns.opcode
import dns.rcode
import dns.rdataclass
import dns.rrset

from ..responses import MAX_UDP_PAYLOAD, Query, normalize_name


class ResolveError(Exception):
    """No usable answer could be obtained from any upstream."""


class UpstreamError(ResolveError):
    """One upstream exchange failed (timeout, I/O, TLS, HTTP, bad answer)."""


class ResponseMismatch(UpstreamError):
    """A reply that does not answer our query (wrong ID or question)."""


class CertificateTimeError(UpstreamError):
    """The certificate is outside its validity period *by our clock*.

    "Not yet valid" or "expired": with a well-known provider this almost
    always means the system clock is wrong, which enables the NTP-name
    exception of "encrypted only".
    """


#: OpenSSL X509_V_ERR_CERT_NOT_YET_VALID and X509_V_ERR_CERT_HAS_EXPIRED.
_CERT_TIME_CODES = frozenset({9, 10})


def tls_verify_error(exc: BaseException) -> UpstreamError | None:
    """The certificate-verification failure anywhere in ``exc``'s cause chain,
    as an :class:`UpstreamError` (a :class:`CertificateTimeError` for validity
    period failures), or ``None`` if there is none."""
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, ssl.SSLCertVerificationError):
            message = f"TLS certificate rejected: {current.verify_message or 'verification failed'}"
            if current.verify_code in _CERT_TIME_CODES:
                return CertificateTimeError(message)
            return UpstreamError(message)
        current = current.__cause__ or current.__context__
    return None


@dataclass(frozen=True, slots=True)
class Question:
    """What we ask an upstream: one question plus the client's DO/CD bits."""

    name: str  # normalized (lowercase, no final dot): cache and dedupe key
    qname: dns.name.Name  # as sent upstream (the first asker's case)
    rdtype: int
    dnssec_ok: bool = False
    checking_disabled: bool = False

    @classmethod
    def make(cls, qname: dns.name.Name | str, rdtype: int, dnssec_ok: bool = False,
             checking_disabled: bool = False) -> "Question":
        if isinstance(qname, str):
            qname = dns.name.from_text(qname)
        return cls(normalize_name(qname), qname, int(rdtype), dnssec_ok, checking_disabled)

    @classmethod
    def of(cls, query: Query) -> "Question":
        return cls(query.name, query.qname, query.qtype, query.dnssec_ok, query.checking_disabled)

    @property
    def key(self) -> tuple[str, int, bool, bool]:
        return (self.name, self.rdtype, self.dnssec_ok, self.checking_disabled)

    def to_message(self, qid: int, *, payload: int = MAX_UDP_PAYLOAD) -> dns.message.Message:
        """The upstream query. It never carries client EDNS options (ECS, cookies)."""
        message = dns.message.Message(id=qid)
        message.flags = dns.flags.RD | (dns.flags.CD if self.checking_disabled else 0)
        message.question = [dns.rrset.RRset(self.qname, dns.rdataclass.IN, self.rdtype)]
        message.use_edns(0, dns.flags.DO if self.dnssec_ok else 0, payload)
        return message

    def to_wire(self, qid: int, *, pad_block: int = 0) -> bytes:
        """Wire form of :meth:`to_message`, optionally padded (RFC 7830/8467).

        Encrypted transports pad queries to a multiple of ``pad_block`` bytes
        (128 is the RFC 8467 recommendation) so their size does not reveal
        the name. Done by hand: dnspython 2.3 has no ``pad`` argument.
        """
        message = self.to_message(qid)
        wire = message.to_wire()
        if pad_block <= 0:
            return wire
        # The option header is 4 bytes; fill up to the next block boundary.
        fill = -(len(wire) + 4) % pad_block
        message.use_edns(0, message.ednsflags, message.payload,
                         options=[dns.edns.GenericOption(dns.edns.PADDING, b"\0" * fill)])
        return message.to_wire()


@dataclass(slots=True)
class Resolution:
    """An upstream answer. ``message`` is private to the caller, which may change it."""

    message: dns.message.Message
    upstream: str = ""  # label of the upstream that answered
    cached: bool = False
    tier: str = ""  # tier of that upstream ("configured", "fallback", "ntp-rescue", ...)


class Resolver(Protocol):
    """Anything that answers questions: the cached forwarder, or a test fake."""

    async def resolve(self, question: Question) -> Resolution: ...


def check_response(question: Question, qid: int, wire: bytes) -> dns.message.Message:
    """Parse an upstream reply and check it answers our query.

    Raises :class:`ResponseMismatch` for a wrong ID or question (on plain UDP
    the caller keeps waiting for the real reply) and :class:`UpstreamError`
    for anything undecodable.
    """
    if len(wire) < 12:
        raise ResponseMismatch("short reply")
    if int.from_bytes(wire[:2], "big") != qid:
        raise ResponseMismatch("reply ID does not match")
    try:
        message = dns.message.from_wire(wire, ignore_trailing=True)
    except Exception as exc:  # dnspython raises many types for malformed input
        raise UpstreamError(f"undecodable reply: {type(exc).__name__}") from None
    if not message.flags & dns.flags.QR or message.opcode() != dns.opcode.QUERY:
        raise ResponseMismatch("not a reply to a query")
    if not message.question and message.rcode() != dns.rcode.NOERROR:
        # Some servers send FORMERR/REFUSED/SERVFAIL without the question.
        raise UpstreamError(f"upstream answered {dns.rcode.to_text(message.rcode())}")
    if len(message.question) != 1:
        raise ResponseMismatch("reply has no single question")
    asked = message.question[0]
    # Name comparison is case-insensitive, like DNS itself.
    if asked.name != question.qname or asked.rdtype != question.rdtype or asked.rdclass != dns.rdataclass.IN:
        raise ResponseMismatch("reply question does not match")
    return message
