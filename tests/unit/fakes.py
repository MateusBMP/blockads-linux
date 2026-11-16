"""Test doubles shared by the daemon tests."""

import dns.message
import dns.rdatatype
import dns.rrset

from blockads_linux.daemon.upstream.base import Resolution, ResolveError

DEFAULT_A = "192.0.2.1"
DEFAULT_AAAA = "2001:db8::1"


class FakeResolver:
    """Upstream stand-in, like upstream's ``defaultUpstream``.

    Every A query gets 192.0.2.1 and every AAAA query 2001:db8::1, unless
    ``answers[(name, type)]`` says otherwise; names in ``dead`` (or ``"*"``)
    fail.
    """

    def __init__(self, answers=None, dead=()):
        self.answers = answers or {}
        self.dead = set(dead)
        self.calls = []

    async def resolve(self, question):
        self.calls.append((question.name, dns.rdatatype.to_text(question.rdtype)))
        if "*" in self.dead or question.name in self.dead:
            raise ResolveError("dead upstream")
        message = dns.message.make_response(question.to_message(0x4242))
        key = (question.name, dns.rdatatype.to_text(question.rdtype))
        records = self.answers.get(key)
        if records is None:
            if question.rdtype == dns.rdatatype.A:
                records = [("A", DEFAULT_A)]
            elif question.rdtype == dns.rdatatype.AAAA:
                records = [("AAAA", DEFAULT_AAAA)]
            else:
                records = []
        for record in records:
            if record and record[0] == "RCODE":
                message.set_rcode(record[1])
                continue
            owner = question.qname
            if len(record) == 3:
                owner, record = record[0], record[1:]
            message.answer.append(dns.rrset.from_text(owner, 300, "IN", *record))
        return Resolution(message, upstream="fake")
