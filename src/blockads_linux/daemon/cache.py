"""TTL-bounded LRU cache of upstream answers.

Entries are stored in wire form and parsed again on every hit, so no caller
can modify a cached answer; TTLs are aged by the time spent in the cache. The
clock is monotonic, so wall-clock jumps (NTP, suspend) never extend an entry.

What is cached (RFC 2308):
* positive answers for the smallest TTL in the answer and authority sections;
* NXDOMAIN and NODATA for ``min(SOA TTL, SOA MINIMUM)``, capped at
  ``max_negative_ttl``; negative answers without a SOA are not cached;
* never: truncated replies, SERVFAIL, REFUSED or any other error, TTL 0.
"""

from __future__ import annotations

import time
from collections import OrderedDict
from collections.abc import Callable, Hashable
from dataclasses import dataclass

import dns.flags
import dns.message
import dns.rcode
import dns.rdatatype

DEFAULT_MAX_ENTRIES = 10_000
DEFAULT_MAX_TTL = 86_400
DEFAULT_MAX_NEGATIVE_TTL = 3_600


def cache_ttl(message: dns.message.Message, max_ttl: int = DEFAULT_MAX_TTL,
              max_negative_ttl: int = DEFAULT_MAX_NEGATIVE_TTL) -> int:
    """How long ``message`` may be cached, in seconds (0: not at all)."""
    if message.flags & dns.flags.TC:
        return 0
    rcode = message.rcode()
    if rcode not in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN):
        return 0
    if rcode == dns.rcode.NOERROR and message.answer:
        ttls = [rrset.ttl for rrset in message.answer] + [rrset.ttl for rrset in message.authority]
        return max(0, min(min(ttls), max_ttl))
    for rrset in message.authority:
        if rrset.rdtype == dns.rdatatype.SOA and len(rrset):
            return max(0, min(rrset.ttl, rrset[0].minimum, max_negative_ttl))
    return 0


def age_message(message: dns.message.Message, seconds: int) -> dns.message.Message:
    """Decrease every TTL by ``seconds`` (not below 0), in place."""
    if seconds > 0:
        for section in (message.answer, message.authority, message.additional):
            for rrset in section:
                rrset.ttl = max(0, rrset.ttl - seconds)
    return message


@dataclass(slots=True)
class _Entry:
    wire: bytes
    label: str
    tier: str
    stored: float
    expires: float


class DnsCache:
    def __init__(self, max_entries: int = DEFAULT_MAX_ENTRIES, *, max_ttl: int = DEFAULT_MAX_TTL,
                 max_negative_ttl: int = DEFAULT_MAX_NEGATIVE_TTL,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.max_entries = max_entries
        self.max_ttl = max_ttl
        self.max_negative_ttl = max_negative_ttl
        self._clock = clock
        self._entries: OrderedDict[Hashable, _Entry] = OrderedDict()
        self.hits = 0
        self.misses = 0

    def __len__(self) -> int:
        return len(self._entries)

    def get(self, key: Hashable) -> tuple[dns.message.Message, str, str] | None:
        """A fresh, aged copy of the cached answer, its upstream label and tier."""
        entry = self._entries.get(key)
        if entry is None:
            self.misses += 1
            return None
        now = self._clock()
        if now >= entry.expires:
            del self._entries[key]
            self.misses += 1
            return None
        self._entries.move_to_end(key)
        self.hits += 1
        message = dns.message.from_wire(entry.wire, ignore_trailing=True)
        return age_message(message, int(now - entry.stored)), entry.label, entry.tier

    def put(self, key: Hashable, message: dns.message.Message, wire: bytes, label: str = "",
            tier: str = "") -> bool:
        """Store ``message`` (whose wire form is ``wire``) if it is cacheable."""
        if self.max_entries <= 0:
            return False
        ttl = cache_ttl(message, self.max_ttl, self.max_negative_ttl)
        if ttl <= 0:
            return False
        now = self._clock()
        self._entries[key] = _Entry(wire, label, tier, now, now + ttl)
        self._entries.move_to_end(key)
        while len(self._entries) > self.max_entries:
            self._entries.popitem(last=False)
        return True

    def clear(self) -> None:
        self._entries.clear()
