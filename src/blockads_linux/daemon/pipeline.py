"""The per-query decision pipeline (Android root-mode order).

Stages, in order (validation already happened in ``responses.parse_query``):

1. ``<nonce>.probe.blockads-linux.invalid`` -> TXT echo (health probe, never
   logged); any other ``.invalid`` name -> NXDOMAIN; the Firefox canary
   ``use-application-dns.net`` -> NXDOMAIN. These are answered even while
   paused, so a browser cannot switch itself to DoH during a pause.
2. Paused (or a trusted network in pause mode) -> forward unfiltered.
3. Preferred IP type ``ipv4`` -> AAAA answered with NODATA.
4. Internal allowlist (connectivity-check host, hosts of enabled list URLs)
   -> forward unfiltered.
5. DoH bootstrap blocklist, when enabled.
6. Custom ALLOW -> whitelist -> custom BLOCK (allow and whitelist forward
   unfiltered).
7. SafeSearch / YouTube Restricted: A -> the target's address; AAAA,
   HTTPS and SVCB -> NODATA. If the target cannot be resolved, the query
   continues down the pipeline (upstream behaviour).
8. Filter lists: security first; every matching list is reported.
9. Preferred IP type ``ipv6`` -> A answered with NODATA when the name has AAAA.
10. Forward. Then the CNAME-cloaking check (a blocked CNAME target blocks
    the query) and upstream-block detection (every address is a null IP ->
    reason ``upstream_dns``; the upstream's answer is still returned).

Any internal error becomes SERVFAIL: one bad query can never take the
daemon down. The pipeline never logs domain names (none ever reach
the journal); it returns a :class:`QueryEvent` instead.
"""

from __future__ import annotations

import enum
import ipaddress
import logging
import time
from dataclasses import dataclass, field

import dns.message
import dns.rcode
import dns.rdatatype

from ..filters.custom_rules import CustomRuleSet, CustomVerdict, entries_match
from ..filters.matcher import FilterMatcher
from .responses import (
    DEFAULT_BLOCK_TTL,
    PROBE_ANSWER_PREFIX,
    TYPE_A,
    TYPE_AAAA,
    TYPE_TXT,
    BlockMode,
    Query,
    addresses,
    address_reply,
    blocked_reply,
    error_reply,
    forwarded_reply,
    is_invalid_tld,
    is_upstream_blocked,
    nodata_reply,
    normalize_name,
    nxdomain_reply,
    probe_nonce,
    txt_reply,
)
from .safesearch import safesearch_target, youtube_target
from .upstream.base import Question, ResolveError, Resolver

log = logging.getLogger(__name__)

FIREFOX_CANARY = "use-application-dns.net"
TYPE_CNAME = int(dns.rdatatype.CNAME)
TYPE_SVCB = 64
TYPE_HTTPS = 65
MAX_BLOCK_TTL = 86400
#: Addresses kept per event for the query log.
MAX_EVENT_ANSWERS = 8

_IPV6_NULL = ipaddress.IPv6Address("::")


class PreferredIP(enum.Enum):
    AUTO = "auto"
    IPV4 = "ipv4"  # AAAA queries get NODATA
    IPV6 = "ipv6"  # A queries get NODATA when the name has an AAAA record


class Verdict(enum.Enum):
    FORWARDED = "forwarded"  # answered from an upstream (or the cache)
    BLOCKED = "blocked"
    LOCAL = "local"  # answered by the daemon without blocking (SafeSearch, canary, ...)
    FAILED = "failed"  # SERVFAIL


@dataclass(frozen=True, slots=True)
class Policy:
    """Everything a decision depends on. Immutable; swapped atomically on change."""

    matcher: FilterMatcher = field(default_factory=FilterMatcher)
    custom: CustomRuleSet = field(default_factory=CustomRuleSet)
    doh_blocklist: frozenset[str] = frozenset()  # empty: DoH blocking is off
    doh_watch: frozenset[str] = frozenset()  # DoH blocking off: count lookups (bypass warning)
    internal_allow: frozenset[str] = frozenset()  # exact names
    block_mode: BlockMode = BlockMode.NULL_IP
    block_ttl: int = DEFAULT_BLOCK_TTL
    preferred_ip: PreferredIP = PreferredIP.AUTO
    safesearch: bool = False
    youtube_restricted: bool = False
    cname_check: bool = True
    paused: bool = False
    pause_reason: str = "paused"  # or "trusted_network" (the query log's reason)

    def __post_init__(self) -> None:
        if not 0 <= self.block_ttl <= MAX_BLOCK_TTL:
            raise ValueError(f"block_ttl must be within 0..{MAX_BLOCK_TTL}")


@dataclass(slots=True)
class QueryEvent:
    """What happened to one query; feeds the query log and statistics."""

    name: str
    qtype: int
    verdict: Verdict
    reason: str = ""  # block reason (list ids, "custom", ...) or why it was allowed/answered
    rcode: int = 0
    upstream: str = ""
    cached: bool = False
    answers: tuple[str, ...] = ()
    elapsed_ms: float = 0.0
    tier: str = ""  # upstream tier; "ntp-rescue" means plain DNS for an NTP name (wrong clock)

    @property
    def blocked(self) -> bool:
        return self.verdict is Verdict.BLOCKED


Decision = tuple[dns.message.Message, "QueryEvent | None"]


class Pipeline:
    def __init__(self, resolver: Resolver, policy: Policy | None = None) -> None:
        self.resolver = resolver
        self.policy = policy if policy is not None else Policy()
        self.doh_lookups = 0  # lookups of known DoH servers while the DoH block is off (no names kept)
        self.doh_last = 0.0

    async def handle(self, query: Query) -> Decision:
        """Answer one validated query. Never raises (except cancellation)."""
        started = time.monotonic()
        policy = self.policy  # one consistent snapshot per query
        try:
            reply, event = await self._decide(query, policy)
        except Exception as exc:
            # Exception text may contain the query name: log the type only.
            log.error("internal error while answering a query: %s", type(exc).__name__)
            log.debug("internal error details", exc_info=True)
            reply = error_reply(query, dns.rcode.SERVFAIL)
            event = QueryEvent(query.name, query.qtype, Verdict.FAILED, "internal_error", int(dns.rcode.SERVFAIL))
        if event is not None:
            event.elapsed_ms = (time.monotonic() - started) * 1000.0
        return reply, event

    async def _decide(self, query: Query, policy: Policy) -> Decision:
        name, qtype = query.name, query.qtype
        if is_invalid_tld(name):
            nonce = probe_nonce(name)
            if nonce is not None:
                if qtype == TYPE_TXT:
                    return txt_reply(query, PROBE_ANSWER_PREFIX + nonce, ttl=0), None
                return nodata_reply(query, ttl=0), None
            return self._local(query, nxdomain_reply(query, policy.block_ttl), "invalid_tld")
        if name == FIREFOX_CANARY:
            return self._local(query, nxdomain_reply(query, policy.block_ttl), "doh_canary")
        if policy.paused:
            return await self._forward(query, policy, policy.pause_reason, filtered=False)
        if policy.preferred_ip is PreferredIP.IPV4 and qtype == TYPE_AAAA:
            return self._local(query, nodata_reply(query, policy.block_ttl), "preferred_ip")
        if name in policy.internal_allow:
            return await self._forward(query, policy, "internal_allow", filtered=False)
        if policy.doh_blocklist and entries_match(name, policy.doh_blocklist):
            return self._block(query, policy, "doh_bypass_protection")
        if policy.doh_watch and entries_match(name, policy.doh_watch):
            # An application resolves a DoH server: it may be about to bypass the filter.
            self.doh_lookups += 1
            self.doh_last = time.time()
        custom = policy.custom.verdict(name)
        if custom is CustomVerdict.ALLOW:
            return await self._forward(query, policy, "custom_allow", filtered=False)
        if custom is CustomVerdict.WHITELIST:
            return await self._forward(query, policy, "whitelist", filtered=False)
        if custom is CustomVerdict.BLOCK:
            return self._block(query, policy, "custom")
        if policy.safesearch or policy.youtube_restricted:
            answered = await self._safesearch(query, policy)
            if answered is not None:
                return answered
        match = policy.matcher.match(name)
        if match.blocked:
            return self._block(query, policy, match.reason)
        if policy.preferred_ip is PreferredIP.IPV6 and qtype == TYPE_A and await self._has_aaaa(query):
            return self._local(query, nodata_reply(query, policy.block_ttl), "preferred_ip")
        return await self._forward(query, policy, "", filtered=True)

    # --- outcomes -------------------------------------------------------------

    @staticmethod
    def _local(query: Query, reply: dns.message.Message, reason: str, answers: tuple[str, ...] = ()) -> Decision:
        return reply, QueryEvent(query.name, query.qtype, Verdict.LOCAL, reason, int(reply.rcode()), answers=answers)

    @staticmethod
    def _block(query: Query, policy: Policy, reason: str, upstream: str = "", tier: str = "") -> Decision:
        reply = blocked_reply(query, policy.block_mode, policy.block_ttl)
        return reply, QueryEvent(query.name, query.qtype, Verdict.BLOCKED, reason, int(reply.rcode()), upstream,
                                 tier=tier)

    async def _forward(self, query: Query, policy: Policy, reason: str, *, filtered: bool) -> Decision:
        try:
            resolution = await self.resolver.resolve(Question.of(query))
        except ResolveError:
            reply = error_reply(query, dns.rcode.SERVFAIL)
            return reply, QueryEvent(query.name, query.qtype, Verdict.FAILED, "upstream_failed", int(dns.rcode.SERVFAIL))
        message = resolution.message
        if filtered and policy.cname_check:
            cloaked = self._cname_block_reason(query, message, policy)
            if cloaked is not None:
                return self._block(query, policy, "cname:" + cloaked, resolution.upstream, resolution.tier)
        reply = forwarded_reply(query, message)
        verdict = Verdict.FORWARDED
        if is_upstream_blocked(message):
            verdict, reason = Verdict.BLOCKED, "upstream_dns"
        answers = tuple(address for address, _ in addresses(message)[:MAX_EVENT_ANSWERS])
        event = QueryEvent(query.name, query.qtype, verdict, reason, int(reply.rcode()), resolution.upstream,
                           resolution.cached, answers, tier=resolution.tier)
        return reply, event

    # --- helpers ----------------------------------------------------------------

    @staticmethod
    def _cname_block_reason(query: Query, message: dns.message.Message, policy: Policy) -> str | None:
        """Block reason for the first blocked CNAME target in the answer, if any.

        Each target is judged like a query of its own: the internal allowlist,
        custom allow and the whitelist exempt that target, a custom block or a
        filter list blocks it. Only the original name's own exemption (handled
        before forwarding) switches the whole check off.
        """
        for rrset in message.answer:
            if rrset.rdtype != TYPE_CNAME:
                continue
            for rdata in rrset:
                target = normalize_name(rdata.target)
                if not target or target == query.name or target in policy.internal_allow:
                    continue
                custom = policy.custom.verdict(target)
                if custom is CustomVerdict.BLOCK:
                    return "custom"
                if custom is not CustomVerdict.NONE:
                    continue
                match = policy.matcher.match(target)
                if match.blocked:
                    return match.reason
        return None

    async def _safesearch(self, query: Query, policy: Policy) -> Decision | None:
        target = safesearch_target(query.name) if policy.safesearch else None
        reason = "safesearch"
        if target is None and policy.youtube_restricted:
            target, reason = youtube_target(query.name), "youtube_restricted"
        if target is None:
            return None
        if query.qtype in (TYPE_AAAA, TYPE_HTTPS, TYPE_SVCB):
            # No IPv6 address or HTTPS hints that would bypass the rewrite.
            return self._local(query, nodata_reply(query, policy.block_ttl), reason)
        if query.qtype != TYPE_A:
            return None
        found = await self._target_addresses(target)
        if not found:
            return None  # resolution failed: continue like upstream does
        ttl = min(ttl for _, ttl in found)
        reply = address_reply(query, [address for address, _ in found], ttl)
        return self._local(query, reply, reason, tuple(address for address, _ in found[:MAX_EVENT_ANSWERS]))

    async def _target_addresses(self, target: str) -> list[tuple[str, int]]:
        try:
            resolution = await self.resolver.resolve(Question.make(target, TYPE_A))
        except ResolveError:
            return []
        return [(address, ttl) for address, ttl in addresses(resolution.message, TYPE_A) if address != "0.0.0.0"]

    async def _has_aaaa(self, query: Query) -> bool:
        """Port of upstream ``domainHasAAAA``: a non-null AAAA exists for the name."""
        try:
            resolution = await self.resolver.resolve(Question.make(query.qname, TYPE_AAAA))
        except ResolveError:
            return False
        return any(ipaddress.ip_address(address) != _IPV6_NULL for address, _ in addresses(resolution.message, TYPE_AAAA))
