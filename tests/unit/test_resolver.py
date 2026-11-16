"""Tests for daemon.cache and daemon.resolver (the forwarder)."""

import asyncio

import dns.flags
import dns.rcode
import dns.rrset
import pytest

from blockads_linux.daemon.cache import DnsCache, age_message, cache_ttl
from blockads_linux.daemon.resolver import Forwarder, Tier
from blockads_linux.daemon.upstream.base import Question, ResolveError, UpstreamError

from .upstreams import answer


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def reply_for(question, *records, rcode=None, ttl=300, soa=None, flags=0):
    reply = answer(question.to_message(0), *records, rcode=rcode, ttl=ttl, flags=flags)
    if soa is not None:
        soa_ttl, minimum = soa
        reply.authority.append(dns.rrset.from_text("example.", soa_ttl, "IN", "SOA", f"ns. host. 1 2 3 4 {minimum}"))
    return reply


def q(name="clean.example", rdtype=1, **kw):
    return Question.make(name, rdtype, **kw)


def ips(message):
    return [r.address for rrset in message.answer for r in rrset if rrset.rdtype in (1, 28)]


# --- cache ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("make", "expected"),
    [
        (lambda: reply_for(q(), ("A", "192.0.2.1"), ttl=300), 300),
        (lambda: reply_for(q(), ("A", "192.0.2.1"), ttl=10**6), 86400),  # capped
        (lambda: reply_for(q(), ("A", "192.0.2.1"), ttl=0), 0),
        (lambda: reply_for(q(), rcode=dns.rcode.NXDOMAIN, soa=(900, 60)), 60),
        (lambda: reply_for(q(), soa=(30, 600)), 30),  # NODATA
        (lambda: reply_for(q(), rcode=dns.rcode.NXDOMAIN, soa=(86400, 86400)), 3600),  # negative cap
        (lambda: reply_for(q(), rcode=dns.rcode.NXDOMAIN), 0),  # no SOA: not cacheable
        (lambda: reply_for(q()), 0),  # NODATA without SOA
        (lambda: reply_for(q(), rcode=dns.rcode.SERVFAIL, soa=(60, 60)), 0),
        (lambda: reply_for(q(), rcode=dns.rcode.REFUSED), 0),
        (lambda: reply_for(q(), ("A", "192.0.2.1"), flags=dns.flags.TC), 0),
    ],
)
def test_cache_ttl(make, expected):
    assert cache_ttl(make()) == expected


def test_cache_ages_expires_and_isolates_copies():
    clock = Clock()
    cache = DnsCache(clock=clock)
    message = reply_for(q(), ("A", "192.0.2.1"), ttl=100)
    assert cache.put("k", message, message.to_wire(), "up", "fallback")
    clock.now += 30.7
    copy, label, tier = cache.get("k")
    assert (label, tier) == ("up", "fallback") and copy.answer[0].ttl == 70
    copy.answer[0].ttl = 5  # callers may change their copy freely
    assert cache.get("k")[0].answer[0].ttl == 70
    clock.now += 70
    assert cache.get("k") is None and len(cache) == 0
    assert (cache.hits, cache.misses) == (2, 1)


def test_cache_lru_eviction_and_uncacheable():
    cache = DnsCache(max_entries=2, clock=Clock())
    for key in "abc":
        message = reply_for(q(), ("A", "192.0.2.1"))
        cache.put(key, message, message.to_wire())
        if key == "b":
            cache.get("a")  # "a" becomes most recently used
    assert cache.get("b") is None and cache.get("a") is not None and cache.get("c") is not None
    servfail = reply_for(q(), rcode=dns.rcode.SERVFAIL)
    assert not cache.put("d", servfail, servfail.to_wire())
    assert not DnsCache(max_entries=0).put("e", servfail, servfail.to_wire())


def test_age_message_floors_at_zero():
    message = reply_for(q(), ("A", "192.0.2.1"), ttl=10, soa=(5, 5))
    age_message(message, 7)
    assert message.answer[0].ttl == 3 and message.authority[0].ttl == 0


# --- forwarder ----------------------------------------------------------------


class Scripted:
    """An upstream whose replies come from ``script(question)`` (an Exception is raised)."""

    def __init__(self, label, script=None, *, delay=0.0, encrypted=False):
        self.label = label
        self.encrypted = encrypted
        self.script = script or (lambda question: reply_for(question, ("A", "192.0.2.1")))
        self.delay = delay
        self.calls = 0
        self.closed = False

    async def exchange(self, question):
        self.calls += 1
        if self.delay:
            await asyncio.sleep(self.delay)
        result = self.script(question)
        if isinstance(result, Exception):
            raise result
        return result

    async def close(self):
        self.closed = True


def failing(label="dead"):
    return Scripted(label, lambda question: UpstreamError("timeout"))


def run(coro):
    return asyncio.run(coro)


def test_cache_hit_skips_the_upstream():
    async def body():
        clock = Clock()
        upstream = Scripted("doh")
        forwarder = Forwarder([Tier("configured", [upstream])], cache=DnsCache(clock=clock), clock=clock)
        first = await forwarder.resolve(q())
        clock.now += 100
        second = await forwarder.resolve(q("CLEAN.example"))  # the key is case-insensitive
        assert not first.cached and second.cached and second.upstream == "doh"
        assert upstream.calls == 1 and second.message.answer[0].ttl == 200
        assert first.message is not second.message

    run(body())


def test_identical_queries_in_flight_are_merged():
    async def body():
        upstream = Scripted("doh", delay=0.05)
        forwarder = Forwarder([Tier("configured", [upstream])], cache=DnsCache(max_entries=0))
        results = await asyncio.gather(*(forwarder.resolve(q()) for _ in range(10)))
        assert upstream.calls == 1
        assert len({id(r.message) for r in results}) == 10  # everyone gets a private copy
        await forwarder.resolve(q(dnssec_ok=True))  # DO is part of the key
        assert upstream.calls == 2

    run(body())


def test_a_waiter_giving_up_does_not_cancel_the_others():
    async def body():
        upstream = Scripted("doh", delay=0.1)
        forwarder = Forwarder([Tier("configured", [upstream])])
        impatient = asyncio.ensure_future(forwarder.resolve(q()))
        patient = asyncio.ensure_future(forwarder.resolve(q()))
        await asyncio.sleep(0.02)
        impatient.cancel()
        assert ips((await patient).message) == ["192.0.2.1"]

    run(body())


def test_fallback_tier_and_active_upstream():
    async def body():
        primary, fallback = failing("doh"), Scripted("plain")
        forwarder = Forwarder([Tier("configured", [primary]), Tier("fallback", [fallback])])
        result = await forwarder.resolve(q())
        assert result.upstream == "plain" and forwarder.active.tier == "fallback"
        health = {h.label: h for h in forwarder.health}
        assert health["doh"].failures == 1 and health["doh"].last_error == "timeout"

    run(body())


def test_circuit_breaker_skips_then_retries():
    async def body():
        clock = Clock()
        primary, fallback = failing("doh"), Scripted("plain")
        forwarder = Forwarder([Tier("configured", [primary]), Tier("fallback", [fallback])],
                              cache=DnsCache(max_entries=0), clock=clock)
        for _ in range(5):
            await forwarder.resolve(q())
        assert primary.calls == 3 and fallback.calls == 5  # skipped after 3 failures
        clock.now += 31
        await forwarder.resolve(q())
        assert primary.calls == 4  # half-open: one more try...
        await forwarder.resolve(q())
        assert primary.calls == 4  # ...which failed, so it is skipped again
        forwarder.flush()
        await forwarder.resolve(q())
        assert primary.calls == 5

    run(body())


def test_everything_skipped_is_still_tried():
    async def body():
        clock = Clock()
        flaky_answers = iter([UpstreamError("down")] * 3 + [None])

        def script(question):
            outcome = next(flaky_answers)
            return outcome if outcome is not None else reply_for(question, ("A", "192.0.2.1"))

        upstream = Scripted("only", script)
        forwarder = Forwarder([Tier("configured", [upstream])], cache=DnsCache(max_entries=0), clock=clock)
        for _ in range(3):
            with pytest.raises(ResolveError, match="down"):
                await forwarder.resolve(q())
        assert ips((await forwarder.resolve(q())).message) == ["192.0.2.1"]

    run(body())


def test_errors_and_deadline():
    async def body():
        forwarder = Forwarder([Tier("configured", [failing("a")]), Tier("fallback", [failing("b")])])
        with pytest.raises(ResolveError, match="a: timeout; b: timeout"):
            await forwarder.resolve(q())
        with pytest.raises(ResolveError, match="no upstream"):
            await Forwarder([]).resolve(q())
        slow = Forwarder([Tier("configured", [Scripted("slow", delay=5)])], deadline=0.1)
        with pytest.raises(ResolveError, match="deadline"):
            await slow.resolve(q())

    run(body())


def test_failures_are_not_cached_and_servfail_is_passed_on():
    async def body():
        outcomes = iter([UpstreamError("down"), None])

        def script(question):
            outcome = next(outcomes)
            return outcome if outcome is not None else reply_for(question, ("A", "192.0.2.1"))

        upstream = Scripted("doh", script)
        forwarder = Forwarder([Tier("configured", [upstream])])
        with pytest.raises(ResolveError):
            await forwarder.resolve(q())
        assert ips((await forwarder.resolve(q())).message) == ["192.0.2.1"]

        servfail = Scripted("doh", lambda question: reply_for(question, rcode=dns.rcode.SERVFAIL))
        fallback = Scripted("plain")
        forwarder = Forwarder([Tier("configured", [servfail]), Tier("fallback", [fallback])])
        result = await forwarder.resolve(q())
        assert result.message.rcode() == dns.rcode.SERVFAIL and fallback.calls == 0

    run(body())


def test_negative_answers_are_cached():
    async def body():
        upstream = Scripted("doh", lambda question: reply_for(question, rcode=dns.rcode.NXDOMAIN, soa=(60, 60)))
        forwarder = Forwarder([Tier("configured", [upstream])])
        await forwarder.resolve(q("nope.example"))
        again = await forwarder.resolve(q("nope.example"))
        assert again.cached and again.message.rcode() == dns.rcode.NXDOMAIN and upstream.calls == 1

    run(body())


def test_close_fails_pending_lookups_and_closes_upstreams():
    async def body():
        upstream = Scripted("doh", delay=5)
        forwarder = Forwarder([Tier("configured", [upstream])])
        pending = asyncio.ensure_future(forwarder.resolve(q()))
        await asyncio.sleep(0.02)
        await forwarder.close()
        with pytest.raises(ResolveError, match="shutting down"):
            await pending
        assert upstream.closed

    run(body())


def test_reset_flushes_and_drops_pools_but_keeps_working():
    async def body():
        upstream = Scripted("doh")
        forwarder = Forwarder([Tier("configured", [upstream])])
        await forwarder.resolve(q())
        await forwarder.reset()
        assert upstream.closed and len(forwarder.cache) == 0
        result = await forwarder.resolve(q())
        assert not result.cached and upstream.calls == 2

    run(body())


def test_reset_with_real_transports_reconnects(tmp_path):
    """DoH and TCP upstreams must work again after their pools are dropped."""
    from blockads_linux.daemon.upstream.doh import DohUpstream
    from blockads_linux.daemon.upstream.tcp import StreamUpstream

    from .upstreams import DohServer, StreamServer, make_test_ca, server_tls_context

    pytest.importorskip("cryptography")
    ca, cert, key = make_test_ca(tmp_path)

    async def body():
        doh_server = await DohServer(server_tls_context(cert, key, alpn=("h2",))).start()
        tcp_server = await StreamServer().start()
        doh = DohUpstream(f"https://dns.test:{doh_server.port}/dns-query", "127.0.0.1", cafile=str(ca))
        tcp = StreamUpstream("127.0.0.1", tcp_server.port)
        forwarder = Forwarder([Tier("configured", [doh]), Tier("fallback", [tcp])], cache=DnsCache(max_entries=0))
        await forwarder.resolve(q())
        await forwarder.reset()
        assert ips((await forwarder.resolve(q())).message) == ["192.0.2.1"]
        assert doh_server.connections == 2  # a new pool after the reset
        await doh.exchange(q()) and await tcp.exchange(q())
        await forwarder.close()
        doh_server.close()
        tcp_server.close()

    run(body())


# --- clock rescue: plain DNS for NTP names only ("encrypted only") -------------

from blockads_linux.daemon.upstream.base import CertificateTimeError  # noqa: E402


def wrong_clock(label="doh"):
    return Scripted(label, lambda question: CertificateTimeError("TLS certificate rejected: certificate is not yet valid"),
                    encrypted=True)


def ntp(name):
    return name == "pool.ntp.org" or name.endswith(".pool.ntp.org")


def rescue_forwarder(primary, clock=None, **kw):
    plain = Scripted("udp://9.9.9.9")
    clock = clock or Clock()
    forwarder = Forwarder([Tier("configured", [primary])], rescue=[Tier("ntp-rescue", [plain])], ntp_names=ntp,
                          cache=DnsCache(max_entries=0), clock=clock, **kw)
    return forwarder, plain


def test_ntp_names_get_plain_dns_when_the_clock_is_wrong():
    async def body():
        forwarder, plain = rescue_forwarder(wrong_clock())
        result = await forwarder.resolve(q("2.arch.pool.ntp.org"))
        assert ips(result.message) == ["192.0.2.1"] and result.tier == "ntp-rescue"
        assert result.upstream == "udp://9.9.9.9" and forwarder.clock_suspect
        aaaa = await forwarder.resolve(q("2.arch.pool.ntp.org", 28))
        assert aaaa.tier == "ntp-rescue"
        assert plain.calls == 2

    run(body())


def test_everything_else_stays_encrypted_only():
    async def body():
        forwarder, plain = rescue_forwarder(wrong_clock())
        for question in (q("example.com"), q("pool.ntp.org", 15), q("evilpool.ntp.org"), q("pool.ntp.org.evil.example")):
            with pytest.raises(ResolveError, match="not yet valid"):
                await forwarder.resolve(question)
        assert plain.calls == 0

    run(body())


def test_no_rescue_without_a_certificate_time_error():
    async def body():
        forwarder, plain = rescue_forwarder(failing("doh"))  # a timeout, not the clock
        with pytest.raises(ResolveError, match="timeout"):
            await forwarder.resolve(q("pool.ntp.org"))
        assert plain.calls == 0 and not forwarder.clock_suspect

    run(body())


def test_rescue_only_after_the_encrypted_tier_failed():
    async def body():
        forwarder, plain = rescue_forwarder(Scripted("doh", encrypted=True))
        forwarder.clock_error_at = 0.0  # even with a stale suspicion...
        result = await forwarder.resolve(q("pool.ntp.org"))
        assert result.tier == "configured" and plain.calls == 0  # ...a working DoH is used

    run(body())


def test_clock_suspicion_expires_and_survives_skipped_upstreams():
    async def body():
        clock = Clock()
        outcomes = iter([CertificateTimeError("expired")] + [UpstreamError("timeout")] * 10)
        primary = Scripted("doh", lambda question: next(outcomes), encrypted=True)
        forwarder, plain = rescue_forwarder(primary, clock=clock, clock_window=300)
        await forwarder.resolve(q("pool.ntp.org"))  # certificate time error -> rescue
        # Later failures are timeouts, but the clock error is still recent.
        clock.now += 200
        assert (await forwarder.resolve(q("pool.ntp.org"))).tier == "ntp-rescue"
        clock.now += 200  # 400 s after the certificate error: the window has passed
        with pytest.raises(ResolveError):
            await forwarder.resolve(q("pool.ntp.org"))
        forwarder.clock_error_at = clock.now
        forwarder.flush()  # a network change forgets the suspicion
        assert not forwarder.clock_suspect

    run(body())


def test_rescue_answers_keep_their_tier_in_the_cache():
    async def body():
        plain = Scripted("udp://9.9.9.9")
        forwarder = Forwarder([Tier("configured", [wrong_clock()])], rescue=[Tier("ntp-rescue", [plain])],
                              ntp_names=ntp)
        await forwarder.resolve(q("0.pool.ntp.org"))
        cached = await forwarder.resolve(q("0.pool.ntp.org"))
        assert cached.cached and cached.tier == "ntp-rescue" and plain.calls == 1

    run(body())
