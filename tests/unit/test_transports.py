"""Tests for the plain UDP, TCP and DoT upstream transports (loopback fakes)."""

import asyncio
import socket
import time

import dns.edns
import dns.flags
import dns.message
import dns.rcode
import pytest

from blockads_linux.daemon.upstream.base import Question, UpstreamError
from blockads_linux.daemon.upstream.dot import DotUpstream, make_tls_context
from blockads_linux.daemon.upstream.plain import UdpUpstream
from blockads_linux.daemon.upstream.tcp import StreamUpstream

from .upstreams import StreamServer, UdpServer, answer, default_handler, make_test_ca, server_tls_context


def run(coro):
    return asyncio.run(coro)


def q(name="clean.example", rdtype=1, **kw):
    return Question.make(name, rdtype, **kw)


def ips(message):
    return [r.address for rrset in message.answer for r in rrset if rrset.rdtype in (1, 28)]


# --- UDP --------------------------------------------------------------------


def test_udp_exchange_and_query_shape():
    async def body():
        server = await UdpServer().start()
        upstream = UdpUpstream("127.0.0.1", server.port)
        reply = await upstream.exchange(q("Clean.Example", dnssec_ok=True, checking_disabled=True))
        assert ips(reply) == ["192.0.2.1"]
        sent, wire, _ = server.queries[0]
        assert sent.flags & dns.flags.RD and sent.flags & dns.flags.CD
        assert sent.edns == 0 and sent.payload == 1232 and sent.ednsflags & dns.flags.DO
        assert not sent.options  # no ECS or anything else from the client
        assert str(sent.question[0].name) == "Clean.Example."
        server.close()

    run(body())


def test_udp_ignores_forged_and_mismatched_replies():
    def handler(query, wire):
        wrong_id = answer(query, ("A", "6.6.6.6"))
        wrong_id.id = (query.id + 1) % 65536
        other_question = dns.message.make_response(dns.message.make_query("evil.example", "A"))
        other_question.id = query.id
        return [wrong_id, other_question, b"\x00", answer(query, ("A", "192.0.2.1"))]

    async def body():
        server = await UdpServer(handler).start()
        reply = await UdpUpstream("127.0.0.1", server.port).exchange(q())
        assert ips(reply) == ["192.0.2.1"]
        server.close()

    run(body())


def test_udp_only_accepts_the_upstream_address():
    """A reply from another port never reaches the connected socket."""
    async def body():
        forger = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        forger.bind(("127.0.0.1", 0))

        async def handler(query, wire):
            client = server.queries[-1][2]
            forger.sendto(answer(query, ("A", "6.6.6.6")).to_wire(), client)
            await asyncio.sleep(0.1)
            return answer(query, ("A", "192.0.2.1"))

        server = await UdpServer(handler).start()
        reply = await UdpUpstream("127.0.0.1", server.port).exchange(q())
        assert ips(reply) == ["192.0.2.1"]
        server.close()
        forger.close()

    run(body())


def test_udp_garbage_with_our_id_fails_fast():
    async def body():
        server = await UdpServer(lambda query, wire: wire[:2] + b"\x81\x80\x00\x01" + b"\xff" * 20).start()
        started = time.monotonic()
        with pytest.raises(UpstreamError, match="undecodable"):
            await UdpUpstream("127.0.0.1", server.port, timeout=2).exchange(q())
        assert time.monotonic() - started < 1
        server.close()

    run(body())


def test_udp_timeout_and_refused():
    async def body():
        silent = await UdpServer(lambda query, wire: None).start()
        with pytest.raises(UpstreamError, match="timeout"):
            await UdpUpstream("127.0.0.1", silent.port, timeout=0.2).exchange(q())
        silent.close()
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.bind(("127.0.0.1", 0))
        closed_port = probe.getsockname()[1]
        probe.close()
        started = time.monotonic()
        with pytest.raises(UpstreamError, match="ConnectionRefused"):
            await UdpUpstream("127.0.0.1", closed_port, timeout=2).exchange(q())
        assert time.monotonic() - started < 1  # ICMP port unreachable, not a timeout

    run(body())


def test_udp_truncation_retries_over_tcp():
    def udp_handler(query, wire):
        return answer(query, flags=dns.flags.TC)

    def tcp_handler(query, wire):
        return answer(query, *[("TXT", f'"{i}"') for i in range(50)])

    async def body():
        udp = await UdpServer(udp_handler).start()
        tcp = await StreamServer(tcp_handler).start(port=udp.port)
        reply = await UdpUpstream("127.0.0.1", udp.port).exchange(q(rdtype=16))
        assert len(reply.answer[0]) == 50 and not reply.flags & dns.flags.TC
        assert len(udp.queries) == 1 and len(tcp.queries) == 1
        udp.close()
        tcp.close()

    run(body())


def test_question_with_scope_less_ipv6_label():
    upstream = UdpUpstream("2620:fe::fe")
    assert upstream.label == "udp://[2620:fe::fe]:53"


# --- TCP --------------------------------------------------------------------


def test_tcp_pipelining_out_of_order_on_one_connection():
    async def body():
        server = await StreamServer(reverse=True).start()
        upstream = StreamUpstream("127.0.0.1", server.port)
        names = [f"n{i}.example" for i in range(20)]
        replies = await asyncio.gather(*(upstream.exchange(q(name)) for name in names))
        assert [str(r.question[0].name) for r in replies] == [n + "." for n in names]
        assert server.connections == 1
        await upstream.close()
        server.close()

    run(body())


def test_tcp_reuse_and_idle_close():
    async def body():
        server = await StreamServer().start()
        upstream = StreamUpstream("127.0.0.1", server.port, idle_timeout=0.2)
        await upstream.exchange(q())
        await upstream.exchange(q())
        assert server.connections == 1
        await asyncio.sleep(0.4)  # our idle timer closes the connection
        await upstream.exchange(q())
        assert server.connections == 2
        await upstream.close()
        server.close()

    run(body())


def test_tcp_dead_reused_connection_is_retried_once():
    async def body():
        server = await StreamServer(close_after=1).start()  # the server hangs up after every reply
        upstream = StreamUpstream("127.0.0.1", server.port)
        for _ in range(3):
            assert ips(await upstream.exchange(q())) == ["192.0.2.1"]
        assert server.connections == 3
        await upstream.close()
        server.close()

    run(body())


def test_tcp_timeout_mismatch_and_refused():
    async def body():
        silent = await StreamServer(lambda query, wire: None).start()
        with pytest.raises(UpstreamError, match="timeout"):
            await StreamUpstream("127.0.0.1", silent.port, timeout=0.2).exchange(q())
        silent.close()

        def wrong_question(query, wire):
            reply = dns.message.make_response(dns.message.make_query("evil.example", "A"))
            reply.id = query.id
            return reply

        liar = await StreamServer(wrong_question).start()
        with pytest.raises(UpstreamError):
            await StreamUpstream("127.0.0.1", liar.port, timeout=1).exchange(q())
        liar.close()

        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        closed_port = probe.getsockname()[1]
        probe.close()
        with pytest.raises(UpstreamError, match="connect failed"):
            await StreamUpstream("127.0.0.1", closed_port).exchange(q())

    run(body())


# --- DoT --------------------------------------------------------------------


@pytest.fixture
def test_ca(tmp_path):
    pytest.importorskip("cryptography")
    return make_test_ca(tmp_path)


def test_dot_exchange_is_verified_and_padded(test_ca):
    ca, cert, key = test_ca

    async def body():
        server = await StreamServer(ssl_context=server_tls_context(cert, key, alpn=("dot",))).start()
        upstream = DotUpstream("127.0.0.1", "dns.test", server.port, ssl_context=make_tls_context(str(ca), ("dot",)))
        assert upstream.encrypted and upstream.label == "tls://dns.test"
        assert ips(await upstream.exchange(q())) == ["192.0.2.1"]
        _, wire, _ = server.queries[0]
        assert len(wire) % 128 == 0
        assert any(o.otype == dns.edns.PADDING for o in dns.message.from_wire(wire).options)
        await upstream.close()
        server.close()

    run(body())


def test_dot_rejects_wrong_name_and_unknown_ca(test_ca):
    ca, cert, key = test_ca

    async def body():
        server = await StreamServer(ssl_context=server_tls_context(cert, key)).start()
        wrong_name = DotUpstream("127.0.0.1", "other.test", server.port, ssl_context=make_tls_context(str(ca)))
        with pytest.raises(UpstreamError, match="certificate"):
            await wrong_name.exchange(q())
        system_store = DotUpstream("127.0.0.1", "dns.test", server.port)  # the test CA is not trusted
        with pytest.raises(UpstreamError, match="certificate"):
            await system_store.exchange(q())
        server.close()

    run(body())


def test_default_handler_shapes():
    query = dns.message.make_query("x.example", "MX")
    assert default_handler(query, b"").rcode() == dns.rcode.NOERROR


# --- DoH --------------------------------------------------------------------

from blockads_linux.daemon.upstream.doh import DohUpstream, parse_doh_url, pinned_tls_context  # noqa: E402

from .upstreams import DohServer  # noqa: E402


def doh_pair(test_ca, **server_kw):
    ca, cert, key = test_ca
    server = DohServer(server_tls_context(cert, key, alpn=("h2",)), **server_kw)
    return server, ca


def doh_upstream(server, ca, name="dns.test", **kw):
    return DohUpstream(f"https://{name}:{server.port}/dns-query", "127.0.0.1",
                       cafile=str(ca), **kw)


def test_parse_doh_url():
    assert parse_doh_url("https://dns.quad9.net/dns-query") == ("dns.quad9.net", 443, "/dns-query")
    assert parse_doh_url("https://dns.google/dns-query{?dns}") == ("dns.google", 443, "/dns-query")
    assert parse_doh_url("https://doh.example:8443") == ("doh.example", 8443, "/dns-query")
    for bad in ("http://dns.example/dns-query", "https://user:pw@dns.example/", "https:///dns-query"):
        with pytest.raises(ValueError):
            parse_doh_url(bad)


def test_doh_exchange_over_http2(test_ca):
    def respond(query, request):
        reply = answer(query, ("A", "192.0.2.1")).to_wire()
        return 200, {"content-type": "application/dns-message", "set-cookie": "track=me"}, reply

    async def body():
        server, ca = doh_pair(test_ca, respond=respond)
        await server.start()
        upstream = doh_upstream(server, ca)
        assert upstream.encrypted
        for _ in range(2):
            assert ips(await upstream.exchange(q("Clean.Example"))) == ["192.0.2.1"]
        assert server.connections == 1  # the HTTP/2 connection is reused
        first, second = server.requests
        headers = first["headers"]
        assert headers[":method"] == "POST" and headers[":path"] == "/dns-query"
        assert headers[":authority"] == f"dns.test:{server.port}"
        assert headers["content-type"] == "application/dns-message"
        assert "user-agent" not in headers and headers.get("accept-encoding") == "identity"
        assert "cookie" not in second["headers"]  # Set-Cookie is ignored
        sent = dns.message.from_wire(first["body"])
        assert sent.id == 0 and len(first["body"]) % 128 == 0
        await upstream.close()
        server.close()

    run(body())


@pytest.mark.parametrize(
    ("override", "error"),
    [
        ((500, {"content-type": "application/dns-message"}, b""), "HTTP 500"),
        ((302, {"location": "https://evil.example/"}, b""), "HTTP 302"),
        ((200, {"content-type": "text/html"}, b"<html>"), "content type"),
        ((200, {"content-type": "application/dns-message"}, b"\0" * 70000), "too large"),
        ((200, {"content-type": "application/dns-message"}, b"\0" * 40), "not a reply"),
    ],
)
def test_doh_rejects_bad_replies(test_ca, override, error):
    async def body():
        server, ca = doh_pair(test_ca, respond=lambda query, request: override)
        await server.start()
        upstream = doh_upstream(server, ca)
        with pytest.raises(UpstreamError, match=error):
            await upstream.exchange(q())
        await upstream.close()
        server.close()

    run(body())


def test_doh_question_mismatch(test_ca):
    def respond(query, request):
        other = dns.message.make_response(dns.message.make_query("evil.example", "A"))
        other.id = 0
        return 200, {"content-type": "application/dns-message"}, other.to_wire()

    async def body():
        server, ca = doh_pair(test_ca, respond=respond)
        await server.start()
        upstream = doh_upstream(server, ca)
        with pytest.raises(UpstreamError, match="question"):
            await upstream.exchange(q())
        await upstream.close()
        server.close()

    run(body())


def test_doh_tls_name_is_pinned_in_the_context():
    """httpcore < 0.17 ignores sni_hostname and passes the bootstrap IP as server_hostname."""
    import ssl

    context = pinned_tls_context("dns.test")
    assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
    tls = context.wrap_bio(ssl.MemoryBIO(), ssl.MemoryBIO(), server_hostname="127.0.0.1")
    assert tls.server_hostname == "dns.test"
    with socket.socket() as raw:
        assert context.wrap_socket(raw, server_hostname="9.9.9.9", do_handshake_on_connect=False) \
            .server_hostname == "dns.test"
    other = DohUpstream("https://other.test/dns-query", "127.0.0.1")
    assert other._ssl_context.pinned_name == "other.test"  # one context per upstream identity


def test_doh_certificate_and_timeout(test_ca):
    async def body():
        server, ca = doh_pair(test_ca, delay=1.0)
        await server.start()
        wrong_name = doh_upstream(server, ca, name="other.test")
        with pytest.raises(UpstreamError, match="certificate"):
            await wrong_name.exchange(q())
        untrusted = DohUpstream(f"https://dns.test:{server.port}/dns-query", "127.0.0.1")
        with pytest.raises(UpstreamError, match="certificate"):
            await untrusted.exchange(q())
        slow = doh_upstream(server, ca, timeout=0.3)
        started = time.monotonic()
        with pytest.raises(UpstreamError, match="timeout"):
            await slow.exchange(q())
        assert time.monotonic() - started < 1
        for upstream in (wrong_name, untrusted, slow):
            await upstream.close()
        server.close()

    run(body())


# --- certificate time errors (a wrong clock) ----------------------------------

from blockads_linux.daemon.upstream.base import CertificateTimeError  # noqa: E402


@pytest.mark.parametrize(("valid", "message"), [((24, 48), "not yet valid"), ((-48, -24), "expired")])
def test_certificate_time_errors_are_typed(tmp_path, valid, message):
    pytest.importorskip("cryptography")
    ca, cert, key = make_test_ca(tmp_path, valid=valid)

    async def body():
        dot_server = await StreamServer(ssl_context=server_tls_context(cert, key)).start()
        doh_server = await DohServer(server_tls_context(cert, key, alpn=("h2",))).start()
        dot = DotUpstream("127.0.0.1", "dns.test", dot_server.port, ssl_context=make_tls_context(str(ca)))
        doh = DohUpstream(f"https://dns.test:{doh_server.port}/dns-query", "127.0.0.1",
                          cafile=str(ca))
        for upstream in (dot, doh):
            with pytest.raises(CertificateTimeError, match=message):
                await upstream.exchange(q())
            await upstream.close()
        dot_server.close()
        doh_server.close()

    run(body())


def test_other_certificate_errors_are_not_time_errors(test_ca):
    ca, cert, key = test_ca

    async def body():
        server = await StreamServer(ssl_context=server_tls_context(cert, key)).start()
        upstream = DotUpstream("127.0.0.1", "other.test", server.port, ssl_context=make_tls_context(str(ca)))
        with pytest.raises(UpstreamError) as info:
            await upstream.exchange(q())
        assert not isinstance(info.value, CertificateTimeError)
        server.close()

    run(body())
