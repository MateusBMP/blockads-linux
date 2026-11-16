"""The whole resolver chain in one process: client -> DnsServer -> Pipeline ->
Forwarder -> real transports -> fake upstreams on loopback. Plus fuzzing of
upstream replies, which are untrusted input."""

import asyncio
import random
import socket

import dns.flags
import dns.message
import dns.rcode
import pytest

from blockads_linux.daemon.cache import DnsCache
from blockads_linux.daemon.pipeline import Pipeline, Policy, Verdict
from blockads_linux.daemon.resolver import Forwarder, Tier
from blockads_linux.daemon.server import DnsServer, bind_sockets
from blockads_linux.daemon.upstream.base import Question, UpstreamError, check_response
from blockads_linux.daemon.upstream.doh import DohUpstream
from blockads_linux.daemon.upstream.plain import UdpUpstream
from blockads_linux.filters.custom_rules import CustomRuleSet, parse_rules

from .upstreams import DohServer, StreamServer, UdpServer, answer, make_test_ca, server_tls_context


async def udp_query(port, wire):
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    sock.connect(("127.0.0.1", port))
    try:
        await loop.sock_sendall(sock, wire)
        return await asyncio.wait_for(loop.sock_recv(sock, 65535), 5)
    finally:
        sock.close()


async def tcp_query(port, wire):
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        writer.write(len(wire).to_bytes(2, "big") + wire)
        size = int.from_bytes(await asyncio.wait_for(reader.readexactly(2), 5), "big")
        return await reader.readexactly(size)
    finally:
        writer.close()


def handler(query, wire):
    name = str(query.question[0].name).lower()
    rdtype = query.question[0].rdtype
    if name == "big.example." and rdtype == 16:
        return answer(query, *[("TXT", '"%s"' % ("t" * 100 + str(i))) for i in range(30)])
    if name == "cloaked.example.":
        return answer(query, ("cloaked.example.", "CNAME", "edge.tracker.example."),
                      ("edge.tracker.example.", "A", "192.0.2.77"))
    if rdtype == 1:
        return answer(query, ("A", "192.0.2.1"))
    return answer(query)


def udp_handler(query, wire):
    reply = handler(query, wire)
    if len(reply.to_wire(max_size=65535)) > 1232:  # what a real server does over UDP
        reply = answer(query, flags=dns.flags.TC)
    return reply


def test_full_chain_over_plain_dns():
    policy = Policy(custom=CustomRuleSet.build(parse_rules("tracker.example")))
    events = []

    async def body():
        udp = await UdpServer(udp_handler).start()
        tcp = await StreamServer(handler).start(port=udp.port)
        forwarder = Forwarder([Tier("configured", [UdpUpstream("127.0.0.1", udp.port)])], cache=DnsCache())
        server = DnsServer(Pipeline(forwarder, policy), on_event=events.append)
        for _ in range(20):
            try:
                await server.start(bind_sockets("127.0.0.1", 0))
                break
            except OSError:
                continue
        port = server.addresses[0][1][1]
        try:
            # 0x20: two clients, different case, one cached answer, each sees its own case.
            first = dns.message.from_wire(await udp_query(port, dns.message.make_query("WwW.Example.COM", "A").to_wire()))
            second = dns.message.from_wire(await udp_query(port, dns.message.make_query("www.EXAMPLE.com", "A").to_wire()))
            assert str(first.question[0].name) == "WwW.Example.COM." and str(first.answer[0].name) == "WwW.Example.COM."
            assert str(second.question[0].name) == "www.EXAMPLE.com." and str(second.answer[0].name) == "www.EXAMPLE.com."
            assert len(udp.queries) == 1  # the second came from the cache

            # Upstream truncates over UDP -> the forwarder retries over TCP; our UDP
            # client gets TC (too big for 512 bytes), our TCP client gets everything.
            big = dns.message.make_query("big.example", "TXT").to_wire()
            short = dns.message.from_wire(await udp_query(port, big))
            assert short.flags & dns.flags.TC and not short.answer
            full = dns.message.from_wire(await tcp_query(port, big))
            assert len(full.answer[0]) == 30 and not full.flags & dns.flags.TC
            assert len(tcp.queries) == 1  # the TCP client's query was served from the cache

            # CNAME cloaking through a real upstream answer.
            cloaked = dns.message.from_wire(await udp_query(port, dns.message.make_query("cloaked.example", "A").to_wire()))
            assert [r.address for r in cloaked.answer[0]] == ["0.0.0.0"]
        finally:
            await server.close()
            await forwarder.close()
            udp.close()
            tcp.close()

    asyncio.run(body())
    reasons = [(e.verdict, e.reason, e.cached) for e in events]
    assert reasons[0] == (Verdict.FORWARDED, "", False) and reasons[1] == (Verdict.FORWARDED, "", True)
    assert reasons[-1] == (Verdict.BLOCKED, "cname:custom", False)


def test_full_chain_over_doh(tmp_path):
    pytest.importorskip("cryptography")
    ca, cert, key = make_test_ca(tmp_path)

    async def body():
        doh = await DohServer(server_tls_context(cert, key, alpn=("h2",)), handler=handler).start()
        upstream = DohUpstream(f"https://dns.test:{doh.port}/dns-query", "127.0.0.1",
                               cafile=str(ca))
        forwarder = Forwarder([Tier("configured", [upstream])])
        pipeline = Pipeline(forwarder)
        from blockads_linux.daemon.responses import parse_query, render

        results = await asyncio.gather(*(
            pipeline.handle(parse_query(dns.message.make_query(f"n{i}.example", "A").to_wire())) for i in range(25)
        ))
        for reply, event in results:
            assert [r.address for r in dns.message.from_wire(render(reply)).answer[0]] == ["192.0.2.1"]
            assert event.upstream.startswith("https://dns.test") and event.verdict is Verdict.FORWARDED
        assert doh.connections == 1 and len(doh.requests) == 25  # one HTTP/2 connection, 25 streams
        await forwarder.close()
        doh.close()

    asyncio.run(body())


def test_fuzzed_upstream_replies_only_raise_upstream_errors():
    rng = random.Random(99)
    question = Question.make("www.example.com", 1, dnssec_ok=True)
    query = question.to_message(0x1234)
    seeds = [
        answer(query, ("A", "192.0.2.1"), ("A", "192.0.2.2")).to_wire(),
        answer(query, ("www.example.com.", "CNAME", "x.example.net."), ("x.example.net.", "A", "192.0.2.3")).to_wire(),
        answer(query, rcode=dns.rcode.NXDOMAIN).to_wire(),
    ]
    accepted = 0
    for _ in range(5000):
        wire = bytearray(rng.choice(seeds))
        for _ in range(rng.randint(1, 8)):
            action = rng.random()
            if action < 0.7:
                wire[rng.randrange(len(wire))] = rng.randrange(256)
            elif action < 0.85:
                wire.insert(rng.randrange(len(wire) + 1), rng.randrange(256))
            else:
                del wire[rng.randrange(len(wire)) :]
                if len(wire) < 2:
                    wire = bytearray(b"\x12\x34")
        try:
            message = check_response(question, 0x1234, bytes(wire))
        except UpstreamError:
            continue
        accepted += 1
        # Whatever was accepted must be usable downstream.
        message.to_wire()
    assert accepted > 0
