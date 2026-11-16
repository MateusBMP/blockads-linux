"""Tests for daemon.server and daemon.sdnotify (real sockets on loopback)."""

import asyncio
import contextlib
import os
import random
import socket
import subprocess
import sys

import dns.flags
import dns.message
import dns.opcode
import dns.rcode

from blockads_linux.daemon import sdnotify
from blockads_linux.daemon.pipeline import Pipeline, Policy, Verdict
from blockads_linux.daemon.server import DnsServer, bind_sockets
from blockads_linux.filters.custom_rules import CustomRuleSet, parse_rules

from .fakes import DEFAULT_A, FakeResolver


def bind_free():
    for _ in range(20):
        try:
            return bind_sockets("127.0.0.1", 0)
        except OSError:  # the UDP port's TCP twin was taken: try another
            continue
    raise RuntimeError("no free port")


@contextlib.asynccontextmanager
async def running(pipeline=None, **kw):
    server = DnsServer(pipeline or Pipeline(FakeResolver()), **kw)
    await server.start(bind_free())
    port = server.addresses[0][1][1]
    try:
        yield server, port
    finally:
        await server.close()


async def udp_ask(port, wire, timeout=2.0):
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    sock.connect(("127.0.0.1", port))
    try:
        await loop.sock_sendall(sock, wire)
        return await asyncio.wait_for(loop.sock_recv(sock, 65535), timeout)
    except TimeoutError:
        return None
    finally:
        sock.close()


async def tcp_ask(port, *wires, timeout=2.0):
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        writer.write(b"".join(len(w).to_bytes(2, "big") + w for w in wires))
        await writer.drain()
        replies = []
        for _ in wires:
            size = int.from_bytes(await asyncio.wait_for(reader.readexactly(2), timeout), "big")
            replies.append(await asyncio.wait_for(reader.readexactly(size), timeout))
        return replies
    finally:
        writer.close()


def query_wire(name="clean.example", rdtype="A", qid=0x1234, **kw):
    message = dns.message.make_query(name, rdtype, **kw)
    message.id = qid
    return message.to_wire()


def ips(wire):
    reply = dns.message.from_wire(wire)
    return [r.address for rrset in reply.answer if rrset.rdtype in (1, 28) for r in rrset]


def run(coro):
    return asyncio.run(coro)


def test_udp_and_tcp_forward_and_block():
    """Upstream TestStartStandalone: forward and block over both transports."""
    policy = Policy(custom=CustomRuleSet.build(parse_rules("blocked.example")))
    events = []

    async def body():
        async with running(Pipeline(FakeResolver(), policy), on_event=events.append) as (server, port):
            assert ips(await udp_ask(port, query_wire())) == [DEFAULT_A]
            assert ips(await udp_ask(port, query_wire("blocked.example"))) == ["0.0.0.0"]
            forward, block = await tcp_ask(port, query_wire(), query_wire("blocked.example"))
            assert ips(forward) == [DEFAULT_A] and ips(block) == ["0.0.0.0"]
            assert server.stats.answered == 4

    run(body())
    assert [e.verdict for e in events] == [Verdict.FORWARDED, Verdict.BLOCKED] * 2


def test_tcp_pipelining_answers_every_query():
    async def body():
        async with running() as (_, port):
            wires = [query_wire(f"n{i}.example", qid=i) for i in range(10)]
            replies = await tcp_ask(port, *wires)
            assert sorted(dns.message.from_wire(r).id for r in replies) == list(range(10))

    run(body())


def test_invalid_input_handling():
    async def body():
        async with running() as (server, port):
            response = dns.message.make_response(dns.message.make_query("x.example", "A")).to_wire()
            assert await udp_ask(port, response, timeout=0.3) is None  # never answer a response
            assert await udp_ask(port, b"\x00\x01", timeout=0.3) is None  # runt
            notify = bytearray(query_wire())
            notify[2] = (notify[2] & 0x87) | (dns.opcode.NOTIFY << 3)
            reply = await udp_ask(port, bytes(notify))
            assert reply[3] & 0xF == dns.rcode.NOTIMP
            assert server.stats.invalid == 3
            # still serving
            assert ips(await udp_ask(port, query_wire())) == [DEFAULT_A]

    run(body())


def test_udp_truncation_and_tcp_full_answer():
    records = [("TXT", '"%s"' % ("x" * 200 + str(i))) for i in range(20)]
    resolver = FakeResolver(answers={("big.example", "TXT"): records})

    async def body():
        async with running(Pipeline(resolver)) as (_, port):
            short = dns.message.from_wire(await udp_ask(port, query_wire("big.example", "TXT")))
            assert short.flags & dns.flags.TC and not short.answer
            edns = dns.message.from_wire(await udp_ask(port, query_wire("big.example", "TXT", use_edns=0, payload=4096)))
            assert edns.flags & dns.flags.TC  # still over our 1232-byte maximum
            (full,) = await tcp_ask(port, query_wire("big.example", "TXT"))
            full = dns.message.from_wire(full)
            assert not full.flags & dns.flags.TC and len(full.answer[0]) == 20

    run(body())


def test_internal_error_gets_servfail():
    class Broken(Pipeline):
        async def handle(self, query):
            raise RuntimeError("boom")

    async def body():
        async with running(Broken(FakeResolver())) as (server, port):
            reply = await udp_ask(port, query_wire())
            assert reply[:2] == b"\x12\x34" and reply[3] & 0xF == dns.rcode.SERVFAIL
            (reply,) = await tcp_ask(port, query_wire())
            assert reply[3] & 0xF == dns.rcode.SERVFAIL
            assert server.stats.internal_errors == 2

    run(body())


def test_event_handler_errors_are_contained():
    def explode(event):
        raise ValueError("handler bug")

    async def body():
        async with running(on_event=explode) as (_, port):
            assert ips(await udp_ask(port, query_wire())) == [DEFAULT_A]

    run(body())


def test_tcp_idle_timeout_closes_the_connection():
    async def body():
        async with running(tcp_idle_timeout=0.2) as (server, port):
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(b"\x00")  # half a length prefix, then silence
            await writer.drain()
            assert await asyncio.wait_for(reader.read(), 2) == b""  # closed by the server
            writer.close()
            await asyncio.sleep(0.05)
            assert server.stats.tcp_open == 0

    run(body())


def test_tcp_connection_limit():
    async def body():
        async with running(tcp_max_connections=1) as (server, port):
            reader1, writer1 = await asyncio.open_connection("127.0.0.1", port)
            writer1.write(len(query_wire()).to_bytes(2, "big") + query_wire())
            await writer1.drain()
            await reader1.readexactly(2)  # the first connection is being served
            reader2, writer2 = await asyncio.open_connection("127.0.0.1", port)
            assert await asyncio.wait_for(reader2.read(), 2) == b""
            assert server.stats.tcp_rejected == 1
            writer1.close()
            writer2.close()

    run(body())


def test_tcp_garbage_closes_only_that_connection():
    async def body():
        async with running() as (_, port):
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            response = dns.message.make_response(dns.message.make_query("x.example", "A")).to_wire()
            writer.write(len(response).to_bytes(2, "big") + response)
            await writer.drain()
            assert await asyncio.wait_for(reader.read(), 2) == b""
            writer.close()
            assert ips((await tcp_ask(port, query_wire()))[0]) == [DEFAULT_A]

    run(body())


def test_udp_overload_drops():
    gate = asyncio.Event

    class Slow(Pipeline):
        async def handle(self, query):
            await self.gate.wait()
            return await super().handle(query)

    async def body():
        pipeline = Slow(FakeResolver())
        pipeline.gate = gate()
        async with running(pipeline, max_inflight=2) as (server, port):
            loop = asyncio.get_running_loop()
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setblocking(False)
            sock.connect(("127.0.0.1", port))
            for i in range(5):
                await loop.sock_sendall(sock, query_wire(qid=i))
            await asyncio.sleep(0.2)
            assert server.stats.dropped == 3
            pipeline.gate.set()
            ids = {dns.message.from_wire(await asyncio.wait_for(loop.sock_recv(sock, 4096), 2)).id for _ in range(2)}
            assert ids == {0, 1}
            sock.close()

    run(body())


def test_fuzzed_datagrams_never_stop_the_server():
    rng = random.Random(7)
    seeds = [query_wire(), query_wire("a.b.example", "HTTPS", use_edns=0, want_dnssec=True)]

    async def body():
        async with running() as (server, port):
            loop = asyncio.get_running_loop()
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setblocking(False)
            sock.connect(("127.0.0.1", port))
            for _ in range(500):
                wire = bytearray(rng.choice(seeds))
                for _ in range(rng.randint(1, 5)):
                    wire[rng.randrange(len(wire))] = rng.randrange(256)
                await loop.sock_sendall(sock, bytes(wire[: rng.randint(0, len(wire))]))
            await asyncio.sleep(0.3)
            sock.close()
            assert server.stats.internal_errors == 0
            assert ips(await udp_ask(port, query_wire())) == [DEFAULT_A]

    run(body())


def test_close_cancels_in_flight_work():
    class Hang(Pipeline):
        async def handle(self, query):
            await asyncio.Event().wait()

    async def body():
        server = DnsServer(Hang(FakeResolver()))
        await server.start(bind_free())
        port = server.addresses[0][1][1]
        assert await udp_ask(port, query_wire(), timeout=0.2) is None
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(len(query_wire()).to_bytes(2, "big") + query_wire())
        await writer.drain()
        await asyncio.sleep(0.05)
        await asyncio.wait_for(server.close(), 2)
        writer.close()

    run(body())


def test_bind_sockets_never_sets_reuseaddr_on_udp():
    udp, tcp = bind_free()
    try:
        assert udp.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR) == 0
        assert udp.type == socket.SOCK_DGRAM and tcp.type == socket.SOCK_STREAM
        assert udp.getsockname() == tcp.getsockname()
    finally:
        udp.close()
        tcp.close()


# --- sdnotify ---------------------------------------------------------------


def test_notify(tmp_path):
    path = str(tmp_path / "notify.sock")
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as receiver:
        receiver.bind(path)
        assert sdnotify.notify("READY=1", {"NOTIFY_SOCKET": path})
        assert receiver.recv(64) == b"READY=1"
    abstract = f"@blockads-test-{os.getpid()}"
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as receiver:
        receiver.bind("\0" + abstract[1:])
        assert sdnotify.notify("WATCHDOG=1", {"NOTIFY_SOCKET": abstract})
        assert receiver.recv(64) == b"WATCHDOG=1"
    assert not sdnotify.notify("READY=1", {})
    assert not sdnotify.notify("READY=1", {"NOTIFY_SOCKET": "relative"})


def test_listen_fds_ignores_other_pids_and_garbage():
    env = {"LISTEN_PID": "1", "LISTEN_FDS": "2", "LISTEN_FDNAMES": "a:b"}
    assert sdnotify.listen_fds(env) == []
    assert env == {}  # unset, like sd_listen_fds(1)
    assert sdnotify.listen_fds({"LISTEN_PID": "x", "LISTEN_FDS": "1"}) == []
    assert sdnotify.listen_fds({}) == []


def test_listen_fds_adopts_passed_sockets():
    """Run in a child that receives two sockets as fds 3 and 4, like systemd does."""
    child = (
        "import os, socket, sys\n"
        "for target, fd in enumerate(map(int, sys.argv[1:]), start=3):\n"
        "    os.dup2(fd, target)\n"
        "os.environ.update(LISTEN_PID=str(os.getpid()), LISTEN_FDS='2', LISTEN_FDNAMES='dns-v4:')\n"
        "from blockads_linux.daemon.sdnotify import listen_fds\n"
        "got = listen_fds()\n"
        "print([(s.type == socket.SOCK_DGRAM, s.getsockname()[1], n) for s, n in got], 'LISTEN_FDS' in os.environ)\n"
    )
    udp, tcp = bind_free()
    try:
        env = dict(os.environ, PYTHONPATH=os.pathsep.join(sys.path))
        out = subprocess.run(
            [sys.executable, "-c", child, str(udp.fileno()), str(tcp.fileno())],
            pass_fds=(udp.fileno(), tcp.fileno()), capture_output=True, text=True, env=env, check=True,
        ).stdout.strip()
        port = udp.getsockname()[1]
        assert out == f"[(True, {port}, 'dns-v4'), (False, {port}, 'unknown')] False"
    finally:
        udp.close()
        tcp.close()
