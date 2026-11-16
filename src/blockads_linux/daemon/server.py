"""DNS listeners: UDP and TCP on sockets bound by systemd (or by ``--dev``).

Every datagram or TCP message is handled in its own task, and every failure
is contained: invalid input gets the reply ``parse_query`` chose (or none),
an internal error gets SERVFAIL, and nothing propagates to the event loop.

Limits: at most ``max_inflight`` UDP queries in flight (more are dropped and
counted; clients retry), ``tcp_max_connections`` TCP connections (more are
closed at once), ``tcp_max_pipelined`` concurrent queries per connection
(the connection is not read further until one completes), and
``tcp_idle_timeout`` seconds to wait for each length prefix or message body.

A listener started with ``acl`` (the bridge listener) answers
only the sources the ACL allows; any other datagram or connection is dropped
silently and counted in ``acl_dropped``. Such listeners are left out of
``probe_addresses`` (the watchdog's self-probe comes from loopback).
"""

from __future__ import annotations

import asyncio
import contextlib
import errno
import functools
import logging
import socket
from collections.abc import Callable, Coroutine, Iterable
from dataclasses import dataclass
from typing import Any

import dns.rcode

from .pipeline import Pipeline, QueryEvent
from .responses import MAX_TCP_MESSAGE, InvalidQuery, Query, header_reply, parse_query, render

log = logging.getLogger(__name__)


@dataclass(slots=True)
class ServerStats:
    received: int = 0
    answered: int = 0
    invalid: int = 0
    dropped: int = 0  # UDP overload
    internal_errors: int = 0
    tcp_open: int = 0
    tcp_rejected: int = 0
    acl_dropped: int = 0


class DnsServer:
    def __init__(
        self,
        pipeline: Pipeline,
        *,
        on_event: Callable[[QueryEvent], None] | None = None,
        max_inflight: int = 2048,
        tcp_max_connections: int = 128,
        tcp_max_pipelined: int = 32,
        tcp_idle_timeout: float = 10.0,
    ) -> None:
        self.pipeline = pipeline
        self.stats = ServerStats()
        self._on_event = on_event
        self._max_inflight = max_inflight
        self._tcp_max_connections = tcp_max_connections
        self._tcp_max_pipelined = tcp_max_pipelined
        self._tcp_idle_timeout = tcp_idle_timeout
        self._tasks: set[asyncio.Task[Any]] = set()
        self._connections: set[asyncio.Task[Any]] = set()
        self._udp: list[asyncio.DatagramTransport] = []
        self._tcp: list[asyncio.Server] = []
        self._guarded: set[int] = set()  # id() of listeners started with an ACL

    @property
    def addresses(self) -> list[tuple[str, Any]]:
        """``("udp"|"tcp", sockname)`` of every listener."""
        found = [("udp", t.get_extra_info("sockname")) for t in self._udp]
        found += [("tcp", s.sockets[0].getsockname()) for s in self._tcp if s.sockets]
        return found

    @property
    def probe_addresses(self) -> list[tuple[str, Any]]:
        """Like ``addresses``, without the listeners guarded by an ACL."""
        found = [("udp", t.get_extra_info("sockname")) for t in self._udp if id(t) not in self._guarded]
        found += [("tcp", s.sockets[0].getsockname()) for s in self._tcp
                  if s.sockets and id(s) not in self._guarded]
        return found

    async def start(self, sockets: Iterable[socket.socket], *, acl: Callable[[str], bool] | None = None) -> None:
        """Serve ``sockets``; with ``acl``, only peers for which ``acl(host)`` is true are answered."""
        loop = asyncio.get_running_loop()
        for sock in sockets:
            sock.setblocking(False)
            if sock.type == socket.SOCK_DGRAM:
                transport, _ = await loop.create_datagram_endpoint(lambda: _UdpProtocol(self, acl), sock=sock)
                self._udp.append(transport)
                listener: object = transport
            elif sock.type == socket.SOCK_STREAM:
                handler = self._serve_tcp if acl is None else functools.partial(self._serve_tcp_guarded, acl)
                listener = await asyncio.start_server(handler, sock=sock)
                self._tcp.append(listener)  # type: ignore[arg-type]
            else:
                raise ValueError(f"unsupported socket type {sock.type!r}")
            if acl is not None:
                self._guarded.add(id(listener))

    async def close(self) -> None:
        for transport in self._udp:
            transport.close()
        for server in self._tcp:
            server.close()
        pending = list(self._tasks | self._connections)
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        for server in self._tcp:
            await server.wait_closed()
        self._udp.clear()
        self._tcp.clear()
        self._guarded.clear()

    # --- shared ----------------------------------------------------------------

    def _spawn(self, coro: Coroutine[Any, Any, None]) -> asyncio.Task[None]:
        task = asyncio.get_running_loop().create_task(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return task

    async def _resolve(self, query: Query, raw: bytes, limit: int) -> bytes | None:
        """Wire reply for a valid query; never raises (except cancellation)."""
        try:
            reply, event = await self.pipeline.handle(query)
            wire = render(reply, limit)
        except Exception as exc:
            self.stats.internal_errors += 1
            log.error("internal error in the DNS server: %s", type(exc).__name__)
            return header_reply(raw, dns.rcode.SERVFAIL)
        self.stats.answered += 1
        if event is not None and self._on_event is not None:
            try:
                self._on_event(event)
            except Exception as exc:
                log.error("query event handler failed: %s", type(exc).__name__)
        return wire

    def _parse(self, data: bytes) -> tuple[Query | None, bytes | None]:
        """``(query, None)`` for a valid query, else ``(None, reply or None)``."""
        self.stats.received += 1
        try:
            return parse_query(data), None
        except InvalidQuery as exc:
            self.stats.invalid += 1
            return None, exc.response

    # --- UDP -------------------------------------------------------------------

    def _on_datagram(self, transport: asyncio.DatagramTransport, data: bytes, addr: Any) -> None:
        query, reply = self._parse(data)
        if query is None:
            if reply is not None:
                transport.sendto(reply, addr)
            return
        if len(self._tasks) >= self._max_inflight:
            self.stats.dropped += 1
            return
        self._spawn(self._answer_udp(transport, query, data, addr))

    async def _answer_udp(self, transport: asyncio.DatagramTransport, query: Query, data: bytes, addr: Any) -> None:
        wire = await self._resolve(query, data, query.udp_limit)
        if wire is not None and not transport.is_closing():
            transport.sendto(wire, addr)

    # --- TCP -------------------------------------------------------------------

    async def _serve_tcp_guarded(self, acl: Callable[[str], bool],
                                 reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        if not peer or not _acl_allows(acl, peer[0]):
            self.stats.acl_dropped += 1
            writer.transport.abort()
            return
        await self._serve_tcp(reader, writer)

    async def _serve_tcp(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if self.stats.tcp_open >= self._tcp_max_connections:
            self.stats.tcp_rejected += 1
            writer.close()
            return
        me = asyncio.current_task()
        if me is not None:
            self._connections.add(me)
        self.stats.tcp_open += 1
        pending: set[asyncio.Task[None]] = set()
        lock = asyncio.Lock()
        try:
            while True:
                try:
                    prefix = await asyncio.wait_for(reader.readexactly(2), self._tcp_idle_timeout)
                    data = await asyncio.wait_for(reader.readexactly(int.from_bytes(prefix, "big")),
                                                  self._tcp_idle_timeout)
                except (TimeoutError, asyncio.IncompleteReadError, OSError):
                    break
                query, reply = self._parse(data)
                if query is None:
                    if reply is None:
                        break  # not a query (or a runt): drop the connection
                    await self._write_tcp(writer, lock, reply)
                    continue
                if len(pending) >= self._tcp_max_pipelined:
                    await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
                task = self._spawn(self._answer_tcp(writer, lock, query, data))
                pending.add(task)
                task.add_done_callback(pending.discard)
        finally:
            if pending:
                await asyncio.wait(pending, timeout=self._tcp_idle_timeout)
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
            self.stats.tcp_open -= 1
            if me is not None:
                self._connections.discard(me)

    async def _answer_tcp(self, writer: asyncio.StreamWriter, lock: asyncio.Lock, query: Query, data: bytes) -> None:
        wire = await self._resolve(query, data, MAX_TCP_MESSAGE)
        if wire is not None:
            await self._write_tcp(writer, lock, wire)

    @staticmethod
    async def _write_tcp(writer: asyncio.StreamWriter, lock: asyncio.Lock, wire: bytes) -> None:
        async with lock:
            if writer.is_closing():
                return
            writer.write(len(wire).to_bytes(2, "big") + wire)
            with contextlib.suppress(OSError):
                await writer.drain()


def _acl_allows(acl: Callable[[str], bool], host: str) -> bool:
    try:
        return bool(acl(host))
    except Exception as exc:  # fail closed
        log.error("source ACL failed: %s", type(exc).__name__)
        return False


class _UdpProtocol(asyncio.DatagramProtocol):
    def __init__(self, server: DnsServer, acl: Callable[[str], bool] | None = None) -> None:
        self._server = server
        self._acl = acl
        self._transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self._transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: Any) -> None:
        if self._acl is not None and not _acl_allows(self._acl, addr[0]):
            self._server.stats.acl_dropped += 1
            return
        if self._transport is not None:
            self._server._on_datagram(self._transport, data, addr)

    def error_received(self, exc: Exception) -> None:
        pass  # ICMP errors for earlier replies: nothing to do


def bind_sockets(host: str, port: int) -> list[socket.socket]:
    """Bind a UDP and a TCP socket on ``host:port`` (development mode only).

    In production, systemd binds the privileged port and passes the sockets.
    ``SO_REUSEADDR`` is never set on the UDP socket: it would let another process co-bind the port and steal queries.
    Port 0 picks a free UDP port; when that number is taken for TCP, it tries again.
    """
    for attempt in range(20):
        try:
            return _bind_pair(host, port)
        except OSError as exc:
            if port != 0 or exc.errno != errno.EADDRINUSE or attempt == 19:
                raise
    raise AssertionError("unreachable")  # pragma: no cover


def _bind_pair(host: str, port: int) -> list[socket.socket]:
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    udp = socket.socket(family, socket.SOCK_DGRAM | socket.SOCK_CLOEXEC)
    tcp = socket.socket(family, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
    try:
        for sock in (udp, tcp):
            if family == socket.AF_INET6:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        udp.bind((host, port))
        tcp.bind((host, udp.getsockname()[1]))
        tcp.listen(128)
    except BaseException:
        udp.close()
        tcp.close()
        raise
    return [udp, tcp]
