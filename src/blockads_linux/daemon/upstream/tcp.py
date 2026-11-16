"""DNS over a stream: plain TCP (RFC 7766) and, with a TLS context, DoT (RFC 7858).

One connection per upstream is reused for many queries and pipelined:
replies are matched to queries by ID and may arrive in any order. The
connection is closed after ``idle_timeout`` seconds without queries. A query
that fails because a *reused* connection turned out to be dead (the server
closed it while idle) is retried once on a fresh connection.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import secrets
import ssl
from typing import Any

import dns.message

from .base import Question, UpstreamError, check_response, tls_verify_error

#: Most queries in flight on one connection (RFC 7766 allows pipelining).
MAX_PIPELINED = 64


class _ConnectionLost(UpstreamError):
    pass


class _Connection:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, idle_timeout: float) -> None:
        self._reader = reader
        self._writer = writer
        self._idle_timeout = idle_timeout
        self._pending: dict[int, tuple[asyncio.Future[dns.message.Message], Question]] = {}
        self._idle_handle: asyncio.TimerHandle | None = None
        self._write_lock = asyncio.Lock()
        self.closed = False
        self.queries = 0  # queries started on this connection
        self._reader_task = asyncio.get_running_loop().create_task(self._read_loop())
        self._arm_idle_timer()

    def _arm_idle_timer(self) -> None:
        if self._idle_handle is not None:
            self._idle_handle.cancel()
        self._idle_handle = asyncio.get_running_loop().call_later(self._idle_timeout, self.close)

    @property
    def busy(self) -> bool:
        return len(self._pending) >= MAX_PIPELINED

    async def exchange(self, question: Question, timeout: float, pad_block: int) -> dns.message.Message:
        if self.closed:
            raise _ConnectionLost("connection closed")
        self.queries += 1
        if self._idle_handle is not None:
            self._idle_handle.cancel()
            self._idle_handle = None
        qid = secrets.randbelow(65536)
        while qid in self._pending:
            qid = secrets.randbelow(65536)
        future: asyncio.Future[dns.message.Message] = asyncio.get_running_loop().create_future()
        self._pending[qid] = (future, question)
        try:
            wire = question.to_wire(qid, pad_block=pad_block)
            async with asyncio.timeout(timeout):
                async with self._write_lock:
                    self._writer.write(len(wire).to_bytes(2, "big") + wire)
                    await self._writer.drain()
                return await future
        except TimeoutError:
            raise UpstreamError("timeout") from None
        except OSError as exc:
            self.close()
            raise _ConnectionLost(f"connection failed: {type(exc).__name__}") from None
        finally:
            self._pending.pop(qid, None)
            if not self._pending and not self.closed:
                self._arm_idle_timer()

    async def _read_loop(self) -> None:
        try:
            while True:
                size = int.from_bytes(await self._reader.readexactly(2), "big")
                data = await self._reader.readexactly(size)
                if len(data) < 2:
                    continue
                entry = self._pending.get(int.from_bytes(data[:2], "big"))
                if entry is None:
                    continue  # a late reply to a query that already timed out
                future, question = entry
                if future.done():
                    continue
                try:
                    future.set_result(check_response(question, int.from_bytes(data[:2], "big"), data))
                except UpstreamError as exc:
                    future.set_exception(exc)
        except (asyncio.IncompleteReadError, OSError, ssl.SSLError):
            pass
        except asyncio.CancelledError:
            raise
        finally:
            self.close()

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        if self._idle_handle is not None:
            self._idle_handle.cancel()
        for future, _question in self._pending.values():
            if not future.done():
                future.set_exception(_ConnectionLost("connection closed"))
        self._writer.close()
        if self._reader_task is not asyncio.current_task():
            self._reader_task.cancel()

    async def wait_closed(self) -> None:
        with contextlib.suppress(BaseException):
            await self._reader_task
        with contextlib.suppress(Exception):
            await self._writer.wait_closed()


class StreamUpstream:
    """An upstream reached over TCP, or over TLS when ``ssl_context`` is given."""

    def __init__(
        self,
        address: str,
        port: int = 53,
        *,
        ssl_context: ssl.SSLContext | None = None,
        server_name: str | None = None,
        label: str | None = None,
        timeout: float = 3.0,
        idle_timeout: float = 20.0,
        pad_block: int | None = None,
    ) -> None:
        self.address = str(ipaddress.ip_address(address))
        self.port = port
        self.ssl_context = ssl_context
        self.server_name = server_name
        self.encrypted = ssl_context is not None
        scheme = "tls" if self.encrypted else "tcp"
        host = f"[{self.address}]" if ":" in self.address else self.address
        self.label = label or f"{scheme}://{host}:{port}"
        self.timeout = timeout
        self.idle_timeout = idle_timeout
        self.pad_block = (128 if self.encrypted else 0) if pad_block is None else pad_block
        self._connection: _Connection | None = None
        self._connect_lock = asyncio.Lock()

    async def exchange(self, question: Question) -> dns.message.Message:
        connection = await self._get_connection()
        reused = connection.queries > 0
        try:
            return await connection.exchange(question, self.timeout, self.pad_block)
        except _ConnectionLost as exc:
            if not reused:
                raise UpstreamError(str(exc)) from None
        # A reused connection was already dead: one retry on a fresh one.
        connection = await self._get_connection(dead=connection)
        try:
            return await connection.exchange(question, self.timeout, self.pad_block)
        except _ConnectionLost as exc:
            raise UpstreamError(str(exc)) from None

    async def _get_connection(self, dead: _Connection | None = None) -> _Connection:
        async with self._connect_lock:
            current = self._connection
            if current is not None and current is not dead and not current.closed and not current.busy:
                return current
            if current is not None and current is dead:
                current.close()
            self._connection = await self._connect()
            return self._connection

    async def _connect(self) -> _Connection:
        extra: dict[str, Any] = {}
        if self.ssl_context is not None:
            extra = {"ssl": self.ssl_context, "server_hostname": self.server_name or self.address,
                     "ssl_handshake_timeout": self.timeout}
        try:
            async with asyncio.timeout(self.timeout):
                reader, writer = await asyncio.open_connection(self.address, self.port, **extra)
        except TimeoutError:
            raise UpstreamError("connect timeout") from None
        except ssl.SSLCertVerificationError as exc:
            raise tls_verify_error(exc) or UpstreamError("TLS certificate rejected") from None
        except (OSError, ssl.SSLError) as exc:
            raise UpstreamError(f"connect failed: {type(exc).__name__}") from None
        return _Connection(reader, writer, self.idle_timeout)

    async def close(self) -> None:
        connection, self._connection = self._connection, None
        if connection is not None:
            connection.close()
            await connection.wait_closed()
