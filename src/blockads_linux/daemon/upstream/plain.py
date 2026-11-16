"""Plain DNS over UDP (with TCP retry on truncation).

Each query uses a fresh *connected* UDP socket: the kernel picks a random
source port and delivers only datagrams from the upstream's address, and the
reply must carry our random ID and our question. Anything else is ignored and
we keep waiting until the deadline (fixes the Android root mode, which
accepted replies from any source). An ICMP "port unreachable" fails at once.
A truncated reply (TC=1) is retried over TCP.
"""

from __future__ import annotations

import asyncio
import ipaddress
import secrets
import socket

import dns.flags
import dns.message

from .base import Question, ResponseMismatch, UpstreamError, check_response
from .tcp import StreamUpstream


class UdpUpstream:
    encrypted = False

    def __init__(self, address: str, port: int = 53, *, label: str | None = None, timeout: float = 2.0,
                 tcp: StreamUpstream | None = None) -> None:
        ip = ipaddress.ip_address(address.split("%", 1)[0])
        self.address = address  # may carry an IPv6 scope ("fe80::1%eth0")
        self.port = port
        self._family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
        host = f"[{address}]" if ip.version == 6 else address
        self.label = label or f"udp://{host}:{port}"
        self.timeout = timeout
        self._tcp = tcp if tcp is not None else StreamUpstream(str(ip), port, timeout=timeout)

    async def exchange(self, question: Question) -> dns.message.Message:
        message = await self._exchange_udp(question)
        if message.flags & dns.flags.TC:
            return await self._tcp.exchange(question)
        return message

    async def _exchange_udp(self, question: Question) -> dns.message.Message:
        loop = asyncio.get_running_loop()
        qid = secrets.randbelow(65536)
        wire = question.to_wire(qid)
        sock = socket.socket(self._family, socket.SOCK_DGRAM | socket.SOCK_NONBLOCK | socket.SOCK_CLOEXEC)
        try:
            async with asyncio.timeout(self.timeout):
                await loop.sock_connect(sock, (self.address, self.port))
                await loop.sock_sendall(sock, wire)
                while True:
                    data = await loop.sock_recv(sock, 65535)
                    try:
                        return check_response(question, qid, data)
                    except ResponseMismatch:
                        continue  # stale or forged: keep waiting for the real reply
        except TimeoutError:
            raise UpstreamError("timeout") from None
        except OSError as exc:  # ECONNREFUSED (ICMP), EPERM (local REJECT), ENETUNREACH...
            raise UpstreamError(f"{type(exc).__name__}: {exc.strerror or exc}") from None
        finally:
            sock.close()

    async def close(self) -> None:
        await self._tcp.close()
