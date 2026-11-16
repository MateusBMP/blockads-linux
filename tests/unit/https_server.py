"""A tiny HTTPS/1.1 server for the updater tests (one request per connection).

``routes[path] = handler(request) -> (status, headers, body)``; ``body`` is
bytes or an async iterator of chunks (slow or endless bodies). Every request
is recorded with its headers.
"""

from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass, field


@dataclass
class Request:
    method: str
    path: str
    headers: dict[str, str] = field(default_factory=dict)


def static(body: bytes, *, status: int = 200, content_type: str = "text/plain", etag: str = "",
           last_modified: str = ""):
    """A handler serving ``body`` with ETag/Last-Modified and conditional 304s."""
    def handler(request):
        headers = {"Content-Type": content_type}
        if etag:
            headers["ETag"] = etag
            if request.headers.get("if-none-match") == etag:
                return 304, headers, b""
        if last_modified:
            headers["Last-Modified"] = last_modified
            if not etag and request.headers.get("if-modified-since") == last_modified:
                return 304, headers, b""
        return status, headers, body
    return handler


def redirect(location: str, status: int = 302):
    return lambda request: (status, {"Location": location}, b"")


class HttpsServer:
    def __init__(self, ssl_context, routes=None) -> None:
        self.ssl_context = ssl_context
        self.routes = routes if routes is not None else {}
        self.requests: list[Request] = []
        self._server = None

    async def start(self, host: str = "127.0.0.1") -> HttpsServer:
        self._server = await asyncio.start_server(self._serve, host, 0, ssl=self.ssl_context)
        return self

    @property
    def port(self) -> int:
        return self._server.sockets[0].getsockname()[1]

    def close(self) -> None:
        if self._server is not None:
            self._server.close()

    async def _serve(self, reader, writer) -> None:
        try:
            line = (await reader.readline()).decode("latin-1").split()
            if len(line) < 2:
                return
            request = Request(line[0], line[1])
            while (header := await reader.readline()) not in (b"\r\n", b"\n", b""):
                name, _, value = header.decode("latin-1").partition(":")
                request.headers[name.strip().lower()] = value.strip()
            self.requests.append(request)
            handler = self.routes.get(request.path)
            status, headers, body = handler(request) if handler else (404, {"Content-Type": "text/plain"}, b"nope")
            chunked = not isinstance(body, bytes)
            head = [f"HTTP/1.1 {status} X", "Connection: close"]
            head += [f"{k}: {v}" for k, v in headers.items()]
            head.append("Transfer-Encoding: chunked" if chunked else f"Content-Length: {len(body)}")
            writer.write(("\r\n".join(head) + "\r\n\r\n").encode("latin-1"))
            if chunked:
                async for chunk in body:
                    writer.write(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
                    await writer.drain()
                writer.write(b"0\r\n\r\n")
            else:
                writer.write(body)
            await writer.drain()
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            with contextlib.suppress(Exception):
                writer.close()
