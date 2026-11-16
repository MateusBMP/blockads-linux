"""Tests for updater.fetch against a local HTTPS server with a test CA."""

import asyncio
import gzip
import hashlib

import pytest

from blockads_linux.updater.fetch import DaemonResolver, FetchError, Fetcher, is_global_address

from .https_server import HttpsServer, redirect, static
from .upstreams import UdpServer, answer, make_test_ca, server_tls_context

pytest.importorskip("cryptography")

LIST = b"# test list\n0.0.0.0 ads.example\n||tracker.example^\n"


@pytest.fixture(scope="module")
def tls(tmp_path_factory):
    directory = tmp_path_factory.mktemp("ca")
    ca, cert, key = make_test_ca(directory, names=("lists.test", "other.test"))
    return str(ca), server_tls_context(cert, key)


def run(coro):
    return asyncio.run(coro)


def fetcher(ca, **kwargs):
    async def resolve(host):
        return {"lists.test": ["127.0.0.1"], "other.test": ["127.0.0.1"], "private.test": ["192.168.1.10"],
                }.get(host, [])
    kwargs.setdefault("allow_address", lambda address: address.startswith("127."))
    return Fetcher(resolve, cafile=ca, **kwargs)


def serve(tls, routes, scenario):
    async def body():
        server = await HttpsServer(tls[1], routes).start()
        try:
            return await scenario(server, f"https://lists.test:{server.port}")
        finally:
            server.close()
    return run(body())


def test_download_and_conditional_requests(tls, tmp_path):
    dest = tmp_path / "list.txt"

    async def scenario(server, base):
        f = fetcher(tls[0])
        result = await f.fetch(f"{base}/list.txt", dest)
        assert result.status == "ok" and result.sha256 == hashlib.sha256(LIST).hexdigest()
        assert result.size == len(LIST) and result.etag == '"v1"' and dest.read_bytes() == LIST
        request = server.requests[-1]
        assert request.headers["host"] == f"lists.test:{server.port}"
        assert request.headers["user-agent"].startswith("blockads-linux/")
        assert "cookie" not in request.headers
        again = await f.fetch(f"{base}/list.txt", tmp_path / "again.txt", etag=result.etag)
        assert again.status == "not_modified" and not (tmp_path / "again.txt").exists()
        assert server.requests[-1].headers["if-none-match"] == '"v1"'
        by_date = await f.fetch(f"{base}/dated.txt", tmp_path / "d.txt", last_modified="Mon, 01 Jan 2024 00:00:00 GMT")
        assert by_date.status == "not_modified"

    serve(tls, {"/list.txt": static(LIST, etag='"v1"'),
                "/dated.txt": static(LIST, last_modified="Mon, 01 Jan 2024 00:00:00 GMT")}, scenario)


def test_gzip_body_is_decoded(tls, tmp_path):
    async def scenario(server, base):
        result = await fetcher(tls[0]).fetch(f"{base}/gz", tmp_path / "x")
        assert (tmp_path / "x").read_bytes() == LIST and result.sha256 == hashlib.sha256(LIST).hexdigest()

    def handler(request):
        return 200, {"Content-Encoding": "gzip", "Content-Type": "text/plain"}, gzip.compress(LIST)

    serve(tls, {"/gz": handler}, scenario)


def test_redirects(tls, tmp_path):
    async def scenario(server, base):
        f = fetcher(tls[0])
        result = await f.fetch(f"{base}/r1", tmp_path / "x")
        assert result.status == "ok" and result.url == f"https://other.test:{server.port}/list.txt"
        assert server.requests[-1].headers["host"] == f"other.test:{server.port}"
        with pytest.raises(FetchError, match="more than 3 redirects"):
            await f.fetch(f"{base}/loop", tmp_path / "x")
        with pytest.raises(FetchError, match="non-HTTPS"):
            await f.fetch(f"{base}/to-http", tmp_path / "x")
        with pytest.raises(FetchError, match="no public address"):
            await f.fetch(f"{base}/to-private", tmp_path / "x")
        with pytest.raises(FetchError, match="no public address"):
            await f.fetch(f"{base}/to-literal", tmp_path / "x")

    routes = {
        "/r1": redirect("/r2", 301),
        "/r2": lambda request: (307, {"Location": f"https://other.test:{request.headers['host'].split(':')[1]}"
                                                  "/list.txt"}, b""),
        "/list.txt": static(LIST),
        "/loop": redirect("/loop"),
        "/to-http": redirect("http://lists.test/list.txt"),
        "/to-private": redirect("https://private.test/list.txt"),
        "/to-literal": redirect("https://10.0.0.1/list.txt"),
    }
    serve(tls, routes, scenario)


def test_rejections(tls, tmp_path):
    async def endless(request):
        async def chunks():
            while True:
                yield b"0.0.0.0 x.example\n" * 1000
        return 200, {"Content-Type": "text/plain"}, chunks()

    async def slow(request):
        async def chunks():
            yield b"0.0.0.0 a.example\n"
            await asyncio.sleep(5)
            yield b"0.0.0.0 b.example\n"
        return 200, {}, chunks()

    async def scenario(server, base):
        f = fetcher(tls[0], max_bytes=64 * 1024, read_timeout=0.5, total_timeout=2)
        for path, message in [("/html-type", "HTML page"), ("/html-sniff", "HTML page"), ("/missing", "HTTP 404"),
                              ("/error", "HTTP 503"), ("/empty", "empty response"), ("/big", "larger than"),
                              ("/endless", "larger than"), ("/slow", "ReadTimeout")]:
            dest = tmp_path / "out.txt"
            with pytest.raises(FetchError, match=message):
                await f.fetch(base + path, dest)
            assert not dest.exists() and not list(tmp_path.glob("*.part")), path
        with pytest.raises(FetchError, match="took too long"):
            await fetcher(tls[0], read_timeout=10, total_timeout=0.5).fetch(base + "/slow", tmp_path / "x")
        with pytest.raises(FetchError, match="not an HTTPS URL"):
            await f.fetch(f"http://lists.test:{server.port}/x", tmp_path / "x")
        with pytest.raises(FetchError, match="no address"):
            await f.fetch("https://unknown.test/x", tmp_path / "x")

    routes = {
        "/html-type": static(b"0.0.0.0 a.example\n", content_type="text/html; charset=utf-8"),
        "/html-sniff": static(b"\n  <!DOCTYPE html><title>Login</title>"),
        "/error": static(b"busy", status=503),
        "/empty": static(b""),
        "/big": static(b"x" * (65 * 1024)),
        "/endless": lambda request: _await(endless(request)),
        "/slow": lambda request: _await(slow(request)),
    }
    serve(tls, routes, scenario)


def _await(coroutine):
    """Run a handler coroutine that only builds its response (no awaits before returning)."""
    try:
        coroutine.send(None)
    except StopIteration as stop:
        return stop.value
    raise RuntimeError("handler awaited")


def test_certificate_must_match_the_host(tls, tmp_path):
    async def scenario(server, base):
        async def resolve(host):
            return ["127.0.0.1"]
        f = Fetcher(resolve, cafile=tls[0], allow_address=lambda a: True)
        with pytest.raises(FetchError, match="certificate"):
            await f.fetch(f"https://wrong.test:{server.port}/list.txt", tmp_path / "x")
        no_ca = Fetcher(resolve, allow_address=lambda a: True)  # system CA store: test CA unknown
        with pytest.raises(FetchError, match="certificate"):
            await no_ca.fetch(f"{base}/list.txt", tmp_path / "x")

    serve(tls, {"/list.txt": static(LIST)}, scenario)


def test_next_address_on_connect_failure(tls, tmp_path):
    async def scenario(server, base):
        async def resolve(host):
            return ["127.0.0.2", "127.0.0.1"]  # nothing listens on 127.0.0.2
        f = Fetcher(resolve, cafile=tls[0], allow_address=lambda a: True)
        result = await f.fetch(f"{base}/list.txt", tmp_path / "x")
        assert result.status == "ok"

    serve(tls, {"/list.txt": static(LIST)}, scenario)


@pytest.mark.parametrize("address, expected", [
    ("1.1.1.1", True), ("2606:4700::1111", True), ("127.0.0.1", False), ("10.1.2.3", False),
    ("192.168.0.1", False), ("172.16.0.1", False), ("169.254.169.254", False), ("100.64.0.1", False),
    ("0.0.0.0", False), ("::1", False), ("fe80::1", False), ("fd00::1", False), ("::ffff:127.0.0.1", False),
    ("::ffff:8.8.8.8", True), ("224.0.0.1", False), ("ff02::1", False), ("192.0.2.1", False),
])
def test_is_global_address(address, expected):
    assert is_global_address(address) is expected


def test_daemon_resolver():
    def handler(query, wire):
        qtype = query.question[0].rdtype
        if qtype == 1:
            return answer(query, ("A", "203.0.113.5"), ("A", "203.0.113.6"))
        return answer(query, ("AAAA", "2001:db8::5"))

    async def scenario():
        server = await UdpServer(handler).start()
        try:
            addresses = await DaemonResolver("127.0.0.1", server.port, timeout=1)("lists.test")
            assert addresses == ["203.0.113.5", "203.0.113.6", "2001:db8::5"]
        finally:
            server.close()
        with pytest.raises(OSError):
            await DaemonResolver("127.0.0.1", 9, timeout=0.2)("lists.test")

    run(scenario())
