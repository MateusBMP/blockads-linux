"""End-to-end test of ``python -m blockads_linux.daemon --dev`` (offline).

The daemon runs as a real subprocess on an ephemeral loopback port, with a
fake plain-DNS upstream on loopback, a compiled list and a custom rule.
"""

import asyncio
import os
import re
import signal
import sys

import dns.message
import dns.rcode
import pytest

from blockads_linux.daemon.__main__ import _listen_address, build_parser, build_policy_config, main
from blockads_linux.daemon.upstream.policy import UpstreamPolicy

from .upstreams import UdpServer


async def ask(port, name, rdtype="A", tcp=False):
    loop = asyncio.get_running_loop()
    wire = dns.message.make_query(name, rdtype).to_wire()
    if tcp:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(len(wire).to_bytes(2, "big") + wire)
        size = int.from_bytes(await asyncio.wait_for(reader.readexactly(2), 5), "big")
        data = await reader.readexactly(size)
        writer.close()
    else:
        import socket

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        sock.connect(("127.0.0.1", port))
        await loop.sock_sendall(sock, wire)
        data = await asyncio.wait_for(loop.sock_recv(sock, 4096), 5)
        sock.close()
    reply = dns.message.from_wire(data)
    return dns.rcode.to_text(reply.rcode()), [r.to_text() for rrset in reply.answer for r in rrset]


def test_dev_daemon_end_to_end(tmp_path):
    hosts = tmp_path / "hosts.txt"
    hosts.write_text("# test list\n0.0.0.0 doubleclick.net\n0.0.0.0 tracker.example\n")
    rules = tmp_path / "rules.txt"
    rules.write_text("||custom-blocked.example^\n@@||tracker.example^\n")

    async def body():
        upstream = await UdpServer().start()
        env = dict(os.environ, PYTHONPATH=os.pathsep.join(sys.path))
        process = await asyncio.create_subprocess_exec(
            sys.executable, "-m", "blockads_linux.daemon", "--dev", "--listen", "127.0.0.1:0",
            "--upstream", f"udp://127.0.0.1:{upstream.port}", "--fallback", "none", "--no-netmon",
            "--list", str(hosts), "--rules", str(rules),
            "--log-queries",
            stderr=asyncio.subprocess.PIPE, env=env,
        )
        lines = []
        try:
            port = None
            while port is None:
                line = (await asyncio.wait_for(process.stderr.readline(), 10)).decode()
                assert line, "daemon exited early:\n" + "".join(lines)
                lines.append(line)
                match = re.search(r"serving DNS on tcp \('127\.0\.0\.1', (\d+)\)", line)
                port = int(match.group(1)) if match else None
            assert await ask(port, "doubleclick.net") == ("NOERROR", ["0.0.0.0"])
            assert await ask(port, "custom-blocked.example", "AAAA") == ("NOERROR", ["::"])
            assert await ask(port, "tracker.example") == ("NOERROR", ["192.0.2.1"])  # custom allow
            assert await ask(port, "example.com", tcp=True) == ("NOERROR", ["192.0.2.1"])
            assert await ask(port, "use-application-dns.net") == ("NXDOMAIN", [])
            process.send_signal(signal.SIGTERM)
            assert await asyncio.wait_for(process.wait(), 10) == 0
            rest = (await process.stderr.read()).decode()
            log = "".join(lines) + rest
            assert "blocked   A     doubleclick.net (hosts)" in log
            assert "custom_allow" in log and "stopping" in log
            assert "httpx" not in log
        finally:
            if process.returncode is None:
                process.kill()
                await process.wait()
            upstream.close()

    asyncio.run(body())


def test_argument_errors(monkeypatch, capsys):
    assert main(["--dev"]) == 2
    monkeypatch.delenv("LISTEN_FDS", raising=False)
    assert main([]) == 2
    assert main(["--list", "x.txt"]) == 2
    assert "need --dev" in capsys.readouterr().err


def test_listen_address_parsing():
    assert _listen_address("127.0.0.1:5300") == ("127.0.0.1", 5300)
    assert _listen_address("[::1]:5300") == ("::1", 5300)
    for bad in ("localhost:53", "127.0.0.1", "127.0.0.1:0x", "[::1]", "127.0.0.1:70000"):
        with pytest.raises(Exception):
            _listen_address(bad)


def policy_from(argv, resolv):
    config = build_policy_config(build_parser().parse_args(list(argv)))
    return UpstreamPolicy(config, resolv_conf=resolv)  # no NetworkManager: resolv.conf is the network


def test_tiers_from_arguments(tmp_path):
    resolv = tmp_path / "resolv.conf"
    resolv.write_text("nameserver 127.0.0.53\nnameserver 192.0.2.53\n")

    def tiers(*argv):
        return policy_from(argv, resolv).tiers

    default = tiers()
    assert [t.name for t in default] == ["configured", "fallback", "network"]
    assert all(u.encrypted for u in default[0].upstreams) and not any(u.encrypted for u in default[1].upstreams)
    assert [u.label for u in default[2].upstreams] == ["udp://192.0.2.53"]  # loopback skipped
    assert [t.name for t in tiers("--encrypted-only")] == ["configured"]
    assert [t.name for t in tiers("--fallback", "none")] == ["configured"]
    assert [t.name for t in tiers("--fallback", "udp://192.0.2.9")] == ["configured", "fallback"]
    assert [t.name for t in tiers("--upstream", "udp://192.0.2.1")] == ["configured", "network"]
    system = tiers("--upstream", "system")
    assert [t.name for t in system] == ["configured"] and system[0].upstreams[0].label == "udp://192.0.2.53"
    with pytest.raises(SystemExit):
        tiers("--upstream", "udp://192.0.2.53", "--encrypted-only")
    with pytest.raises(SystemExit):
        tiers("--upstream", "system", "--upstream", "quad9")
    resolv.write_text("nameserver 127.0.0.53\n")
    assert tiers("--upstream", "system") == ()  # SERVFAIL until the network has a usable server


def test_encrypted_only_keeps_plain_servers_for_the_ntp_rescue(tmp_path):
    resolv = tmp_path / "resolv.conf"
    resolv.write_text("nameserver 192.0.2.53\nnameserver 9.9.9.9\n")
    (rescue,) = policy_from(["--encrypted-only"], resolv).rescue
    assert rescue.name == "ntp-rescue"
    assert [u.label for u in rescue.upstreams] == ["udp://9.9.9.9", "udp://149.112.112.112", "udp://192.0.2.53"]
    assert not any(u.encrypted for u in rescue.upstreams)
    assert policy_from([], resolv).rescue == ()  # normal mode: fallback/network tiers serve everything


def test_systemd_sockets_are_split_by_name():
    import socket

    from blockads_linux.daemon.__main__ import select_sockets

    socks = {name: socket.socket(socket.AF_INET, socket.SOCK_DGRAM) for name in ("dns-v4", "dns-v6", "dns-bridge", "unknown")}
    try:
        loopback, bridge = select_sockets(list((s, n) for n, s in socks.items()))
        assert loopback == [socks["dns-v4"], socks["dns-v6"]]
        assert bridge == [socks["dns-bridge"]]  # served behind the source ACL
        assert socks["unknown"].fileno() == -1
    finally:
        for s in socks.values():
            s.close()
