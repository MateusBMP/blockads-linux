"""Tests for daemon.health (watchdog, interception probe, install check) and daemon.preload."""

import asyncio
import json
import os
import re
import signal
import socket
import sys
import time

import dns.flags
import dns.message
import dns.rcode
import dns.rrset
import pytest

from blockads_linux.daemon import health
from blockads_linux.daemon.health import (
    EXIT_RESTART,
    Health,
    check_probe_reply,
    fingerprint,
    probe,
    probe_query,
    read_fw_state,
    self_targets,
    watchdog_interval,
)
from blockads_linux.daemon.preload import preload
from blockads_linux.daemon.responses import PROBE_ANSWER_PREFIX, PROBE_ZONE

from .test_server import running


def free_port():
    """A loopback port with nothing listening (UDP and TCP)."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def write_state(path, applied=True, ipv4="active", ipv6="unavailable"):
    path.write_text(json.dumps({"applied": applied, "families": {"ipv4": {"status": ipv4},
                                                                 "ipv6": {"status": ipv6}}}))
    return path


# --- probe -------------------------------------------------------------------

def test_probe_answered_by_the_pipeline_over_udp_and_tcp():
    async def body():
        async with running() as (server, port):
            assert await probe("127.0.0.1", port) is None
            assert server.stats.answered == 2

    asyncio.run(body())


def test_probe_reports_refused_and_timeout():
    async def refused():
        port = free_port()
        assert await probe("127.0.0.1", port, tries=2) == f"udp 127.0.0.1:{port}: refused"

    async def silent():
        # A UDP socket that never answers: timeout (no retry after a timeout).
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        started = time.monotonic()
        try:
            assert await probe("127.0.0.1", port, timeout=0.2, tries=3) == f"udp 127.0.0.1:{port}: timeout"
        finally:
            sock.close()
        assert time.monotonic() - started < 1.5

    asyncio.run(refused())
    asyncio.run(silent())


def _reply(query_wire, rcode=dns.rcode.NOERROR, text=None, qr=True, qid=None):
    query = dns.message.from_wire(query_wire)
    reply = dns.message.make_response(query)
    reply.set_rcode(rcode)
    if not qr:
        reply.flags &= ~dns.flags.QR
    if qid is not None:
        reply.id = qid
    if text is not None:
        reply.answer.append(dns.rrset.from_text(query.question[0].name, 0, "IN", "TXT", f'"{text}"'))
    return reply.to_wire()


def test_check_probe_reply():
    nonce = "ab" * 16
    qid, wire = probe_query(nonce)
    assert dns.message.from_wire(wire).question[0].name.to_text() == f"{nonce}.{PROBE_ZONE}."
    check_probe_reply(_reply(wire, text=PROBE_ANSWER_PREFIX + nonce), qid, nonce)
    cases = {
        "wrong answer": _reply(wire, text=PROBE_ANSWER_PREFIX + "cd" * 16),
        "rcode NXDOMAIN": _reply(wire, rcode=dns.rcode.NXDOMAIN),
        "does not match": _reply(wire, text=PROBE_ANSWER_PREFIX + nonce, qid=(qid + 1) % 65536),
        "does not match ": _reply(wire, text=PROBE_ANSWER_PREFIX + nonce, qr=False),
        "bad reply": b"\x00\x01",
    }
    for expected, data in cases.items():
        with pytest.raises(health.ProbeError, match=expected.strip()):
            check_probe_reply(data, qid, nonce)


def test_self_targets_need_udp_and_tcp_and_map_wildcards_to_loopback():
    addresses = [("udp", ("127.0.0.1", 153)), ("tcp", ("127.0.0.1", 153)),
                 ("udp", ("::1", 153, 0, 0)), ("tcp", ("::1", 153, 0, 0)),
                 ("udp", ("0.0.0.0", 5300)), ("tcp", ("0.0.0.0", 5300)),
                 ("udp", ("::", 5301, 0, 0)), ("tcp", ("::", 5301, 0, 0)),
                 ("udp", ("127.0.0.1", 9999))]
    assert self_targets(addresses) == [("127.0.0.1", 153), ("::1", 153), ("127.0.0.1", 5300), ("::1", 5301)]


# --- state.json and environment ----------------------------------------------

def test_read_fw_state(tmp_path):
    path = tmp_path / "state.json"
    assert read_fw_state(path) == []
    assert read_fw_state(write_state(path)) == ["ipv4"]
    assert read_fw_state(write_state(path, ipv6="active")) == ["ipv4", "ipv6"]
    assert read_fw_state(write_state(path, ipv6="degraded")) == ["ipv4"]
    assert read_fw_state(write_state(path, applied=False)) == []
    path.write_text('{"applied": false, "reverted": true}')
    assert read_fw_state(path) == []
    for bad in ("{", "[]", '{"applied": true}', '{"applied": true, "families": {"ipv4": "active"}}',
                '{"applied": "yes", "families": {"ipv4": {"status": "active"}}}'):
        path.write_text(bad)
        assert read_fw_state(path) == []


def test_watchdog_interval():
    pid = str(os.getpid())
    assert watchdog_interval({}) is None
    assert watchdog_interval({"WATCHDOG_USEC": "60000000"}) == 20.0
    assert watchdog_interval({"WATCHDOG_USEC": "60000000", "WATCHDOG_PID": pid}) == 20.0
    assert watchdog_interval({"WATCHDOG_USEC": "60000000", "WATCHDOG_PID": "1"}) is None
    assert watchdog_interval({"WATCHDOG_USEC": "0"}) is None
    assert watchdog_interval({"WATCHDOG_USEC": "x"}) is None


def test_fingerprint_sees_replacement_and_removal(tmp_path):
    path = tmp_path / "os.py"
    path.write_text("a")
    first = fingerprint([path, tmp_path])
    assert fingerprint([path, tmp_path]) == first
    replacement = tmp_path / "new"
    replacement.write_text("a")
    os.replace(replacement, path)  # how package managers install files
    second = fingerprint([path, tmp_path])
    assert second != first
    path.unlink()
    assert fingerprint([path])[0] == (str(path), None)


# --- Health loops --------------------------------------------------------------

def make_health(targets, **kw):
    pings = []
    kw.setdefault("fw_state_path", None)
    kw.setdefault("install_check", False)
    kw.setdefault("probe_timeout", 0.5)
    instance = Health(targets, notify=pings.append, **kw)
    return instance, pings


async def run_for(instance, seconds):
    """Run ``instance`` for ``seconds``; return its exit code or None if still running."""
    task = asyncio.create_task(instance.run())
    done, _ = await asyncio.wait({task}, timeout=seconds)
    if done:
        return task.result()
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)
    return None


def test_watchdog_pings_only_while_listeners_answer():
    async def body():
        async with running() as (server, port):
            targets = [("127.0.0.1", port)]
            instance, pings = make_health(lambda: targets, watchdog=0.1)
            assert await run_for(instance, 0.5) is None
            assert pings and set(pings) == {"WATCHDOG=1"} and instance.healthy
            # The listener goes away (e.g. its socket was closed): no more pings.
            targets[:] = [("127.0.0.1", free_port())]
            count = len(pings)
            assert await run_for(instance, 0.6) is None
            assert len(pings) == count and not instance.healthy
            assert "refused" in instance.self_error

    asyncio.run(body())


def test_watchdog_withheld_without_listeners():
    async def body():
        instance, pings = make_health(lambda: [], watchdog=0.05)
        assert await run_for(instance, 0.3) is None
        assert pings == [] and instance.self_error == "no listeners"

    asyncio.run(body())


def test_a_blocked_event_loop_fails_the_self_check(monkeypatch):
    monkeypatch.setattr(health, "MAX_LOOP_LAG", 0.2)
    monkeypatch.setattr(health, "LAG_TICK", 0.05)

    async def body():
        async with running() as (server, port):
            instance, _ = make_health(lambda: [("127.0.0.1", port)])
            task = asyncio.create_task(instance.run())  # only the lag loop
            await asyncio.sleep(0.1)
            time.sleep(0.4)  # block the event loop
            await asyncio.sleep(0.1)
            assert (await instance.self_check()).startswith("event loop stalled")
            assert await instance.self_check() is None  # recovered
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    asyncio.run(body())


def test_interception_probe_follows_state_json(tmp_path):
    async def body():
        async with running() as (server, port):
            state = tmp_path / "state.json"
            # Our server stands in for the helper's REDIRECT target on port 9.
            instance, _ = make_health(lambda: [], fw_state_path=state, fw_probe_port=port,
                                      fw_probe_hosts={"ipv4": "127.0.0.1"}, fw_interval=0.05)
            assert await run_for(instance, 0.3) is None  # no state yet: nothing probed
            assert instance.fw_families == [] and server.stats.answered == 0
            write_state(state)
            assert await run_for(instance, 0.3) is None
            assert instance.fw_families == ["ipv4"] and instance.fw_failures == 0
            assert server.stats.answered >= 2

    asyncio.run(body())


def test_lost_interception_alerts_and_exits_75(tmp_path):
    async def body():
        alerts = []
        state = write_state(tmp_path / "state.json")
        instance, _ = make_health(lambda: [], fw_state_path=state, fw_probe_port=free_port(),
                                  fw_probe_hosts={"ipv4": "127.0.0.1"}, fw_interval=0.05,
                                  on_alert=alerts.append)
        assert await run_for(instance, 5) == EXIT_RESTART
        assert instance.fw_failures == 3
        assert [a.kind for a in alerts] == ["interception-lost"] and instance.alerts == alerts
        assert "refused" in instance.exit_reason

    asyncio.run(body())


def test_transient_probe_failures_reset(tmp_path):
    async def body():
        async with running() as (server, port):
            state = write_state(tmp_path / "state.json")
            hosts = {"ipv4": "127.0.0.1"}
            instance, _ = make_health(lambda: [], fw_state_path=state, fw_probe_port=free_port(),
                                      fw_probe_hosts=hosts, fw_interval=3600, fw_retry_interval=3600,
                                      fw_failures_to_restart=3)
            task = asyncio.create_task(instance.run())
            for _ in range(2):
                instance.poke()
                await _until(lambda n=instance.fw_failures: instance.fw_failures > n)
            assert instance.fw_failures == 2
            instance.fw_probe_port = port  # the rules are back
            instance.poke()
            await _until(lambda: instance.fw_failures == 0)
            assert instance.fw_error is None and not task.done()
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    asyncio.run(body())


async def _until(predicate, timeout=5.0):
    deadline = time.monotonic() + timeout
    while not predicate():
        assert time.monotonic() < deadline, "condition not reached"
        await asyncio.sleep(0.01)


def test_install_change_exits_75(tmp_path):
    async def body():
        watched = tmp_path / "VERSION"
        watched.write_text("1")
        instance, _ = make_health(lambda: [], install_check=True, install_interval=0.05,
                                  install_paths_=[watched])
        assert await run_for(instance, 0.3) is None
        task = asyncio.create_task(instance.run())
        await asyncio.sleep(0.1)
        watched.unlink()
        assert await asyncio.wait_for(task, 2) == EXIT_RESTART
        assert str(watched) in instance.exit_reason

    asyncio.run(body())


def test_default_install_paths_exist():
    paths = health.install_paths()
    assert all(path.exists() for path in paths)
    assert any(path.name == "os.py" for path in paths)
    assert any(path.parts[-2:] == ("blockads_linux", "__init__.py") for path in paths)


# --- end to end ------------------------------------------------------------------

def test_daemon_exits_75_when_interception_is_lost(tmp_path):
    """A dev daemon told the rules are applied, with nothing redirecting port 9."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        try:
            sock.bind(("127.0.0.1", 9))
        except PermissionError:
            pass  # privileged: nothing of ours can be there
        except OSError:
            pytest.skip("something listens on 127.0.0.1:9")
    state = write_state(tmp_path / "state.json")

    async def body():
        env = dict(os.environ, PYTHONPATH=os.pathsep.join(sys.path))
        process = await asyncio.create_subprocess_exec(
            sys.executable, "-m", "blockads_linux.daemon", "--dev", "--listen", "127.0.0.1:0",
            "--upstream", "udp://127.0.0.1:1", "--fallback", "none", "--no-netmon",
            "--fw-state", str(state), "--health-interval", "0.1",
            stderr=asyncio.subprocess.PIPE, env=env,
        )
        try:
            assert await asyncio.wait_for(process.wait(), 20) == EXIT_RESTART
        finally:
            if process.returncode is None:
                process.kill()
                await process.wait()
        log = (await process.stderr.read()).decode()
        assert "alert: DNS interception stopped working" in log
        assert re.search(r"stopping \(exit 75: interception probe failed 3 times", log)

    asyncio.run(body())


def test_daemon_sigterm_still_exits_0(tmp_path):
    async def body():
        env = dict(os.environ, PYTHONPATH=os.pathsep.join(sys.path))
        process = await asyncio.create_subprocess_exec(
            sys.executable, "-m", "blockads_linux.daemon", "--dev", "--listen", "127.0.0.1:0",
            "--upstream", "udp://127.0.0.1:1", "--fallback", "none", "--no-netmon",
            stderr=asyncio.subprocess.PIPE, env=env,
        )
        try:
            while b"serving DNS on tcp" not in await asyncio.wait_for(process.stderr.readline(), 10):
                pass
            process.send_signal(signal.SIGTERM)
            assert await asyncio.wait_for(process.wait(), 10) == 0
        finally:
            if process.returncode is None:
                process.kill()
                await process.wait()

    asyncio.run(body())


# --- preload ---------------------------------------------------------------------

def test_preload_imports_our_modules_and_dns_types():
    missing = preload()
    assert not [name for name in missing if name.startswith(("blockads_linux", "dns", "encodings"))], missing
    for name in ("blockads_linux.daemon.health", "blockads_linux.filters.matcher", "dns.rdtypes.IN.A",
                 "dns.rdtypes.ANY.TXT", "dns.rdtypes.svcbbase", "encodings.idna"):
        assert name in sys.modules
    assert "blockads_linux.daemon.__main__" not in missing


def test_failed_round_is_retried_sooner(tmp_path):
    async def body():
        state = write_state(tmp_path / "state.json")
        instance, _ = make_health(lambda: [], fw_state_path=state, fw_probe_port=free_port(),
                                  fw_probe_hosts={"ipv4": "127.0.0.1"}, fw_interval=3600,
                                  fw_retry_interval=0.05, fw_failures_to_restart=3, probe_timeout=0.2)
        task = asyncio.create_task(instance.run())
        instance.poke()  # one failed round; the next two come on their own, not after 3600 s
        code = await asyncio.wait_for(task, 10)
        assert code == 75 and instance.fw_failures == 3

    asyncio.run(body())


def test_retry_interval_never_exceeds_the_interval():
    instance, _ = make_health(lambda: [], fw_state_path=None, fw_interval=1.0, fw_retry_interval=5.0)
    assert instance.fw_retry_interval == 1.0
