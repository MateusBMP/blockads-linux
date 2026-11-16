"""Self-healing: watchdog, interception probe and install check.

Three independent loops, all on the event loop:

* **Watchdog.** ``WATCHDOG=1`` is sent only while the event loop is
  responsive and an in-process probe query through our own listening sockets
  (UDP and TCP) is answered. The probe name is answered by the pipeline
  itself, so an upstream outage never stops the watchdog. A hang therefore
  becomes watchdog → kill → revert → restart.
* **Interception probe.** Every 15 s, and at once after :meth:`Health.poke`
  (network change, resume, firewalld reload), the same probe goes to
  ``127.0.0.1:9`` / ``[::1]:9`` for each family that ``blockads-fw`` reports
  active in ``/run/blockads-fw/state.json``. Only the helper's REDIRECT rule
  makes port 9 reach us, so a failure means the rules are gone. After a
  failed round the next comes after 5 s instead of 15 s; after 3 failed
  rounds in a row the daemon raises an alert and exits 75: systemd
  reverts (fail-open), restarts and re-applies. Without an applied state
  (development, or between the helper's revert and apply) nothing is probed.
* **Install check.** Every 60 s, the stdlib directory and our package are
  fingerprinted; a Python or package upgrade (or an uninstall) while running
  exits 75 so the new code is loaded by a fresh process.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import json
import logging
import os
import secrets
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import dns.flags
import dns.message
import dns.rcode
import dns.rdatatype

from . import sdnotify
from .responses import PROBE_ANSWER_PREFIX, PROBE_ZONE

log = logging.getLogger(__name__)

#: systemd treats this exit status as "restart me" (EX_TEMPFAIL).
EXIT_RESTART = 75

FW_STATE_PATH = Path("/run/blockads-fw/state.json")
#: blockads-fw's commit-confirm port: REDIRECTed to the daemon only by our rules.
FW_PROBE_PORT = 9
FW_PROBE_HOSTS = {"ipv4": "127.0.0.1", "ipv6": "::1"}

PROBE_TIMEOUT = 2.0
PROBE_TRIES = 3  # per protocol; a refused attempt is retried after 0.2 s
FW_PROBE_INTERVAL = 15.0
# After a failed round, the next ones come sooner: a flush is confirmed (and
# repaired) within ~15 + 2 * 5 s plus probe time, inside the 45 s recovery target, while
# three rounds still ride out a ~10 s hiccup (measured 47-50 s with 15 s).
FW_RETRY_INTERVAL = 5.0
FW_FAILURES_TO_RESTART = 3
INSTALL_CHECK_INTERVAL = 60.0
#: Event-loop stalls longer than this withhold the watchdog ping.
MAX_LOOP_LAG = 5.0
LAG_TICK = 0.5


class ProbeError(Exception):
    """A probe query failed; the message says why."""


def probe_query(nonce: str) -> tuple[int, bytes]:
    message = dns.message.make_query(f"{nonce}.{PROBE_ZONE}", dns.rdatatype.TXT)
    message.id = secrets.randbelow(65536)
    message.flags &= ~dns.flags.RD
    return message.id, message.to_wire()


def check_probe_reply(data: bytes, qid: int, nonce: str) -> None:
    try:
        reply = dns.message.from_wire(data)
    except Exception as exc:
        raise ProbeError(f"bad reply: {exc}") from None
    if reply.id != qid or not reply.flags & dns.flags.QR:
        raise ProbeError("reply does not match the query")
    if reply.rcode() != dns.rcode.NOERROR:
        raise ProbeError(f"rcode {dns.rcode.to_text(reply.rcode())}")
    expected = f"{PROBE_ANSWER_PREFIX}{nonce}".encode()
    for rrset in reply.answer:
        if rrset.rdtype == dns.rdatatype.TXT and any(expected in rdata.strings for rdata in rrset):
            return
    raise ProbeError("wrong answer")


class _ReplyProtocol(asyncio.DatagramProtocol):
    def __init__(self) -> None:
        self.reply: asyncio.Future[bytes] = asyncio.get_running_loop().create_future()

    def datagram_received(self, data: bytes, addr: Any) -> None:
        if not self.reply.done():
            self.reply.set_result(data)

    def error_received(self, exc: Exception) -> None:
        if not self.reply.done():
            self.reply.set_exception(exc)

    def connection_lost(self, exc: Exception | None) -> None:
        if not self.reply.done():
            self.reply.set_exception(exc or ConnectionError("closed"))


async def probe_once(host: str, port: int, proto: str, timeout: float = PROBE_TIMEOUT) -> None:
    """One probe query; raises :class:`ProbeError` (or ``ConnectionRefusedError``)."""
    nonce = secrets.token_hex(16)
    qid, wire = probe_query(nonce)
    loop = asyncio.get_running_loop()
    try:
        async with asyncio.timeout(timeout):
            if proto == "udp":
                transport, protocol = await loop.create_datagram_endpoint(_ReplyProtocol, remote_addr=(host, port))
                try:
                    transport.sendto(wire)
                    data = await protocol.reply
                finally:
                    transport.close()
            else:
                reader, writer = await asyncio.open_connection(host, port)
                try:
                    writer.write(len(wire).to_bytes(2, "big") + wire)
                    await writer.drain()
                    size = int.from_bytes(await reader.readexactly(2), "big")
                    data = await reader.readexactly(size)
                finally:
                    writer.close()
                    with contextlib.suppress(OSError):
                        await writer.wait_closed()
    except TimeoutError:
        raise ProbeError("timeout") from None
    except ConnectionRefusedError:
        raise
    except (OSError, asyncio.IncompleteReadError) as exc:
        raise ProbeError(f"error: {exc}") from None
    check_probe_reply(data, qid, nonce)


async def probe(host: str, port: int, *, timeout: float = PROBE_TIMEOUT, tries: int = PROBE_TRIES) -> str | None:
    """UDP then TCP, ``tries`` attempts each. None when both answer, else the last failure."""
    for proto in ("udp", "tcp"):
        failure = "not tried"
        for attempt in range(tries):
            try:
                await probe_once(host, port, proto, timeout)
            except ConnectionRefusedError:
                failure = "refused"
            except ProbeError as exc:
                failure = str(exc)
            else:
                failure = None
                break
            if failure != "timeout" and attempt + 1 < tries:
                await asyncio.sleep(0.2)
        if failure is not None:
            return f"{proto} {host}:{port}: {failure}"
    return None


def self_targets(addresses: Iterable[tuple[str, Any]]) -> list[tuple[str, int]]:
    """Where to probe our own listeners: one ``(host, port)`` per bound address.

    Only addresses with both a UDP and a TCP listener qualify (the probe uses
    both). Wildcard binds are probed on loopback.
    """
    kinds: dict[tuple[str, int], set[str]] = {}
    for kind, sockname in addresses:
        host, port = sockname[0], sockname[1]
        address = ipaddress.ip_address(host.split("%", 1)[0])
        if address.is_unspecified:
            host = "::1" if address.version == 6 else "127.0.0.1"
        kinds.setdefault((host, port), set()).add(kind)
    return [target for target, found in kinds.items() if found >= {"udp", "tcp"}]


def read_fw_state(path: Path = FW_STATE_PATH) -> list[str]:
    """Families ``blockads-fw`` applied and reports active (empty when none or unreadable)."""
    try:
        state = json.loads(path.read_text("utf-8"))
    except FileNotFoundError:
        return []
    except (OSError, ValueError) as exc:
        log.warning("cannot read %s: %s", path, exc)
        return []
    if not isinstance(state, dict) or state.get("applied") is not True:
        return []
    families = state.get("families")
    if not isinstance(families, dict):
        return []
    return [family for family in ("ipv4", "ipv6")
            if isinstance(families.get(family), dict) and families[family].get("status") == "active"]


def watchdog_interval(environ: dict[str, str] | None = None) -> float | None:
    """Seconds between watchdog pings (a third of ``WatchdogSec=``), or None when disabled."""
    env = os.environ if environ is None else environ
    try:
        usec = int(env.get("WATCHDOG_USEC", ""))
    except ValueError:
        return None
    pid = env.get("WATCHDOG_PID")
    if usec <= 0 or (pid and pid != str(os.getpid())):
        return None
    return usec / 3_000_000


def install_paths() -> list[Path]:
    """Files whose replacement means the running code is stale.

    The stdlib directory (a minor upgrade renames files into it, a major one
    removes it), ``os.py`` itself, and our package's ``__init__.py``.
    """
    import blockads_linux

    stdlib = Path(os.__file__).resolve()
    return [stdlib.parent, stdlib, Path(blockads_linux.__file__).resolve()]


def fingerprint(paths: Iterable[Path]) -> tuple:
    out = []
    for path in paths:
        try:
            st = path.stat()
        except OSError:
            out.append((str(path), None))
        else:
            out.append((str(path), st.st_dev, st.st_ino, st.st_mtime_ns, st.st_size))
    return tuple(out)


@dataclass(slots=True)
class Alert:
    kind: str
    message: str
    at: float = field(default_factory=time.time)


class Health:
    """The daemon's health loops. :meth:`run` returns only to request an exit.

    ``exit_code`` is set (to :data:`EXIT_RESTART`) when the daemon must restart.
    ``fw_state_path=None`` disables the interception probe (development mode).
    """

    def __init__(
        self,
        targets: Callable[[], list[tuple[str, int]]],
        *,
        fw_state_path: Path | None = FW_STATE_PATH,
        fw_probe_port: int = FW_PROBE_PORT,
        fw_probe_hosts: dict[str, str] | None = None,
        fw_interval: float = FW_PROBE_INTERVAL,
        fw_retry_interval: float = FW_RETRY_INTERVAL,
        fw_failures_to_restart: int = FW_FAILURES_TO_RESTART,
        watchdog: float | None = None,
        install_check: bool = True,
        install_interval: float = INSTALL_CHECK_INTERVAL,
        install_paths_: list[Path] | None = None,
        probe_timeout: float = PROBE_TIMEOUT,
        on_alert: Callable[[Alert], None] | None = None,
        notify: Callable[[str], Any] = sdnotify.notify,
    ) -> None:
        self._targets = targets
        self.fw_state_path = fw_state_path
        self.fw_probe_port = fw_probe_port
        self.fw_probe_hosts = dict(FW_PROBE_HOSTS if fw_probe_hosts is None else fw_probe_hosts)
        self.fw_interval = fw_interval
        self.fw_retry_interval = min(fw_retry_interval, fw_interval)
        self.fw_failures_to_restart = fw_failures_to_restart
        self.watchdog = watchdog
        self.install_check = install_check
        self.install_interval = install_interval
        self._install_paths = install_paths() if install_paths_ is None else install_paths_
        self.probe_timeout = probe_timeout
        self._on_alert = on_alert
        self._notify = notify

        self.exit_code: int | None = None
        self.exit_reason = ""
        self.alerts: list[Alert] = []
        self.healthy = True  # last self-check
        self.self_error: str | None = None
        self.fw_families: list[str] = []
        self.fw_failures = 0
        self.fw_error: str | None = None
        self.max_lag = 0.0
        self._poke = asyncio.Event()
        self._done = asyncio.Event()

    # --- public ----------------------------------------------------------------

    def poke(self) -> None:
        """Probe the interception now (network change, resume, firewall reload)."""
        self._poke.set()

    def summary(self) -> dict:
        return {
            "healthy": self.healthy,
            "self_error": self.self_error,
            "interception": self.fw_families,
            "interception_expected": self.fw_state_path is not None,  # False in --dev without --fw-state
            "interception_failures": self.fw_failures,
            "interception_error": self.fw_error,
            "max_loop_lag_ms": round(self.max_lag * 1000, 1),
        }

    async def run(self) -> int:
        """Run until a restart is needed; returns the exit code."""
        tasks = [asyncio.create_task(self._lag_loop()), asyncio.create_task(self._fw_loop())]
        if self.watchdog:
            tasks.append(asyncio.create_task(self._watchdog_loop()))
        if self.install_check:
            tasks.append(asyncio.create_task(self._install_loop()))
        try:
            await self._done.wait()
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
        assert self.exit_code is not None
        return self.exit_code

    # --- checks ----------------------------------------------------------------

    async def self_check(self) -> str | None:
        """None when the loop is responsive and every own listener answers."""
        lag, self.max_lag = self.max_lag, 0.0
        if lag > MAX_LOOP_LAG:
            return f"event loop stalled for {lag:.1f} s"
        targets = self._targets()
        if not targets:
            return "no listeners"
        for host, port in targets:
            failure = await probe(host, port, timeout=self.probe_timeout)
            if failure:
                return failure
        return None

    async def fw_check(self) -> str | None:
        """Probe each family the helper applied; None when all answer or none is applied."""
        if self.fw_state_path is None:
            return None
        self.fw_families = await asyncio.to_thread(read_fw_state, self.fw_state_path)
        for family in self.fw_families:
            host = self.fw_probe_hosts.get(family)
            if host is None:
                continue
            failure = await probe(host, self.fw_probe_port, timeout=self.probe_timeout)
            if failure:
                return f"{family}: {failure}"
        return None

    # --- loops -----------------------------------------------------------------

    def _restart(self, reason: str) -> None:
        if self.exit_code is None:
            self.exit_code = EXIT_RESTART
            self.exit_reason = reason
            log.error("restarting: %s", reason)
        self._done.set()

    def _alert(self, kind: str, message: str) -> None:
        alert = Alert(kind, message)
        self.alerts.append(alert)
        del self.alerts[:-20]
        log.warning("alert: %s", message)
        if self._on_alert is not None:
            try:
                self._on_alert(alert)
            except Exception:
                log.exception("alert handler failed")

    async def _lag_loop(self) -> None:
        loop = asyncio.get_running_loop()
        while True:
            start = loop.time()
            await asyncio.sleep(LAG_TICK)
            self.max_lag = max(self.max_lag, loop.time() - start - LAG_TICK)

    async def _watchdog_loop(self) -> None:
        while True:
            error = await self.self_check()
            if error is None:
                self._notify("WATCHDOG=1")
            elif self.healthy or error != self.self_error:
                log.warning("self-check failed, withholding the watchdog: %s", error)
            self.healthy, self.self_error = error is None, error
            await asyncio.sleep(self.watchdog)

    async def _fw_loop(self) -> None:
        while True:
            with contextlib.suppress(TimeoutError):
                async with asyncio.timeout(self.fw_retry_interval if self.fw_failures else self.fw_interval):
                    await self._poke.wait()
            self._poke.clear()
            error = await self.fw_check()
            if error is None:
                if self.fw_failures:
                    log.info("interception probe answers again")
                self.fw_failures, self.fw_error = 0, None
                continue
            self.fw_failures += 1
            self.fw_error = error
            log.warning("interception probe failed (%d/%d): %s", self.fw_failures,
                        self.fw_failures_to_restart, error)
            if self.fw_failures >= self.fw_failures_to_restart:
                self._alert("interception-lost", f"DNS interception stopped working ({error}); restarting")
                self._restart(f"interception probe failed {self.fw_failures} times: {error}")
                return

    async def _install_loop(self) -> None:
        initial = await asyncio.to_thread(fingerprint, self._install_paths)
        while True:
            await asyncio.sleep(self.install_interval)
            current = await asyncio.to_thread(fingerprint, self._install_paths)
            if current != initial:
                changed = [a[0] for a, b in zip(initial, current, strict=True) if a != b]
                self._restart(f"installed files changed: {', '.join(changed)}")
                return
