"""Local self-test (replaces Android's third-party "Test Ad Blocking" site).

1. Ask the daemon which of a few well-known ad domains it blocks (``TestDomain``).
2. Resolve that domain the way applications do (``getaddrinfo``, in a thread).
3. Blocked answers (``0.0.0.0``/``::``) or "no such name" mean the system's DNS
   goes through the filter; a real address means something bypasses it
   (another resolver cache, a VPN, browser DNS-over-HTTPS…).

Runs only when the user asks; a domain that is blocked is never sent out.
"""

from __future__ import annotations

import socket
import threading
from collections.abc import Callable
from typing import Any

from PyQt6.QtCore import QObject, pyqtSignal

from . import format as fmt
from .dbus_client import CallError, DaemonClient

CANDIDATES = ("doubleclick.net", "googleadservices.com", "adservice.google.com", "ads.yahoo.com",
              "static.ads-twitter.com", "ad.doubleclick.net")
BLOCKED_ADDRESSES = {"0.0.0.0", "::"}


def resolve(name: str) -> tuple[str, list[str]]:
    """("blocked" | "nxdomain" | "resolved" | "error", addresses)."""
    try:
        infos = socket.getaddrinfo(name, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        if exc.errno in (socket.EAI_NONAME, getattr(socket, "EAI_NODATA", -5)):
            return "nxdomain", []
        return "error", [str(exc)]
    addresses = sorted({info[4][0] for info in infos})
    if addresses and set(addresses) <= BLOCKED_ADDRESSES:
        return "blocked", addresses
    return "resolved", addresses


def verdict_text(domain: str, outcome: str, addresses: list[str]) -> tuple[bool, str]:
    name = fmt.safe(domain, 120)
    if outcome in ("blocked", "nxdomain"):
        return True, fmt.translate("SelfTest", "Working: %1 is blocked for applications on this computer.").replace("%1", name)
    if outcome == "resolved":
        return False, fmt.translate("SelfTest", "Not working: %1 resolved to %2. Something bypasses the filter (a VPN, another DNS "
                         "cache, or the interception is not applied).").replace("%1", name).replace(
            "%2", ", ".join(fmt.safe(a, 60) for a in addresses[:3]))
    return False, fmt.translate("SelfTest", "The test could not resolve %1: %2").replace("%1", name).replace(
        "%2", fmt.safe(" ".join(addresses), 200))


class SelfTest(QObject):
    finished = pyqtSignal(bool, str)
    _resolved = pyqtSignal(str, str, list)

    def __init__(self, client: DaemonClient, resolver: Callable[[str], tuple[str, list[str]]] = resolve,
                 candidates: tuple[str, ...] = CANDIDATES, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.client = client
        self.resolver = resolver
        self.candidates = candidates
        self.running = False
        self._resolved.connect(self._done)

    def start(self) -> None:
        if self.running:
            return
        self.running = True
        self._try(list(self.candidates))

    def _try(self, candidates: list[str]) -> None:
        if not candidates:
            self._finish(False, fmt.translate("SelfTest", "None of the test domains is blocked by your filters; enable an ad "
                                       "list and try again."))
            return
        domain = candidates.pop(0)

        def answer(result: dict[str, Any]) -> None:
            if result.get("verdict") == "blocked":
                threading.Thread(target=self._resolve, args=(domain,), daemon=True).start()
            else:
                self._try(candidates)

        def failed(error: CallError) -> None:
            self._finish(False, error.message if error.kind != "not_running"
                         else fmt.translate("SelfTest", "The filter service is not running."))

        self.client.call("TestDomain", domain).then(answer, failed)

    def _resolve(self, domain: str) -> None:
        outcome, addresses = self.resolver(domain)
        self._resolved.emit(domain, outcome, addresses)  # queued to the GUI thread

    def _done(self, domain: str, outcome: str, addresses: list) -> None:
        self._finish(*verdict_text(domain, outcome, addresses))

    def _finish(self, ok: bool, text: str) -> None:
        self.running = False
        self.finished.emit(ok, text)
