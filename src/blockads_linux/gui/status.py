"""One shared view of the daemon's status for the window, pages and tray.

Polls ``GetStatus`` (every 2 s while a window is visible, every 15 s for the
tray alone) and right away on ``StatusChanged``/``FiltersUpdated``/``Alert``
or when the daemon appears on the bus. ``state`` is the tray/shield state.
"""

from __future__ import annotations

from typing import Any

from PyQt6.QtCore import QObject, QTimer, pyqtSignal

from .dbus_client import CallError, DaemonClient

FAST_MS = 2000
SLOW_MS = 15000


def overall_state(status: dict[str, Any] | None, available: bool) -> str:
    """active (green) | paused (yellow) | off (grey: not running) | error (red: running but not protecting)."""
    if not available or status is None:
        return "off"
    if status.get("protection", {}).get("state") in ("paused", "trusted"):
        return "paused"  # "trusted": a trusted network in pause mode
    health = status.get("health")
    if health is not None and (not health.get("healthy", True) or health.get("interception_error")):
        return "error"
    if health is not None and health.get("interception_expected") and not health.get("interception"):
        return "error"  # blockads-fw has not applied the redirect: applications bypass the filter
    if status.get("alerts"):
        return "error"
    return "active"


class StatusModel(QObject):
    updated = pyqtSignal(dict)
    state_changed = pyqtSignal(str)
    unavailable = pyqtSignal(object)  # CallError | None

    def __init__(self, client: DaemonClient, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.client = client
        self.status: dict[str, Any] | None = None
        self.state = "off"
        self.error: CallError | None = None
        self._in_flight = False
        self._again = False
        self.timer = QTimer(self)
        self.timer.setInterval(SLOW_MS)
        self.timer.timeout.connect(self.refresh)
        # bound methods, not lambdas: PyQt disconnects them when this object is deleted
        client.status_changed.connect(self.refresh)
        client.filters_updated.connect(self.refresh)
        client.alert.connect(self.refresh)
        client.available_changed.connect(self._available)

    def start(self) -> None:
        self.timer.start()
        self.refresh()

    def set_fast(self, fast: bool) -> None:
        self.timer.setInterval(FAST_MS if fast else SLOW_MS)

    def refresh(self, *_signal_args: object) -> None:
        if not self.client.connected:
            self._set(None, CallError("not_running", "cannot connect to the D-Bus bus"))
            return
        if self._in_flight:
            self._again = True
            return
        self._in_flight = True
        self.client.call("GetStatus").then(self._got, self._failed)

    def _got(self, status: dict[str, Any]) -> None:
        self._in_flight = False
        self._set(status if isinstance(status, dict) else None, None)
        self._again_if_needed()

    def _failed(self, error: CallError) -> None:
        self._in_flight = False
        self._set(None, error)
        self._again_if_needed()

    def _again_if_needed(self) -> None:
        if self._again:
            self._again = False
            self.refresh()

    def _available(self, available: bool) -> None:
        if available:
            self.refresh()
        else:
            self._set(None, CallError("not_running", "the daemon is not running"))

    def _set(self, status: dict[str, Any] | None, error: CallError | None) -> None:
        self.status, self.error = status, error
        if status is not None:
            self.updated.emit(status)
        else:
            self.unavailable.emit(error)
        state = overall_state(status, status is not None)
        if state != self.state:
            self.state = state
            self.state_changed.emit(state)
