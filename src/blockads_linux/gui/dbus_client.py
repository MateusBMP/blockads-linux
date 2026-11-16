"""Asynchronous client for the daemon's D-Bus API.

Every call is asynchronous (``QDBusConnection.asyncCall`` + a
``QDBusPendingCallWatcher``); the GUI never blocks on the bus. Arguments are
marshalled from the method's signature in ``common.dbus_api``, so the GUI and
the daemon cannot disagree about types.

Calls of actions other than ``view`` carry the ALLOW_INTERACTIVE_AUTHORIZATION
flag: the desktop's polkit agent asks for the password when the action needs
it, and the daemon waits up to ``AUTH_TIMEOUT`` for the answer.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from PyQt6.QtCore import QMetaType, QObject, pyqtSignal, pyqtSlot
from PyQt6.QtDBus import (
    QDBusArgument,
    QDBusConnection,
    QDBusMessage,
    QDBusPendingCall,
    QDBusPendingCallWatcher,
    QDBusPendingReply,
    QDBusServiceWatcher,
)

from ..common import dbus_api

NOT_RUNNING = frozenset({"org.freedesktop.DBus.Error.ServiceUnknown", "org.freedesktop.DBus.Error.NameHasNoOwner",
                         "org.freedesktop.DBus.Error.NoReply", "org.freedesktop.DBus.Error.Disconnected"})
DENIED = frozenset({"org.freedesktop.DBus.Error.AccessDenied",
                    "org.freedesktop.DBus.Error.InteractiveAuthorizationRequired"})
VIEW_TIMEOUT_MS = 30_000
INTERACTIVE_TIMEOUT_MS = int((dbus_api.AUTH_TIMEOUT + 10) * 1000)

_SCALARS = {"t": QMetaType.Type.ULongLong, "u": QMetaType.Type.UInt}


class CallError(Exception):
    """``kind``: not_running | denied | invalid | read_only | unavailable | failed."""

    def __init__(self, kind: str, message: str, name: str = "") -> None:
        super().__init__(message)
        self.kind = kind
        self.message = message
        self.name = name


def classify_error(name: str, message: str) -> CallError:
    if name in NOT_RUNNING:
        return CallError("not_running", message, name)
    if name in DENIED:
        return CallError("denied", message, name)
    if name in ("org.freedesktop.DBus.Error.InvalidArgs", "org.freedesktop.DBus.Error.LimitsExceeded"):
        return CallError("invalid", message, name)
    short = name[len(dbus_api.ERROR_PREFIX):] if name.startswith(dbus_api.ERROR_PREFIX) else ""
    kind = {"ReadOnly": "read_only", "Unavailable": "unavailable"}.get(short, "failed")
    return CallError(kind, message or name, name)


def marshal(method: dbus_api.Method, args: tuple[Any, ...]) -> list[Any]:
    """Python values -> QtDBus arguments typed exactly as the method's signature."""
    parts = dbus_api._split_signature(method.in_sig)
    if len(parts) != len(args):
        raise TypeError(f"{method.name} takes {len(parts)} arguments, got {len(args)}")
    out: list[Any] = []
    for part, value in zip(parts, args):
        if part == "s":
            out.append(str(value))
        elif part == "b":
            out.append(bool(value))
        elif part in _SCALARS:
            out.append(QDBusArgument(int(value), _SCALARS[part].value))
        elif part == "as":
            out.append(QDBusArgument([str(v) for v in value], QMetaType.Type.QStringList.value))
        else:  # pragma: no cover - the API table has no other types
            raise TypeError(f"unsupported D-Bus type {part!r}")
    return out


class PendingReply(QObject):
    """One call in flight. ``finished(result)`` or ``failed(CallError)``; then it deletes itself."""

    finished = pyqtSignal(object)
    failed = pyqtSignal(object)

    def __init__(self, method: dbus_api.Method, call: QDBusPendingCall, parent: QObject) -> None:
        super().__init__(parent)
        self.method = method
        self._watcher = QDBusPendingCallWatcher(call, self)
        self._watcher.finished.connect(self._done)

    def then(self, on_result: Callable[[Any], None] | None = None,
             on_error: Callable[[CallError], None] | None = None) -> PendingReply:
        if on_result is not None:
            self.finished.connect(on_result)
        if on_error is not None:
            self.failed.connect(on_error)
        return self

    @pyqtSlot(QDBusPendingCallWatcher)
    def _done(self, watcher: QDBusPendingCallWatcher) -> None:
        reply = QDBusPendingReply(watcher).reply()
        try:
            if reply.type() == QDBusMessage.MessageType.ErrorMessage:
                self.failed.emit(classify_error(reply.errorName(), reply.errorMessage()))
                return
            values = reply.arguments()
            if not self.method.out_sig:
                self.finished.emit(None)
                return
            value = values[0] if values else ""
            if self.method.out_sig == "s" and self.method.out.endswith("_json"):
                try:
                    value = json.loads(value)
                except ValueError:
                    self.failed.emit(CallError("failed", "the daemon sent a malformed reply"))
                    return
            self.finished.emit(value)
        finally:
            watcher.deleteLater()
            self.deleteLater()


class DaemonClient(QObject):
    """The GUI's view of ``blockadsd``: calls, availability and the three signals."""

    available_changed = pyqtSignal(bool)
    status_changed = pyqtSignal(dict)  # the signal's summary (no names)
    filters_updated = pyqtSignal(int)
    alert = pyqtSignal(str, str)
    call_failed = pyqtSignal(str, object)  # method, CallError: for a central error display

    def __init__(self, bus: str = "system", parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.bus = bus
        self.connection = connect_bus(bus)
        self.available = False
        if not self.connection.isConnected():
            return
        self._watcher = QDBusServiceWatcher(
            dbus_api.BUS_NAME, self.connection,
            QDBusServiceWatcher.WatchModeFlag.WatchForRegistration
            | QDBusServiceWatcher.WatchModeFlag.WatchForUnregistration, self)
        self._watcher.serviceRegistered.connect(lambda _name: self._set_available(True))
        self._watcher.serviceUnregistered.connect(lambda _name: self._set_available(False))
        for name in dbus_api.SIGNALS:
            self.connection.connect(dbus_api.BUS_NAME, dbus_api.OBJECT_PATH, dbus_api.INTERFACE, name,
                                    self._signal)
        interface = self.connection.interface()
        self.available = bool(interface is not None and interface.isServiceRegistered(dbus_api.BUS_NAME).value())

    @property
    def connected(self) -> bool:
        return self.connection.isConnected()

    def call(self, name: str, *args: Any, interactive: bool | None = None) -> PendingReply:
        method = dbus_api.METHODS[name]
        message = QDBusMessage.createMethodCall(dbus_api.BUS_NAME, dbus_api.OBJECT_PATH, dbus_api.INTERFACE, name)
        message.setArguments(marshal(method, args))
        if interactive is None:
            interactive = method.action != dbus_api.VIEW
        message.setInteractiveAuthorizationAllowed(interactive)
        timeout = INTERACTIVE_TIMEOUT_MS if interactive else VIEW_TIMEOUT_MS
        pending = PendingReply(method, self.connection.asyncCall(message, timeout), self)
        pending.failed.connect(lambda error, n=name: self._failed(n, error))
        return pending

    def _failed(self, name: str, error: CallError) -> None:
        if error.kind == "not_running":
            self._set_available(False)
        self.call_failed.emit(name, error)

    def _set_available(self, value: bool) -> None:
        if value != self.available:
            self.available = value
            self.available_changed.emit(value)

    @pyqtSlot(QDBusMessage)
    def _signal(self, message: QDBusMessage) -> None:
        name, args = message.member(), message.arguments()
        if name == "StatusChanged" and args:
            try:
                summary = json.loads(args[0])
            except ValueError:
                return
            self._set_available(True)
            self.status_changed.emit(summary if isinstance(summary, dict) else {})
        elif name == "FiltersUpdated" and args:
            self.filters_updated.emit(int(args[0]))
        elif name == "Alert" and len(args) >= 2:
            self.alert.emit(str(args[0]), str(args[1]))


def connect_bus(bus: str) -> QDBusConnection:
    """``system``, ``session`` or a bus address (tests, development)."""
    if bus == "system":
        return QDBusConnection.systemBus()
    if bus == "session":
        return QDBusConnection.sessionBus()
    return QDBusConnection.connectToBus(bus, f"blockads-{abs(hash(bus))}")
