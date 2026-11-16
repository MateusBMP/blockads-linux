"""Start/stop our units through systemd's D-Bus API.

Starting needs no password for an active local user (our polkit rule);
stopping keeps systemd's ``auth_admin_keep``. Only on the system bus: in
development (``--bus session`` or an address) there is no unit to start.
"""

from __future__ import annotations

from PyQt6.QtCore import QObject
from PyQt6.QtDBus import QDBusConnection, QDBusMessage

from ..common import dbus_api
from .dbus_client import INTERACTIVE_TIMEOUT_MS, PendingReply

SYSTEMD = ("org.freedesktop.systemd1", "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager")
# Stopping only the service would leave the sockets to start it again on the next connection.
UNITS_STOP = ("blockadsd.service", "blockadsd.socket", "blockadsd-ipv6.socket", "blockadsd-bridge.socket")


class SystemdClient(QObject):
    def __init__(self, connection: QDBusConnection, enabled: bool, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.connection = connection
        self.enabled = enabled

    def call_unit(self, verb: str, unit: str) -> PendingReply:
        """StartUnit, StopUnit, TryRestartUnit… (unit, "replace") -> job path."""
        # PendingReply needs a Method; systemd's are not part of our API table.
        method = dbus_api.Method(verb, "ss", "o", dbus_api.VIEW)
        message = QDBusMessage.createMethodCall(*SYSTEMD, verb)
        message.setArguments([unit, "replace"])
        message.setInteractiveAuthorizationAllowed(True)
        return PendingReply(method, self.connection.asyncCall(message, INTERACTIVE_TIMEOUT_MS), self)

    def start(self, unit: str) -> PendingReply:
        return self.call_unit("StartUnit", unit)

    def stop(self, unit: str) -> PendingReply:
        return self.call_unit("StopUnit", unit)
