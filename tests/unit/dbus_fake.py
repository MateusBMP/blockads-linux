"""A private dbus-daemon and a fake system service for the netmon tests.

The fake owns well-known names (NetworkManager, resolved, logind) on a
throwaway bus, answers ``Properties.GetAll``/``Get`` and resolve1 ``GetLink``
from a table of typed properties, and emits ``PropertiesChanged`` and
``PrepareForSleep`` on request.
"""

from __future__ import annotations

import asyncio
import contextlib
import shutil
import subprocess

from jeepney import DBusAddress, MessageType, new_error, new_method_return, new_signal
from jeepney.bus_messages import MatchRule, message_bus
from jeepney.io.asyncio import open_dbus_router
from jeepney.low_level import HeaderFields

PROPERTIES = "org.freedesktop.DBus.Properties"


def have_dbus_daemon() -> bool:
    return shutil.which("dbus-daemon") is not None


@contextlib.contextmanager
def private_bus():
    """Start a session-config dbus-daemon; yield its address."""
    proc = subprocess.Popen(["dbus-daemon", "--session", "--nofork", "--nopidfile", "--print-address=1"],
                            stdout=subprocess.PIPE, text=True)
    try:
        address = proc.stdout.readline().strip()
        if not address:
            raise RuntimeError("dbus-daemon did not start")
        yield address
    finally:
        proc.terminate()
        proc.wait(timeout=5)


class FakeService:
    """``objects[(path, interface)] = {name: (signature, value)}``."""

    def __init__(self, address: str, names: list[str]) -> None:
        self.address = address
        self.names = names
        self.objects: dict[tuple[str, str], dict[str, tuple[str, object]]] = {}
        self.links: dict[int, str] = {}  # resolve1 GetLink: ifindex -> object path
        self.calls = 0
        self._router = None
        self._task = None
        self._stack = contextlib.AsyncExitStack()

    async def __aenter__(self) -> FakeService:
        self._router = await self._stack.enter_async_context(open_dbus_router(self.address))
        queue: asyncio.Queue = asyncio.Queue()
        self._stack.enter_context(self._router.filter(MatchRule(type="method_call"), queue=queue))
        for name in self.names:
            await self._router.send_and_get_reply(message_bus.RequestName(name))
        self._task = asyncio.create_task(self._serve(queue))
        return self

    async def __aexit__(self, *exc) -> None:
        self._task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await self._task
        await self._stack.aclose()

    async def _serve(self, queue: asyncio.Queue) -> None:
        while True:
            msg = await queue.get()
            if msg.header.message_type != MessageType.method_call:
                continue
            self.calls += 1
            await self._router.send(self._answer(msg))

    def _answer(self, msg):
        fields = msg.header.fields
        path, member = fields[HeaderFields.path], fields[HeaderFields.member]
        interface = fields.get(HeaderFields.interface)
        if interface == PROPERTIES and member == "GetAll":
            props = self.objects.get((path, msg.body[0]))
            if props is None:
                return new_error(msg, "org.freedesktop.DBus.Error.UnknownObject")
            return new_method_return(msg, "a{sv}", (dict(props),))
        if interface == PROPERTIES and member == "Get":
            props = self.objects.get((path, msg.body[0]), {})
            if msg.body[1] not in props:
                return new_error(msg, "org.freedesktop.DBus.Error.UnknownProperty")
            return new_method_return(msg, "v", (props[msg.body[1]],))
        if member == "GetLink" and msg.body[0] in self.links:
            return new_method_return(msg, "o", (self.links[msg.body[0]],))
        return new_error(msg, "org.freedesktop.DBus.Error.UnknownMethod")

    async def changed(self, path: str, interface: str, **props: tuple[str, object]) -> None:
        """Update properties and emit PropertiesChanged."""
        self.objects.setdefault((path, interface), {}).update(props)
        signal = new_signal(DBusAddress(path, interface=PROPERTIES), "PropertiesChanged", "sa{sv}as",
                            (interface, dict(props), []))
        await self._router.send(signal)

    async def signal(self, path: str, interface: str, member: str, signature: str, body: tuple) -> None:
        await self._router.send(new_signal(DBusAddress(path, interface=interface), member, signature, body))
