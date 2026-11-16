"""The daemon's D-Bus service.

Owns ``io.github.mateusbmp.BlockAds1`` on the system bus and serves
``/io/github/mateusbmp/BlockAds1``:

* our interface (``common.dbus_api.METHODS``): signature and size checks,
  at most 8 calls in flight per caller, then a polkit check for the method's
  action, then :class:`~.api.DaemonApi`;
* ``Introspectable.Introspect``, ``Properties.Get``/``GetAll`` (read-only;
  ``Set`` is refused) and ``Peer.Ping``.

Signals: ``StatusChanged`` (debounced), ``FiltersUpdated`` and ``Alert``;
never a domain name. The same connection watches ``NameOwnerChanged`` (a
caller left: cancel its polkit checks; firewalld restarted) and firewalld's
``Reloaded``, and asks systemd-resolved to flush its cache after a policy
change (allowed for user ``blockads`` by our polkit rule).

If the bus goes away the service reconnects with backoff; DNS keeps working
meanwhile. jeepney's filter queues are unbounded for method calls (it drops
silently when a queue is full); our own limits apply instead.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from collections.abc import Callable
from typing import Any

from jeepney import DBusAddress, MessageType, new_error, new_method_call, new_method_return, new_signal
from jeepney.bus_messages import MatchRule, message_bus
from jeepney.io.asyncio import open_dbus_router
from jeepney.low_level import HeaderFields, Message, MessageFlag

from .. import __version__
from ..common import dbus_api
from ..common.dbus_api import (
    API_VERSION,
    BUS_NAME,
    INTERFACE,
    MAX_ARRAY,
    MAX_INFLIGHT_PER_CALLER,
    MAX_JSON,
    MAX_STRING,
    METHODS,
    OBJECT_PATH,
    PROPERTIES,
    SIGNALS,
)
from .api import ApiError, DaemonApi
from .polkit import AllowAll, Authorizer, Decision

log = logging.getLogger("blockadsd.dbus")

DBUS_ERROR = "org.freedesktop.DBus.Error."
PROPERTIES_IFACE = "org.freedesktop.DBus.Properties"
INTROSPECTABLE_IFACE = "org.freedesktop.DBus.Introspectable"
PEER_IFACE = "org.freedesktop.DBus.Peer"
FIREWALLD_BUS = "org.fedoraproject.FirewallD1"
RESOLVED_BUS = "org.freedesktop.resolve1"
NAME_FLAG_DO_NOT_QUEUE = 4
NAME_PRIMARY_OWNER, NAME_ALREADY_OWNER = 1, 4
STATUS_DEBOUNCE = 0.3


class NameTaken(Exception):
    pass


class DBusService:
    def __init__(self, api: DaemonApi, *, bus: str = "SYSTEM", allow_all: bool = False,
                 status_summary: Callable[[], dict[str, Any]] | None = None,
                 on_firewall_reload: Callable[[], None] | None = None,
                 flush_resolved: bool = True, retry: float = 5.0,
                 authorizer_factory: Callable[[Any], Any] | None = None) -> None:
        self.api = api
        self.bus = bus
        self.allow_all = allow_all
        self.status_summary = status_summary
        self.on_firewall_reload = on_firewall_reload
        self.flush_resolved = flush_resolved
        self.retry = retry
        self.authorizer_factory = authorizer_factory or (lambda router: AllowAll() if allow_all else Authorizer(router))
        self.authorizer: Any = None
        self.ready = asyncio.Event()  # the name is owned
        self.unique_name: str | None = None
        self._router: Any = None
        self._inflight: dict[str, int] = {}
        self._tasks: set[asyncio.Task] = set()
        self._status_pending = False
        self._flush_pending = False

    # --- lifecycle -------------------------------------------------------------

    async def run(self) -> None:
        delay = 0.5
        while True:
            try:
                await self._session()
                delay = 0.5
            except asyncio.CancelledError:
                raise
            except NameTaken:
                log.warning("D-Bus: %s is owned by another process; retrying", BUS_NAME)
            except Exception as exc:
                log.warning("D-Bus service: %s; reconnecting", type(exc).__name__)
            finally:
                self._router = None
                self.ready.clear()
            await asyncio.sleep(delay)
            delay = min(delay * 2, self.retry)

    async def _session(self) -> None:
        async with open_dbus_router(self.bus) as router:
            calls: asyncio.Queue[Message] = asyncio.Queue()
            signals: asyncio.Queue[Message] = asyncio.Queue(1024)
            with router.filter(MatchRule(type="method_call"), queue=calls), \
                    router.filter(MatchRule(type="signal"), queue=signals):
                for rule in (
                    MatchRule(type="signal", sender="org.freedesktop.DBus", interface="org.freedesktop.DBus",
                              member="NameOwnerChanged"),
                    MatchRule(type="signal", sender=FIREWALLD_BUS, interface=FIREWALLD_BUS, member="Reloaded"),
                ):
                    await router.send_and_get_reply(message_bus.AddMatch(rule))
                reply = await router.send_and_get_reply(message_bus.RequestName(BUS_NAME, NAME_FLAG_DO_NOT_QUEUE))
                if reply.header.message_type == MessageType.error or reply.body[0] not in (
                        NAME_PRIMARY_OWNER, NAME_ALREADY_OWNER):
                    raise NameTaken()
                self._router = router
                self.unique_name = router.unique_name
                self.authorizer = self.authorizer_factory(router)
                self.ready.set()
                log.info("D-Bus: serving %s", BUS_NAME)
                watcher = asyncio.create_task(self._watch_signals(signals))
                try:
                    while True:
                        message = await calls.get()
                        self._spawn(self._handle(message))
                finally:
                    watcher.cancel()
                    with contextlib.suppress(asyncio.CancelledError):
                        await watcher
                    for task in list(self._tasks):
                        task.cancel()
                    await asyncio.gather(*self._tasks, return_exceptions=True)
                    self._inflight.clear()

    def _spawn(self, coroutine: Any) -> None:
        task = asyncio.get_running_loop().create_task(coroutine)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    # --- signals ----------------------------------------------------------------

    def status_changed(self) -> None:
        """Emit StatusChanged soon (several changes in a burst emit once) and flush resolved's cache."""
        if self._router is None:
            return
        if not self._status_pending:
            self._status_pending = True
            self._spawn(self._emit_status())
        if self.flush_resolved and not self._flush_pending:
            self._flush_pending = True
            self._spawn(self._flush())

    def filters_updated(self, generation: int) -> None:
        self._emit("FiltersUpdated", (generation,))
        self.status_changed()

    def alert(self, kind: str, message: str) -> None:
        self._emit("Alert", (kind, message))
        self.status_changed()

    async def _emit_status(self) -> None:
        await asyncio.sleep(STATUS_DEBOUNCE)
        self._status_pending = False
        summary = self.status_summary() if self.status_summary else {}
        self._emit("StatusChanged", (json.dumps({"api": API_VERSION, **summary}, separators=(",", ":")),))

    def _emit(self, name: str, body: tuple) -> None:
        router = self._router
        if router is None:
            return
        signature = SIGNALS[name][0]
        message = new_signal(DBusAddress(OBJECT_PATH, interface=INTERFACE), name, signature, body)
        self._spawn(self._send(router, message))

    @staticmethod
    async def _send(router: Any, message: Message) -> None:
        with contextlib.suppress(Exception):
            await router.send(message)

    async def _flush(self) -> None:
        await asyncio.sleep(STATUS_DEBOUNCE)
        self._flush_pending = False
        router = self._router
        if router is None:
            return
        message = new_method_call(DBusAddress("/org/freedesktop/resolve1", RESOLVED_BUS,
                                              "org.freedesktop.resolve1.Manager"), "FlushCaches")
        try:
            async with asyncio.timeout(2):
                await router.send_and_get_reply(message)
        except Exception:  # resolved not running, or not allowed: the 10 s block TTL still applies
            pass

    async def _watch_signals(self, queue: asyncio.Queue[Message]) -> None:
        while True:
            message = await queue.get()
            fields = message.header.fields
            member = fields.get(HeaderFields.member)
            body = message.body or ()
            if member == "NameOwnerChanged" and len(body) == 3:
                name, _old, new = body
                if not new and name.startswith(":"):
                    if self.authorizer is not None:
                        self.authorizer.forget(name)
                elif name == FIREWALLD_BUS and new:
                    self._firewall_reloaded()
            elif member == "Reloaded" and fields.get(HeaderFields.interface) == FIREWALLD_BUS:
                self._firewall_reloaded()

    def _firewall_reloaded(self) -> None:
        log.info("firewalld reloaded: checking the interception now")
        if self.on_firewall_reload is not None:
            self.on_firewall_reload()

    # --- method calls -------------------------------------------------------------

    async def _handle(self, message: Message) -> None:
        reply = await self._answer(message)
        if reply is not None and not message.header.flags & MessageFlag.no_reply_expected:
            router = self._router
            if router is not None:
                await self._send(router, reply)

    async def _answer(self, message: Message) -> Message | None:
        fields = message.header.fields
        path = fields.get(HeaderFields.path)
        interface = fields.get(HeaderFields.interface)
        member = fields.get(HeaderFields.member)
        signature = fields.get(HeaderFields.signature, "")
        if path != OBJECT_PATH:
            return new_error(message, DBUS_ERROR + "UnknownObject", "s", (f"no object at {path}",))
        if interface in (None, INTERFACE) and member in METHODS:
            return await self._call(message, METHODS[member], signature)
        if interface in (None, INTROSPECTABLE_IFACE) and member == "Introspect" and not signature:
            return new_method_return(message, "s", (dbus_api.introspection_xml(),))
        if interface == PROPERTIES_IFACE:
            return self._properties(message, member, signature)
        if interface in (None, PEER_IFACE) and member == "Ping" and not signature:
            return new_method_return(message)
        return new_error(message, DBUS_ERROR + "UnknownMethod", "s", (f"unknown method {member}",))

    def _properties(self, message: Message, member: str | None, signature: str) -> Message:
        values = {"Version": ("s", __version__), "ApiVersion": ("u", API_VERSION)}
        assert set(values) == set(PROPERTIES)
        if member == "Get" and signature == "ss":
            iface, name = message.body
            if iface == INTERFACE and name in values:
                return new_method_return(message, "v", (values[name],))
            return new_error(message, DBUS_ERROR + "UnknownProperty", "s", ("no such property",))
        if member == "GetAll" and signature == "s":
            return new_method_return(message, "a{sv}", (values if message.body[0] in (INTERFACE, "") else {},))
        if member == "Set":
            return new_error(message, DBUS_ERROR + "PropertyReadOnly", "s", ("properties are read-only",))
        return new_error(message, DBUS_ERROR + "UnknownMethod", "s", ("unknown method",))

    async def _call(self, message: Message, method: dbus_api.Method, signature: str) -> Message:
        sender = message.header.fields.get(HeaderFields.sender)
        if not sender:
            return new_error(message, DBUS_ERROR + "AccessDenied", "s", ("no sender",))
        if signature != method.in_sig:
            return new_error(message, DBUS_ERROR + "InvalidArgs", "s",
                             (f"{method.name} takes ({method.in_sig}), got ({signature})",))
        problem = check_limits(message.body, method)
        if problem:
            return new_error(message, DBUS_ERROR + "LimitsExceeded", "s", (problem,))
        if self._inflight.get(sender, 0) >= MAX_INFLIGHT_PER_CALLER:
            return new_error(message, DBUS_ERROR + "LimitsExceeded", "s", ("too many calls in flight",))
        self._inflight[sender] = self._inflight.get(sender, 0) + 1
        try:
            interactive = bool(message.header.flags & MessageFlag.allow_interactive_authorization)
            decision = await self.authorizer.check(sender, method.action, interactive=interactive)
            if decision is Decision.INTERACTIVE_REQUIRED:
                return new_error(message, DBUS_ERROR + "InteractiveAuthorizationRequired", "s",
                                 ("authentication is required; allow interactive authorization",))
            if decision is not Decision.AUTHORIZED:
                return new_error(message, DBUS_ERROR + "AccessDenied", "s", ("not authorized",))
            try:
                result = await getattr(self.api, method.name)(*message.body)
            except ApiError as exc:
                name = DBUS_ERROR + "InvalidArgs" if exc.kind == "InvalidArgs" else dbus_api.error_name(exc.kind)
                return new_error(message, name, "s", (exc.message[:MAX_STRING],))
            except Exception as exc:
                # Exception text may contain a domain name: log and return the type only.
                log.error("%s failed: %s", method.name, type(exc).__name__)
                log.debug("details", exc_info=True)
                return new_error(message, dbus_api.error_name("Failed"), "s", (type(exc).__name__,))
            if method.out_sig:
                return new_method_return(message, method.out_sig, (result,))
            return new_method_return(message)
        finally:
            count = self._inflight.get(sender, 1) - 1
            if count:
                self._inflight[sender] = count
            else:
                self._inflight.pop(sender, None)


def check_limits(body: tuple, method: dbus_api.Method) -> str | None:
    """Size limits: strings 4 KiB (JSON 64 KiB), arrays 1000 items."""
    for index, value in enumerate(body):
        limit = MAX_JSON if index in method.json_args else MAX_STRING
        if isinstance(value, str) and len(value.encode("utf-8", "surrogatepass")) > limit:
            return f"argument {index} is longer than {limit} bytes"
        if isinstance(value, list):
            if len(value) > MAX_ARRAY:
                return f"argument {index} has more than {MAX_ARRAY} items"
            if any(isinstance(item, str) and len(item.encode("utf-8", "surrogatepass")) > MAX_STRING
                   for item in value):
                return f"argument {index} has an item longer than {MAX_STRING} bytes"
    return None
