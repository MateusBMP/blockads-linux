"""Tests for daemon.dbus_service and daemon.polkit on a private dbus-daemon,
with a fake polkit authority on the same bus."""

import asyncio
import contextlib
import json
import xml.etree.ElementTree as ET

import pytest
from jeepney import DBusAddress, MessageType, new_error, new_method_call, new_method_return, new_signal
from jeepney.bus_messages import MatchRule
from jeepney.io.asyncio import open_dbus_router
from jeepney.low_level import HeaderFields, MessageFlag

from blockads_linux.common import dbus_api
from blockads_linux.common.atomic import load_json
from blockads_linux.daemon.api import DaemonApi
from blockads_linux.daemon.dbus_service import DBusService, check_limits
from blockads_linux.daemon.polkit import Authorizer
from blockads_linux.daemon.state import StateManager

from .dbus_fake import have_dbus_daemon, private_bus
from .test_state import CATALOG, setup_state

pytestmark = pytest.mark.skipif(not have_dbus_daemon(), reason="needs dbus-daemon")

DAEMON = DBusAddress(dbus_api.OBJECT_PATH, dbus_api.BUS_NAME, dbus_api.INTERFACE)


class FakePolkit:
    """Answers CheckAuthorization from ``results[action]`` = "yes" | "challenge" | "no" | "hold"."""

    def __init__(self, address):
        self.address = address
        self.results = {}
        self.checks = []  # (subject name, action, flags, cancel id)
        self.cancelled = []
        self._held = {}  # cancel id -> request message
        self._stack = contextlib.AsyncExitStack()

    async def __aenter__(self):
        self.router = await self._stack.enter_async_context(open_dbus_router(self.address))
        queue = asyncio.Queue()
        self._stack.enter_context(self.router.filter(MatchRule(type="method_call"), queue=queue))
        from jeepney.bus_messages import message_bus
        await self.router.send_and_get_reply(message_bus.RequestName("org.freedesktop.PolicyKit1"))
        self._task = asyncio.create_task(self._serve(queue))
        return self

    async def __aexit__(self, *exc):
        self._task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await self._task
        await self._stack.aclose()

    async def _serve(self, queue):
        while True:
            msg = await queue.get()
            member = msg.header.fields[HeaderFields.member]
            if member == "CheckAuthorization":
                subject, action, _details, flags, cancel_id = msg.body
                self.checks.append((subject[1]["name"][1], action, flags, cancel_id))
                result = self.results.get(action, "yes")
                if result == "hold":
                    self._held[cancel_id] = msg
                    continue
                body = {"yes": (True, False, {}), "challenge": (False, True, {}), "no": (False, False, {})}[result]
                if result == "challenge" and flags & 1:
                    body = (True, False, {})  # the user typed the password
                await self.router.send(new_method_return(msg, "(bba{ss})", (body,)))
            elif member == "CancelCheckAuthorization":
                self.cancelled.append(msg.body[0])
                held = self._held.pop(msg.body[0], None)
                if held is not None:
                    await self.router.send(new_error(held, "org.freedesktop.PolicyKit1.Error.Cancelled"))
                await self.router.send(new_method_return(msg))

    async def release(self):
        for cancel_id, msg in list(self._held.items()):
            del self._held[cancel_id]
            await self.router.send(new_method_return(msg, "(bba{ss})", ((True, False, {}),)))


@contextlib.asynccontextmanager
async def daemon_on_bus(tmp_path, **service_kwargs):
    paths = setup_state(tmp_path)
    state = StateManager(paths, catalog=CATALOG)
    state.load()
    api = DaemonApi(state, store=None, health=None, forwarder=None)
    with private_bus() as address:
        async with FakePolkit(address) as polkit:
            service = DBusService(api, bus=address, flush_resolved=False,
                                  status_summary=lambda: {"protection": "paused" if state.paused else "active"},
                                  **service_kwargs)
            task = asyncio.create_task(service.run())
            try:
                async with asyncio.timeout(5):
                    await service.ready.wait()
                yield address, service, polkit, paths
            finally:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task


async def call(router, method, signature="", body=(), *, interactive=False, address=DAEMON, interface=None):
    target = address if interface is None else DBusAddress(address.object_path, address.bus_name, interface)
    msg = new_method_call(target, method, signature, body)
    if interactive:
        msg.header.flags |= MessageFlag.allow_interactive_authorization
    async with asyncio.timeout(10):
        reply = await router.send_and_get_reply(msg)
    if reply.header.message_type == MessageType.error:
        return "error", reply.header.fields[HeaderFields.error_name], reply.body
    return "ok", reply.body


def test_view_calls_and_cache(tmp_path):
    async def go():
        async with daemon_on_bus(tmp_path) as (address, _service, polkit, _paths):
            async with open_dbus_router(address) as client:
                kind, body = await call(client, "GetStatus")
                assert kind == "ok" and json.loads(body[0])["protection"]["state"] == "active"
                kind, body = await call(client, "TestDomain", "s", ("x.ads.example",))
                assert json.loads(body[0])["verdict"] == "blocked"
                assert [c[1] for c in polkit.checks] == [dbus_api.VIEW]  # cached for 60 s
                assert polkit.checks[0][0] == client.unique_name and polkit.checks[0][2] == 0

    asyncio.run(go())


def test_weaken_needs_interactive_authorization(tmp_path):
    async def go():
        async with daemon_on_bus(tmp_path) as (address, _service, polkit, paths):
            polkit.results[dbus_api.WEAKEN] = "challenge"
            async with open_dbus_router(address) as client:
                result = await call(client, "Pause", "t", (60,))
                assert result[:2] == ("error", "org.freedesktop.DBus.Error.InteractiveAuthorizationRequired")
                assert load_json(paths.settings, lambda d: d).document["protection"] == {}
                kind, _ = await call(client, "Pause", "t", (60,), interactive=True)
                assert kind == "ok"
                assert polkit.checks[-1][1:3] == (dbus_api.WEAKEN, 1)
                assert load_json(paths.settings, lambda d: d).document["protection"]["paused"] is True
                polkit.results[dbus_api.TIGHTEN] = "no"
                result = await call(client, "Resume", interactive=True)
                assert result[:2] == ("error", "org.freedesktop.DBus.Error.AccessDenied")
                # weaken decisions are never cached
                weaken_checks = [c for c in polkit.checks if c[1] == dbus_api.WEAKEN]
                assert len(weaken_checks) == 2

    asyncio.run(go())


def test_bad_arguments_and_limits(tmp_path):
    async def go():
        async with daemon_on_bus(tmp_path) as (address, _service, polkit, _paths):
            async with open_dbus_router(address) as client:
                result = await call(client, "Pause", "s", ("60",))
                assert result[:2] == ("error", "org.freedesktop.DBus.Error.InvalidArgs")
                result = await call(client, "AddBlockRule", "s", ("a" * 5000,))
                assert result[:2] == ("error", "org.freedesktop.DBus.Error.LimitsExceeded")
                result = await call(client, "EnableFilters", "as", (["x"] * 1001,))
                assert result[:2] == ("error", "org.freedesktop.DBus.Error.LimitsExceeded")
                assert polkit.checks == []  # rejected before polkit is asked
                result = await call(client, "AddBlockRule", "s", ("not a domain",))
                assert result[:2] == ("error", "org.freedesktop.DBus.Error.InvalidArgs")
                result = await call(client, "NoSuchMethod")
                assert result[:2] == ("error", "org.freedesktop.DBus.Error.UnknownMethod")
                result = await call(client, "GetStatus", address=DBusAddress("/elsewhere", dbus_api.BUS_NAME,
                                                                            dbus_api.INTERFACE))
                assert result[:2] == ("error", "org.freedesktop.DBus.Error.UnknownObject")

    asyncio.run(go())


def test_introspection_and_properties(tmp_path):
    async def go():
        async with daemon_on_bus(tmp_path) as (address, _service, _polkit, _paths):
            async with open_dbus_router(address) as client:
                kind, body = await call(client, "Introspect", interface="org.freedesktop.DBus.Introspectable")
                root = ET.fromstring(body[0].split("\n", 2)[2])
                ours = root.find(f"interface[@name='{dbus_api.INTERFACE}']")
                assert {m.get("name") for m in ours.findall("method")} == set(dbus_api.METHODS)
                pause = ours.find("method[@name='GetQueryLog']")
                assert [a.get("type") for a in pause.findall("arg")] == ["s", "t", "u", "s"]
                props = "org.freedesktop.DBus.Properties"
                kind, body = await call(client, "Get", "ss", (dbus_api.INTERFACE, "ApiVersion"), interface=props)
                assert body[0] == ("u", 1)
                kind, body = await call(client, "GetAll", "s", (dbus_api.INTERFACE,), interface=props)
                assert set(body[0]) == {"Version", "ApiVersion"}
                result = await call(client, "Set", "ssv", (dbus_api.INTERFACE, "Version", ("s", "x")),
                                    interface=props)
                assert result[:2] == ("error", "org.freedesktop.DBus.Error.PropertyReadOnly")
                assert (await call(client, "Ping", interface="org.freedesktop.DBus.Peer"))[0] == "ok"

    asyncio.run(go())


def test_inflight_limit_and_cancel_on_disconnect(tmp_path):
    async def go():
        async with daemon_on_bus(tmp_path) as (address, service, polkit, _paths):
            polkit.results[dbus_api.TIGHTEN] = "hold"
            async with open_dbus_router(address) as client:
                calls = [asyncio.create_task(call(client, "UpdateFiltersNow")) for _ in range(9)]
                done, _pending = await asyncio.wait(calls, timeout=5, return_when=asyncio.FIRST_COMPLETED)
                assert [t.result()[:2] for t in done] == [("error", "org.freedesktop.DBus.Error.LimitsExceeded")]
                for _ in range(50):
                    if len(polkit.checks) == 8:
                        break
                    await asyncio.sleep(0.05)
                assert len(polkit.checks) == 8
                await polkit.release()
                results = await asyncio.gather(*[t for t in calls if t not in done])
                assert all(r[0] == "ok" for r in results)
                # a call parked in polkit, then the caller goes away
                polkit.checks.clear()
                parked = asyncio.create_task(call(client, "UpdateFiltersNow"))
                for _ in range(50):
                    if polkit.checks:
                        break
                    await asyncio.sleep(0.05)
                cancel_id = polkit.checks[0][3]
            parked.cancel()
            for _ in range(50):
                if polkit.cancelled:
                    break
                await asyncio.sleep(0.05)
            assert polkit.cancelled == [cancel_id]
            assert service._inflight == {} or all(v <= 1 for v in service._inflight.values())

    asyncio.run(go())


def test_signals_and_firewalld_reload(tmp_path):
    reloads = []

    async def go():
        async with daemon_on_bus(tmp_path, on_firewall_reload=lambda: reloads.append(1)) as (
                address, service, _polkit, _paths):
            async with open_dbus_router(address) as client:
                queue = asyncio.Queue()
                from jeepney.bus_messages import message_bus
                rule = MatchRule(type="signal", interface=dbus_api.INTERFACE)
                with client.filter(rule, queue=queue):
                    await client.send_and_get_reply(message_bus.AddMatch(rule))
                    assert (await call(client, "Pause", "t", (0,)))[0] == "ok"
                    service.status_changed()
                    async with asyncio.timeout(5):
                        signal = await queue.get()
                    assert signal.header.fields[HeaderFields.member] == "StatusChanged"
                    assert json.loads(signal.body[0]) == {"api": 1, "protection": "paused"}
                    service.alert("interception", "lost")
                    async with asyncio.timeout(5):
                        signal = await queue.get()
                    assert signal.header.fields[HeaderFields.member] == "Alert"
                    assert signal.body == ("interception", "lost")
            # firewalld: a Reloaded signal from the owner of its name
            async with open_dbus_router(address) as firewalld:
                await firewalld.send_and_get_reply(message_bus.RequestName("org.fedoraproject.FirewallD1"))
                await firewalld.send(new_signal(DBusAddress("/org/fedoraproject/FirewallD1",
                                                            interface="org.fedoraproject.FirewallD1"), "Reloaded"))
                for _ in range(50):
                    if len(reloads) >= 2:  # name acquired, then Reloaded
                        break
                    await asyncio.sleep(0.05)
            assert len(reloads) >= 2

    asyncio.run(go())


def test_name_taken_then_released(tmp_path):
    async def go():
        paths = setup_state(tmp_path)
        state = StateManager(paths, catalog=CATALOG)
        state.load()
        api = DaemonApi(state, store=None, health=None, forwarder=None)
        with private_bus() as address:
            from jeepney.bus_messages import message_bus
            squatter_cm = open_dbus_router(address)
            squatter = await squatter_cm.__aenter__()
            await squatter.send_and_get_reply(message_bus.RequestName(dbus_api.BUS_NAME))
            service = DBusService(api, bus=address, flush_resolved=False, retry=0.2)
            task = asyncio.create_task(service.run())
            await asyncio.sleep(0.5)
            assert not service.ready.is_set()
            await squatter_cm.__aexit__(None, None, None)
            async with asyncio.timeout(5):
                await service.ready.wait()
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

    asyncio.run(go())


def test_polkit_missing_denies(tmp_path):
    async def go():
        with private_bus() as address:
            async with open_dbus_router(address) as router:
                authorizer = Authorizer(router, quick_timeout=2)
                from blockads_linux.daemon.polkit import Decision
                assert await authorizer.check(":1.99", dbus_api.VIEW, interactive=False) is Decision.DENIED

    asyncio.run(go())


def test_check_limits():
    method = dbus_api.METHODS["SetUpstream"]
    assert check_limits(("x" * 60000,), method) is None  # JSON argument
    assert check_limits(("x" * 70000,), method)
    assert check_limits(("x" * 5000,), dbus_api.METHODS["AddBlockRule"])
    assert check_limits((["a"] * 1000,), dbus_api.METHODS["EnableFilters"]) is None
