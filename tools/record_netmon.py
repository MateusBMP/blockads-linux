#!/usr/bin/env python3
"""Record the D-Bus properties daemon/netmon.py reads, as a JSON test fixture.

    PYTHONPATH=src python3 tools/record_netmon.py > tests/fixtures/netmon/NAME.json

Read-only: it only calls Properties.GetAll and resolve1 GetLink on the
system bus. Review the output before committing it (connection names,
UUIDs and addresses identify the network; replace them if needed).
"""

import asyncio
import json
import socket
import sys

from jeepney.io.asyncio import open_dbus_router

from blockads_linux.daemon.netmon import DBusProperties, read_state


#: The properties netmon reads; everything else (SSIDs, MAC addresses, ...) is dropped.
KEEP = {
    "org.freedesktop.NetworkManager": {"Connectivity", "Metered", "PrimaryConnection", "ActiveConnections",
                                       "ConnectivityCheckUri", "ConnectivityCheckEnabled",
                                       "ConnectivityCheckAvailable"},
    "org.freedesktop.NetworkManager.DnsManager": {"Configuration", "Mode", "RcManager"},
    "org.freedesktop.NetworkManager.Connection.Active": {"Type", "Vpn", "Default", "Default6", "State",
                                                          "Devices", "Uuid"},
    "org.freedesktop.NetworkManager.Device": {"Interface", "IpInterface"},
    "org.freedesktop.resolve1.Manager": {"DNS", "Domains"},
    "org.freedesktop.resolve1.Link": {"DefaultRoute"},
}


class Recorder:
    def __init__(self, inner):
        self.inner = inner
        self.data = {"get_all": {}, "call": {}, "if_names": {}}

    async def get_all(self, bus, path, interface):
        result = await self.inner.get_all(bus, path, interface)
        if result is not None:
            keep = KEEP.get(interface, set())
            self.data["get_all"][f"{bus} {path} {interface}"] = {k: v for k, v in result.items() if k in keep}
        return result

    async def call(self, bus, path, interface, method, signature, args):
        result = await self.inner.call(bus, path, interface, method, signature, args)
        if result is not None:
            key = f"{bus} {path} {interface} {method} {json.dumps(list(args))}"
            self.data["call"][key] = list(result)
        return result

    def if_name(self, index):
        try:
            name = socket.if_indextoname(index)
        except OSError:
            name = f"if{index}"
        self.data["if_names"][str(index)] = name
        return name


def _plain(value):
    if isinstance(value, bytes):
        return list(value)
    if isinstance(value, dict):
        return {k: _plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(v) for v in value]
    return value


async def main() -> None:
    async with open_dbus_router("SYSTEM") as router:
        recorder = Recorder(DBusProperties(router))
        state = await read_state(recorder, recorder.if_name)
    print(f"# {state}", file=sys.stderr)
    json.dump(_plain(recorder.data), sys.stdout, indent=1, sort_keys=True)
    print()


if __name__ == "__main__":
    asyncio.run(main())
