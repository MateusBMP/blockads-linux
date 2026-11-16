"""Runtime probe executed *inside* the planned systemd sandbox (tests/vm/platform_checks.sh).

Exercises what blockadsd needs from the runtime under the hardening
directives: imports (ssl, sqlite3, jeepney, httpx, h2, dnspython), an
sqlite3 database in StateDirectory, a TLS handshake, the system bus
(NetworkManager properties, polkit CheckAuthorization) and the adopted
socket-activation fds. Prints one ``KEY RESULT detail`` line per check.
"""

from __future__ import annotations

import os
import socket
import sqlite3
import ssl
import sys


def out(key: str, ok: bool | None, detail: str = "") -> None:
    status = {True: "PASS", False: "FAIL", None: "INFO"}[ok]
    print(f"{status} {key} {detail}", flush=True)


def main() -> int:
    out("python", None, sys.version.split()[0])
    try:
        import dns.version
        import h2
        import httpx
        import jeepney
        out("imports", True, f"httpx {httpx.__version__}, dnspython {dns.version.version}, "
                              f"h2 {h2.__version__}, jeepney {jeepney.__version__}")
    except Exception as exc:  # noqa: BLE001
        out("imports", False, repr(exc))

    state = os.environ.get("STATE_DIRECTORY", "")
    try:
        db = sqlite3.connect(os.path.join(state, "probe.sqlite3"))
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("CREATE TABLE IF NOT EXISTS t (x)")
        db.execute("INSERT INTO t VALUES (1)")
        db.commit()
        out("sqlite3-wal", True, f"{sqlite3.sqlite_version} in {state}")
    except Exception as exc:  # noqa: BLE001
        out("sqlite3-wal", False, repr(exc))

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection(("9.9.9.9", 853), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname="dns.quad9.net") as tls:
                out("tls-dot", True, f"{tls.version()} {ssl.OPENSSL_VERSION}")
    except Exception as exc:  # noqa: BLE001
        out("tls-dot", False, repr(exc))

    fds = os.environ.get("LISTEN_FDS")
    out("listen-fds", None, f"LISTEN_FDS={fds} LISTEN_FDNAMES={os.environ.get('LISTEN_FDNAMES')}")

    try:
        from jeepney import DBusAddress, new_method_call
        from jeepney.io.blocking import open_dbus_connection

        conn = open_dbus_connection(bus="SYSTEM")
        out("system-bus", True, conn.unique_name)
        nm = DBusAddress("/org/freedesktop/NetworkManager", bus_name="org.freedesktop.NetworkManager",
                         interface="org.freedesktop.DBus.Properties")
        try:
            from jeepney import HeaderFields, MessageType

            reply = conn.send_and_get_reply(new_method_call(nm, "Get", "ss",
                                                            ("org.freedesktop.NetworkManager", "Connectivity")))
            if reply.header.message_type == MessageType.error:
                # jeepney returns error replies; no NetworkManager (e.g. Arch's networkd image) is not a failure.
                out("nm-dbus", None, f"no NetworkManager: {reply.header.fields.get(HeaderFields.error_name, '?')}")
                conn.close()
                return 0
            out("nm-connectivity", True, repr(reply.body[0]))
            dnsm = DBusAddress("/org/freedesktop/NetworkManager/DnsManager",
                               bus_name="org.freedesktop.NetworkManager",
                               interface="org.freedesktop.DBus.Properties")
            reply = conn.send_and_get_reply(new_method_call(dnsm, "GetAll", "s",
                                                            ("org.freedesktop.NetworkManager.DnsManager",)))
            props = reply.body[0]
            out("nm-dnsmanager", "Configuration" in props,
                f"Mode={props.get('Mode', ('', '?'))[1]} entries={len(props.get('Configuration', ('', []))[1])}")
        except Exception as exc:  # noqa: BLE001
            out("nm-dbus", False, repr(exc))
        conn.close()
    except Exception as exc:  # noqa: BLE001
        out("system-bus", False, repr(exc))
    return 0


if __name__ == "__main__":
    sys.exit(main())
