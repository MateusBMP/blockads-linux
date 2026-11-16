"""polkit CheckAuthorization from the daemon's identity (tests/vm/platform_checks.sh).

hold                 -- connect to the system bus, print the unique name, sleep
                        (plays the GUI client, run as an ordinary user)
check NAME ACTION    -- CheckAuthorization for subject system-bus-name NAME
                        (run as user 'blockads', inside the sandbox)

check prints ``AUTHORIZED``, ``CHALLENGE``, ``DENIED`` or ``ERROR <name>: <msg>``.
"""

from __future__ import annotations

import sys
import time

from jeepney import DBusAddress, new_method_call
from jeepney.io.blocking import open_dbus_connection
from jeepney.wrappers import DBusErrorResponse


def main() -> int:
    conn = open_dbus_connection(bus="SYSTEM")
    if sys.argv[1] == "hold":
        print(conn.unique_name, flush=True)
        time.sleep(float(sys.argv[2]) if len(sys.argv) > 2 else 60)
        return 0
    name, action = sys.argv[2], sys.argv[3]
    authority = DBusAddress("/org/freedesktop/PolicyKit1/Authority", bus_name="org.freedesktop.PolicyKit1",
                            interface="org.freedesktop.PolicyKit1.Authority")
    subject = ("system-bus-name", {"name": ("s", name)})
    msg = new_method_call(authority, "CheckAuthorization", "(sa{sv})sa{ss}us",
                          (subject, action, {}, 0, ""))  # flags 0: never pop up a dialog
    reply = conn.send_and_get_reply(msg, timeout=10)
    try:
        from jeepney.wrappers import unwrap_msg
        (is_authorized, is_challenge, details), = unwrap_msg(reply)
    except DBusErrorResponse as exc:
        print(f"ERROR {exc.name}: {exc.data[0] if exc.data else ''}")
        return 1
    print("AUTHORIZED" if is_authorized else "CHALLENGE" if is_challenge else "DENIED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
