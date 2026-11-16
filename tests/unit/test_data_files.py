"""The shipped data/ files agree with each other and with the code."""

from __future__ import annotations

from pathlib import Path

from blockads_linux.daemon.__main__ import BRIDGE_FD_NAME, LOOPBACK_FD_NAMES
from tests.unit.fakefw import load_helper

DATA = Path(__file__).resolve().parents[2] / "data"


def values(name: str, section: str, key: str) -> list[str]:
    text = (DATA / "systemd" / name).read_text()
    out, current = [], None
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("["):
            current = line.strip("[]")
        elif current == section and line.startswith(f"{key}="):
            out.append(line.split("=", 1)[1])
    return out


def test_shipped_firewall_conf_is_the_default():
    fw = load_helper()
    assert fw.parse_config_text((DATA / "firewall.conf").read_text()) == fw.validate_config({})


def test_socket_ports_match_firewall_conf():
    cfg = load_helper().validate_config({})
    for name, port in (("blockadsd.socket", cfg["port"]), ("blockadsd-ipv6.socket", cfg["port"]),
                       ("blockadsd-bridge.socket", cfg["bridge_port"])):
        listens = values(name, "Socket", "ListenDatagram") + values(name, "Socket", "ListenStream")
        assert listens and all(item.rsplit(":", 1)[1] == str(port) for item in listens), name


def test_fd_names():
    assert values("blockadsd.socket", "Socket", "FileDescriptorName") == ["dns-v4"]
    assert values("blockadsd-ipv6.socket", "Socket", "FileDescriptorName") == ["dns-v6"]
    assert values("blockadsd-bridge.socket", "Socket", "FileDescriptorName") == [BRIDGE_FD_NAME]
    assert LOOPBACK_FD_NAMES == {"dns-v4", "dns-v6"}


def test_service_hooks_order():
    assert values("blockadsd.service", "Service", "ExecStartPre") == ["+/usr/lib/blockads-linux/blockads-fw revert"]
    assert values("blockadsd.service", "Service", "ExecStartPost") == [
        "+/usr/lib/blockads-linux/blockads-fw apply --verify"]
    assert values("blockadsd.service", "Service", "ExecStopPost") == [
        "-+/usr/lib/blockads-linux/blockads-fw revert",
        "-+/bin/sh /run/blockads-fw/emergency.sh",
        "+/usr/lib/blockads-linux/blockads-fw-emergency.sh",
    ]
    assert values("blockadsd.service", "Unit", "OnFailure") == ["blockads-failsafe.service"]
    assert values("blockads-failsafe.service", "Service", "ExecStart") == [
        "-/usr/lib/blockads-linux/blockads-fw revert --all-backends",
        "-/bin/sh /run/blockads-fw/emergency.sh",
        "/usr/lib/blockads-linux/blockads-fw-emergency.sh",
    ]
    assert values("blockads-update.service", "Unit", "Requisite") == ["blockadsd.service"]


def test_launchers_match_the_units():
    import importlib
    import re
    import stat

    launchers = DATA / "launchers"
    for unit, name in (("blockadsd.service", "blockadsd"), ("blockads-update.service", "blockads-update")):
        assert values(unit, "Service", "ExecStart") == [f"/usr/lib/blockads-linux/{name}"]
        path = launchers / name
        text = path.read_text()
        assert text.startswith("#!/usr/bin/python3 -I\n")
        assert path.stat().st_mode & stat.S_IXUSR
        assert 'sys.path.insert(0, "/usr/lib/blockads-linux/python")' in text
        module = re.search(r"^from (\S+) import main", text, re.M).group(1)
        assert callable(importlib.import_module(module).main)
    ctl = (launchers / "blockadsctl").read_text()
    assert ctl.startswith("#!/usr/bin/python3 -I\n") and (launchers / "blockadsctl").stat().st_mode & stat.S_IXUSR
    assert 'sys.path.insert(0, "/usr/lib/blockads-linux/python")' in ctl
    assert "from blockads_linux.ctl.cli import main" in ctl
    gui = (launchers / "blockads").read_text()
    assert gui.startswith("#!/usr/bin/python3 -I\n") and (launchers / "blockads").stat().st_mode & stat.S_IXUSR
    assert 'sys.path.insert(0, "/usr/lib/blockads-linux/python")' in gui
    assert "from blockads_linux.gui.app import main" in gui
    assert sorted(p.name for p in launchers.iterdir()) == ["blockads", "blockads-update", "blockadsctl", "blockadsd"]


def test_desktop_files():
    import configparser
    import xml.etree.ElementTree as ET

    app_id = "io.github.mateusbmp.blockads-linux"
    desktop = configparser.ConfigParser(interpolation=None)
    desktop.optionxform = str
    desktop.read(DATA / "applications" / f"{app_id}.desktop")
    entry = desktop["Desktop Entry"]
    assert entry["Exec"] == "blockads" and entry["Icon"] == app_id and entry["Type"] == "Application"
    metainfo = ET.parse(DATA / "metainfo" / f"{app_id}.metainfo.xml").getroot()
    assert metainfo.findtext("id") == app_id
    assert metainfo.find("launchable").text == f"{app_id}.desktop"
    assert (DATA / "icons" / "hicolor" / "scalable" / "apps" / f"{app_id}.svg").exists()
    # the GUI uses the same id (window icon, notifications, autostart entry)
    import pytest
    pytest.importorskip("PyQt6.QtDBus")
    from blockads_linux.gui import notifications
    assert notifications.ICON == app_id


def test_watchdog_and_restart_status():
    from blockads_linux.daemon.health import EXIT_RESTART

    from blockads_linux.daemon.health import MAX_LOOP_LAG

    assert values("blockadsd.service", "Service", "WatchdogSec") == ["15s"]
    # Pings every 5 s; one withheld for loop lag must not be fatal by itself.
    assert MAX_LOOP_LAG <= 15 / 3
    assert values("blockadsd.service", "Service", "Restart") == ["on-failure"]  # covers exit 75
    assert EXIT_RESTART == 75


# --- D-Bus policy and polkit -------------------------------------------------------

POLKIT_DEFAULTS = {  # any / inactive / active
    "view": ("yes", "yes", "yes"),
    "view-logs": ("auth_admin", "auth_admin", "yes"),
    "tighten": ("auth_admin", "auth_admin", "yes"),
    "weaken": ("auth_admin", "auth_admin", "auth_admin_keep"),
    "firewall": ("auth_admin", "auth_admin", "auth_admin_keep"),
}


def test_polkit_actions():
    import xml.etree.ElementTree as ET

    from blockads_linux.common import dbus_api

    root = ET.parse(DATA / "polkit-1" / "actions" / "io.github.mateusbmp.blockads.policy").getroot()
    actions = {a.get("id"): a for a in root.findall("action")}
    assert set(actions) == {*dbus_api.DAEMON_ACTIONS, dbus_api.FIREWALL}
    assert {m.action for m in dbus_api.METHODS.values()} == set(dbus_api.DAEMON_ACTIONS)
    for action_id, action in actions.items():
        short = action_id.removeprefix(dbus_api.ACTION_PREFIX)
        defaults = action.find("defaults")
        assert tuple(defaults.find(k).text for k in ("allow_any", "allow_inactive", "allow_active")) == \
            POLKIT_DEFAULTS[short], short
        annotations = {a.get("key"): a.text for a in action.findall("annotate")}
        if action_id == dbus_api.FIREWALL:
            assert annotations == {"org.freedesktop.policykit.exec.path": "/usr/lib/blockads-linux/blockads-fw"}
        else:  # without it polkit refuses the daemon's checks
            assert annotations == {"org.freedesktop.policykit.owner": "unix-user:blockads"}


def test_dbus_policy():
    import xml.etree.ElementTree as ET

    from blockads_linux.common import dbus_api

    root = ET.parse(DATA / "dbus-1" / "system.d" / f"{dbus_api.BUS_NAME}.conf").getroot()
    user = root.find("policy[@user='blockads']")
    assert [(e.tag, e.attrib) for e in user] == [("allow", {"own": dbus_api.BUS_NAME})]
    default = root.find("policy[@context='default']")
    assert ("deny", {"own": dbus_api.BUS_NAME}) in [(e.tag, e.attrib) for e in default]
    allowed = {(e.get("send_interface"), e.get("send_member")) for e in default.findall("allow")}
    assert all(e.get("send_destination") == dbus_api.BUS_NAME for e in default.findall("allow"))
    assert allowed == {(dbus_api.INTERFACE, None), ("org.freedesktop.DBus.Introspectable", None),
                       ("org.freedesktop.DBus.Peer", None), ("org.freedesktop.DBus.Properties", "Get"),
                       ("org.freedesktop.DBus.Properties", "GetAll")}  # never Properties.Set


def test_polkit_rules_name_our_units():
    text = (DATA / "polkit-1" / "rules.d" / "50-blockads-linux.rules").read_text()
    units = {p.name for p in (DATA / "systemd").iterdir()}
    for unit in ("blockadsd.service", "blockadsd.socket", "blockadsd-ipv6.socket"):
        assert f'"{unit}"' in text and unit in units
    assert '"stop"' not in text and 'subject.user == "blockads"' in text


def test_emergency_copy_paths_match_the_helper():
    mod = load_helper()
    assert f"{mod.RUN_DIR}/{mod.EMERGENCY_COPY}" == "/run/blockads-fw/emergency.sh"
    assert Path(mod.EMERGENCY_SCRIPT).name == "blockads-fw-emergency.sh"


def test_vm_installer_ships_every_unit():
    import re

    script = (DATA.parent / "tests" / "vm" / "install.sh").read_text()
    listed = set(re.search(r"UNITS=\(([^)]*)\)", script).group(1).split())
    assert listed == {p.name for p in (DATA / "systemd").iterdir()}


def test_secondary_sockets_follow_the_main_socket():
    # On an ipv6.disable=1 boot blockadsd-ipv6.socket is not loadable, and since
    # systemd 262 a stop job that names it fails as a whole (found in VM testing). The
    # secondary sockets are PartOf the main one, and stop commands never name it.
    for unit in ("blockadsd-ipv6.socket", "blockadsd-bridge.socket"):
        assert values(unit, "Unit", "PartOf") == ["blockadsd.socket"]
    root = DATA.parent
    for path in [root / "tests" / "vm" / "install.sh", root / "tests" / "vm" / "system_checks.sh",
                 root / "tests" / "ci" / "system.sh", root / "helper" / "blockads-fw"]:
        for line in path.read_text().splitlines():
            if "stop" in line and "systemctl" in line:
                assert "blockadsd-ipv6.socket" not in line, (path.name, line)
