"""blockadsctl against the real daemon process, on a private bus with a fake polkit."""

import asyncio
import json
from pathlib import Path
import os
import re
import signal
import sys

import dns.message
import dns.rdatatype
import pytest

from blockads_linux.common import dbus_api
from blockads_linux.common.atomic import write_json
from blockads_linux.ctl.cli import bridge_line, parse_duration
from blockads_linux.updater import manifest as mf

from .dbus_fake import have_dbus_daemon, private_bus
from .test_dbus_service import FakePolkit
from .test_state import setup_state
from .upstreams import UdpServer


def test_parse_duration():
    assert parse_duration("15m") == 900 and parse_duration("1h30m") == 5400 and parse_duration("2d") == 172800
    assert parse_duration("90") == 90 and parse_duration("forever") == 0
    for bad in ("", "abc", "31d", "1x"):
        with pytest.raises(Exception):
            parse_duration(bad)


def test_bridge_line():
    base = {"patterns": [], "interfaces": [], "subnets": 0, "allowed": 0, "denied": 0, "dropped": 0}
    assert bridge_line(base) == "not filtered (bridge redirect off)"
    assert bridge_line({**base, "patterns": ["docker0"]}) == "filtered (0 interfaces, none up yet)"
    assert bridge_line({**base, "patterns": ["br-+"], "interfaces": ["br-1\x1b"], "allowed": 1200,
                        "dropped": 3}) == "filtered (1 interface: br-1?); 1,200 answered, 3 dropped from other sources"
    assert bridge_line({**base, "patterns": ["docker0", "br-+"], "interfaces": ["br-a", "docker0"]}) == (
        "filtered (2 interfaces: br-a, docker0)")


@pytest.mark.skipif(not have_dbus_daemon(), reason="needs dbus-daemon")
def test_blockadsctl_end_to_end(tmp_path):
    paths = setup_state(tmp_path)

    async def body():
        upstream = await UdpServer().start()
        write_json(paths.settings, {"schema": 1, "filters": {"enabled": ["easylist"]},
                                    "dns": {"upstream": [f"udp://127.0.0.1:{upstream.port}"], "fallback": []}})
        current = mf.load_manifest(paths.manifest)
        mf.publish(paths.manifest, paths.previous_manifest, mf.Manifest(lists={
            "easylist": current.lists["ads_list"]}))
        env = dict(os.environ, PYTHONPATH=os.pathsep.join(sys.path), BLOCKADS_NO_AGENT="1")
        with private_bus() as address:
            async with FakePolkit(address) as polkit:
                polkit.results[dbus_api.WEAKEN] = "challenge"
                daemon = await asyncio.create_subprocess_exec(
                    sys.executable, "-m", "blockads_linux.daemon", "--dev", "--listen", "127.0.0.1:0",
                    "--no-netmon", "--state-dir", str(paths.root), "--state-poll", "0.1", "--dbus", address,
                    "--bridge-listen", "127.0.0.2:0", "--fw-state", str(tmp_path / "no-fw-state.json"),
                    stderr=asyncio.subprocess.PIPE, env=env)
                lines = []

                async def wait_for(pattern):
                    while True:
                        line = (await asyncio.wait_for(daemon.stderr.readline(), 10)).decode()
                        assert line, "daemon exited early:\n" + "".join(lines)
                        lines.append(line)
                        if (match := re.search(pattern, line)):
                            return match

                async def ctl(*args, check=0):
                    process = await asyncio.create_subprocess_exec(
                        sys.executable, "-m", "blockads_linux.ctl", "--bus", address, *args,
                        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=env)
                    out, err = await asyncio.wait_for(process.communicate(), 30)
                    assert process.returncode == check, (args, out, err)
                    return out.decode(), err.decode()

                async def ask(name):
                    import dns.query
                    reply = await asyncio.to_thread(dns.query.udp, dns.message.make_query(name, dns.rdatatype.A),
                                                    "127.0.0.1", port=port, timeout=3)
                    return [r.to_text() for rr in reply.answer for r in rr]

                try:
                    port = int((await wait_for(r"serving DNS on udp \('127\.0\.0\.1', (\d+)\)")).group(1))
                    await wait_for(r"D-Bus: serving")
                    out, _ = await ctl("status")
                    assert "Protection:   active" in out and "1 lists, 2 rules" in out
                    assert "Containers:   not filtered (bridge redirect off)" in out
                    status = json.loads((await ctl("status", "--json"))[0])
                    assert status["bridge"] == {"patterns": [], "interfaces": [], "subnets": 0,
                                                "allowed": 0, "denied": 0, "dropped": 0}
                    assert status["filters"]["generation"] == mf.load_manifest(paths.manifest).generation >= 1
                    out, _ = await ctl("test", "x.ads.example")
                    assert out == "x.ads.example: blocked by easylist\n"
                    await ctl("block", "tracker.example")
                    assert await ask("tracker.example") == ["0.0.0.0"]
                    # weaken without a prompt allowed: refused, nothing changes
                    _, err = await ctl("--no-ask-password", "allow", "ads.example", check=4)
                    assert "not authorized" in err
                    assert await ask("ads.example") == ["0.0.0.0"]
                    # stdin is not a terminal, so blockadsctl never allows a prompt; let polkit say yes
                    polkit.results[dbus_api.WEAKEN] = "yes"
                    await ctl("pause", "15m")
                    assert await ask("ads.example") == ["192.0.2.1"]
                    assert "paused until" in (await ctl("status"))[0]
                    await ctl("resume")
                    assert await ask("ads.example") == ["0.0.0.0"]
                    for _ in range(30):  # the log writer flushes about once a second
                        out, _ = await ctl("log", "-n", "5")
                        if "blocked   ads.example (easylist)" in out:
                            break
                        await asyncio.sleep(0.2)
                    assert "blocked   ads.example (easylist)" in out
                    csv_path = tmp_path / "log.csv"
                    await ctl("log", "--csv", str(csv_path))
                    rows = csv_path.read_text().splitlines()
                    assert rows[0].startswith("id,time_ms,name") and len(rows) >= 3
                    assert oct(csv_path.stat().st_mode & 0o777) == "0o600"
                    backup = tmp_path / "backup.json"
                    await ctl("backup", str(backup))
                    assert json.loads(backup.read_text())["rules"]["rules"] == ["||tracker.example^"]
                    await ctl("unblock", "tracker.example")
                    await ctl("restore", str(backup))
                    assert (await ctl("rules"))[0] == "||tracker.example^\n"
                    android = Path(__file__).resolve().parents[1] / "fixtures" / "android" / "blockads_settings_v1.json"
                    out, _ = await ctl("restore", str(android))
                    assert out.startswith("BlockAds for Android backup: dns 1,") and "apps skipped 1" in out
                    assert "theme=dark" in out
                    rules_now = (await ctl("rules"))[0]
                    assert "||tracker.example^" in rules_now and "||tracker.example.org^" in rules_now
                    assert json.loads((await ctl("settings"))[0])["dns"]["block_mode"] == "nxdomain"
                    await ctl("feature", "safesearch", "on")
                    assert json.loads((await ctl("settings"))[0])["dns"]["safesearch"] is True
                    _, err = await ctl("feature", "nope", "on", check=2)
                    out, _ = await ctl("filters", "--all")
                    assert "[x] easylist" in out
                    _, err = await ctl("filters", "enable", "no_such_list", check=1)
                    assert "unknown list id" in err
                    diag = tmp_path / "diag.json"
                    out, _ = await ctl("diagnostics", str(diag), "--helper", str(tmp_path / "no-helper"))
                    report = json.loads(diag.read_text())
                    assert report["status"]["protection"]["state"] == "active" and report["settings"]
                    assert set(report["errors"]) == {"firewall", "doctor"}
                    # trusted networks (no NetworkManager here: no current connection)
                    _, err = await ctl("networks", "add", check=1)
                    assert "no active NetworkManager connection" in err
                    home = "11111111-2222-4333-8444-555555555555"
                    await ctl("networks", "add", home, "--name", "Home", "--mode", "network_dns")
                    out, _ = await ctl("networks")
                    assert home in out and "network_dns" in out and "Home" in out
                    _, err = await ctl("networks", "add", home, "--pin-ap", check=1)
                    assert "--pin-ap needs the current connection" in err
                    _, err = await ctl("networks", "add", home, "--bssid", "not-a-mac", check=1)
                    assert "BSSID" in err
                    await ctl("networks", "add", home, "--name", "Home", "--bssid", "AA:BB:CC:DD:EE:01")
                    out, _ = await ctl("networks")
                    assert "[only via aa:bb:cc:dd:ee:01]" in out and out.count(home) == 1
                    await ctl("networks", "remove", home)
                    assert "No trusted networks." in (await ctl("networks", "list"))[0]
                    _, err = await ctl("networks", "remove", home, check=1)
                    _, err = await ctl("reset", check=2)
                    daemon.send_signal(signal.SIGTERM)
                    assert await asyncio.wait_for(daemon.wait(), 10) == 0
                finally:
                    if daemon.returncode is None:
                        daemon.kill()
                        await daemon.wait()
                    upstream.close()
            # no daemon on the bus any more
            process = await asyncio.create_subprocess_exec(
                sys.executable, "-m", "blockads_linux.ctl", "--bus", address, "status",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=env)
            _, err = await process.communicate()
            assert process.returncode == 3 and b"not running" in err

    asyncio.run(body())
