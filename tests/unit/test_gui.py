"""The GUI: helpers, and the real windows against the real daemon.

The end-to-end tests run Qt offscreen, start a private dbus-daemon, the
daemon in dev mode on it, a fake polkit and a fake upstream (both in an
asyncio thread), and drive the pages the way a user would.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

pytest.importorskip("PyQt6.QtWidgets")
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import QSettings, Qt  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication, QFileDialog, QMessageBox  # noqa: E402

from blockads_linux.common import dbus_api  # noqa: E402
from blockads_linux.common.atomic import write_json  # noqa: E402
from blockads_linux.gui import format as fmt  # noqa: E402
from blockads_linux.gui.dbus_client import classify_error, marshal  # noqa: E402
from blockads_linux.gui.netspeed import SpeedMeter, read_counters  # noqa: E402
from blockads_linux.gui.pages.dns import PRESETS, upstream_choice  # noqa: E402
from blockads_linux.gui.pages.filters import list_status, visible  # noqa: E402
from blockads_linux.gui.pages.home import bucket_label, health_text, series_buckets  # noqa: E402
from blockads_linux.gui.pages.querylog import details_text, qtype_name  # noqa: E402
from blockads_linux.gui.pages.rules import export_text, import_domains, normalize_input, split_rules  # noqa: E402
from blockads_linux.gui.pages.settings import backup_document, set_autostart  # noqa: E402
from blockads_linux.gui.pages.statistics import reason_slices  # noqa: E402
from blockads_linux.gui.prefs import Prefs  # noqa: E402
from blockads_linux.gui.status import overall_state  # noqa: E402
from blockads_linux.gui.tray import tooltip  # noqa: E402
from blockads_linux.updater import manifest as mf  # noqa: E402

from .dbus_fake import have_dbus_daemon, private_bus  # noqa: E402
from .test_dbus_service import FakePolkit  # noqa: E402
from .test_state import setup_state  # noqa: E402
from .upstreams import UdpServer  # noqa: E402


@pytest.fixture(scope="module")
def qapp():
    app = QApplication.instance() or QApplication(["test"])
    yield app


@pytest.fixture(autouse=True)
def slot_errors():
    """PyQt aborts on an exception escaping a slot: record it and fail the test instead."""
    errors = []
    previous = sys.excepthook
    sys.excepthook = lambda kind, value, tb: errors.append("".join(
        __import__("traceback").format_exception(kind, value, tb)))
    yield errors
    sys.excepthook = previous
    assert not errors, "exception in a Qt slot:\n" + "\n".join(errors)


def wait_until(predicate, timeout=10.0, what="condition"):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        QTest.qWait(25)
    raise AssertionError(f"timed out waiting for {what}")


# --- helpers (no daemon) ------------------------------------------------------------


def test_safe_strips_control_and_bidi():
    assert fmt.safe("ads\x1b[31m.example") == "ads�[31m.example"
    assert fmt.safe("a‮b") == "a�b"
    assert fmt.safe("x" * 400, 10) == "x" * 9 + "…"
    assert fmt.html("<b>x</b>") == "&lt;b&gt;x&lt;/b&gt;"


def test_number_percent_size_duration(qapp):
    assert fmt.number(1234567) == "1 234 567"
    assert fmt.percent(1, 3) == "33.3%" and fmt.percent(0, 0) == "0%"
    assert fmt.size(512) == "512 B" and fmt.size(2048) == "2.0 KB" and fmt.size(3 * 1024**3) == "3.0 GB"
    assert fmt.data_saved(1000) == "1.4 MB"
    assert fmt.duration(42) == "42 s" and fmt.duration(3700) == "1 h 1 min" and fmt.duration(90000) == "1 d 1 h"
    assert fmt.when(0) == "never"


def test_reason_labels(qapp):
    assert fmt.reason("custom") == "your blocklist"
    assert fmt.reason("easylist,adguard_base") == "easylist, adguard_base"
    assert fmt.reason("cname:easylist") == "CNAME cloaking: easylist"
    assert fmt.reason("upstream_dns") == "blocked by the DNS server"
    assert fmt.reason("evil\x1b") == "evil�"


def test_marshal_follows_the_signature(qapp):
    from PyQt6.QtDBus import QDBusArgument
    args = marshal(dbus_api.METHODS["GetQueryLog"], ("{}", 5, 10))
    assert args[0] == "{}" and all(isinstance(a, QDBusArgument) for a in args[1:])
    assert marshal(dbus_api.METHODS["SetLogging"], (1, 7))[0] is True
    assert isinstance(marshal(dbus_api.METHODS["EnableFilters"], (["a"],))[0], QDBusArgument)
    with pytest.raises(TypeError):
        marshal(dbus_api.METHODS["Pause"], ())


def test_classify_error():
    assert classify_error("org.freedesktop.DBus.Error.ServiceUnknown", "x").kind == "not_running"
    assert classify_error("org.freedesktop.DBus.Error.InteractiveAuthorizationRequired", "x").kind == "denied"
    assert classify_error("org.freedesktop.DBus.Error.InvalidArgs", "bad").kind == "invalid"
    assert classify_error(dbus_api.error_name("ReadOnly"), "ro").kind == "read_only"
    assert classify_error(dbus_api.error_name("Unavailable"), "u").kind == "unavailable"
    assert classify_error("com.example.Weird", "").message == "com.example.Weird"


def test_overall_state():
    active = {"protection": {"state": "active"}, "alerts": []}
    assert overall_state(None, False) == "off" and overall_state(active, False) == "off"
    assert overall_state(active, True) == "active"
    assert overall_state({**active, "protection": {"state": "paused"}}, True) == "paused"
    health = {"healthy": True, "interception": ["ipv4"], "interception_expected": True}
    assert overall_state({**active, "health": health}, True) == "active"
    assert overall_state({**active, "health": {**health, "interception": []}}, True) == "error"
    assert overall_state({**active, "health": {**health, "interception": [], "interception_expected": False}},
                         True) == "active"
    assert overall_state({**active, "health": {**health, "interception_error": "x"}}, True) == "error"
    assert overall_state({**active, "alerts": [{"kind": "k", "message": "m"}]}, True) == "error"


def test_import_domains_formats():
    text = """# hosts
0.0.0.0 ads.example tracker.example
127.0.0.1 localhost
::1 ip6-localhost
||adblock.example^
@@||good.example^
@@also-good.example
plain.example
*.sub.example
! comment
not a domain at all
single
ads.example
"""
    block, allow = import_domains(text)
    assert block == ["ads.example", "tracker.example", "adblock.example", "plain.example", "*.sub.example"]
    assert allow == ["good.example", "also-good.example"]


def test_rules_split_export_normalize():
    rules = {"rules": ["||a.example^", "@@||b.example^", "! note", "*.c.example"], "whitelist": ["w.example"]}
    blocked, allowed = split_rules(rules)
    assert blocked == ["a.example", "*.c.example"] and allowed == ["b.example", "w.example"]
    text = export_text(blocked, allowed)
    assert import_domains(text) == (blocked, allowed)
    assert normalize_input(" https://Ads.Example./path ", False) == "ads.example"
    assert normalize_input("ads.example", True) == "*.ads.example"
    assert normalize_input("*.ads.example", False) == "ads.example"
    for bad in ("", "nodot", "bad domain.example", "a..b"):
        assert normalize_input(bad, False) is None


def test_presets_match_the_daemon():
    pytest.importorskip("httpx")
    from blockads_linux.daemon.upstream.presets import PRESETS as DAEMON
    assert [key for key, _ in PRESETS] == list(DAEMON)
    assert {key: name for key, name in PRESETS} == {key: p.name for key, p in DAEMON.items()}


def test_upstream_choice():
    assert upstream_choice({"upstream": ["system"]}) == ("system", [])
    assert upstream_choice({"upstream": ["adguard"]}) == ("adguard", [])
    assert upstream_choice({"upstream": []}) == ("quad9", [])
    assert upstream_choice({"upstream": ["quad9", "udp://1.2.3.4"]}) == ("custom", ["quad9", "udp://1.2.3.4"])


def test_filter_visibility_and_status(qapp):
    entry = {"id": "x", "name": "Ads One", "description": "d", "category": "ads", "enabled": True,
             "downloaded": False}
    assert visible(entry, "enabled", "") and visible(entry, "ads", "one") and not visible(entry, "privacy", "")
    assert not visible(entry, "ads", "zzz") and not visible(entry, "custom", "")
    assert list_status(entry) == "Waiting for download"
    assert list_status({**entry, "error": "HTTP 404"}) == "Error: HTTP 404"
    assert list_status({**entry, "retired": "gone"}) == "Retired: gone"


def test_series_and_labels():
    hour = int(time.mktime((2026, 11, 15, 13, 0, 0, 0, 0, -1)) // 3600)
    assert bucket_label("24h", hour) == "13"
    assert bucket_label("12m", 2026 * 12 + 10) == "11/26"
    assert bucket_label("7d", 20407) == time.strftime("%d/%m", time.gmtime(20407 * 86400))
    stats = {"period": "24h", "series": [{"bucket": hour, "total": 5, "blocked": 2}]}
    assert series_buckets(stats) == [("13", 5, 2)]
    assert reason_slices({"easylist": 3, "easylist,b": 2, "custom": 1}) == [("easylist", 5), ("your blocklist", 1)]


def test_health_text_and_tooltip(qapp):
    status = {"protection": {"state": "active", "paused_until": 0},
              "filters": {"lists": 1, "rules": 2, "missing": ["a"], "updated_at": 0},
              "health": {"healthy": True, "interception": ["ipv4", "ipv6"], "interception_expected": True},
              "upstream": {"active": {"label": "dns.quad9.net", "encrypted": True, "tier": "configured"},
                           "clock_suspect": True, "captive": False},
              "problems": ["settings.json: x\x1b"], "alerts": [], "today": {"total": 10, "blocked": 4}}
    text = health_text(status)
    assert "Interception: IPv4, IPv6" in text and "dns.quad9.net (configured, encrypted)" in text
    assert "is the clock right?" in text and "1 lists not downloaded yet" in text and "x�" in text
    broken = {**status, "health": {**status["health"], "interception": []}}
    assert "applications are not filtered" in health_text(broken)
    assert tooltip("active", status) == "BlockAds: protected\n4 blocked today"
    assert tooltip("off", None) == "BlockAds: not running"
    assert tooltip("paused", {**status, "protection": {"state": "paused", "paused_until": 0}}) == (
        "BlockAds: Paused until resumed")


def test_bypass_warnings(qapp):
    from blockads_linux.gui.pages.home import bypass_warnings

    assert bypass_warnings({}) == []
    assert "DNSOverTLS=yes" in bypass_warnings({"bypass": {"resolved_dot": "yes"}})[0]
    assert bypass_warnings({"bypass": {"resolved_dot": "opportunistic"}}) == []
    recent = {"bypass": {"doh_last": 1000, "doh_blocklist": False}}
    assert "DNS-over-HTTPS" in bypass_warnings(recent, now=2000)[0]
    assert bypass_warnings(recent, now=1000 + 2 * 86400) == []
    assert bypass_warnings({"bypass": {"doh_last": 1000, "doh_blocklist": True}}, now=2000) == []


def test_log_details(qapp):
    entry = {"name": "ads.example", "time_ms": 0, "qtype": 28, "verdict": "blocked", "reason": "easylist",
             "upstream": "", "cached": False, "elapsed_ms": 0, "answers": []}
    text = details_text(entry)
    assert "Domain: ads.example" in text and "Type: AAAA" in text and "Reason: easylist" in text
    assert qtype_name(65) == "HTTPS" and qtype_name(999) == "TYPE999"


def test_netspeed(tmp_path):
    dev = tmp_path / "dev"
    header = "Inter-|   Receive |  Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes\n"
    row = "{name}: {rx} 0 0 0 0 0 0 0 {tx} 0 0 0 0 0 0 0\n"
    dev.write_text(header + row.format(name="lo", rx=999, tx=999) + row.format(name="wlan0", rx=1000, tx=500)
                   + row.format(name="docker0", rx=5, tx=5))
    assert read_counters(dev) == (1000, 500)
    assert read_counters(tmp_path / "missing") == (0, 0)
    now = [100.0]
    meter = SpeedMeter(dev, clock=lambda: now[0])
    assert meter.sample() == (0.0, 0.0)
    dev.write_text(header + row.format(name="wlan0", rx=3000, tx=1500))
    now[0] = 102.0
    assert meter.sample() == (1000.0, 500.0)


def test_prefs_and_autostart(tmp_path, qapp):
    settings = QSettings(str(tmp_path / "gui.conf"), QSettings.Format.IniFormat)
    prefs = Prefs(settings)
    assert prefs.get("tray") is True and prefs.get("theme") == "system"
    settings.setValue("tray", "false")
    settings.setValue("theme", 7)
    assert prefs.get("tray") is False and prefs.get("theme") == "system"
    with pytest.raises(KeyError):
        prefs.set("nope", 1)
    path = tmp_path / "autostart" / "x.desktop"
    set_autostart(True, path)
    assert "Exec=blockads --hidden" in path.read_text()
    set_autostart(False, path)
    assert not path.exists()
    assert backup_document({"a": 1}, {"b": 2}) == {"api": dbus_api.API_VERSION, "settings": {"a": 1},
                                                    "rules": {"b": 2}}


class _Pending:
    def __init__(self, result):
        self.result = result

    def then(self, ok, _failed):
        ok(self.result)


def fake_notifier(tmp_path, clock):
    from PyQt6.QtCore import QObject, pyqtSignal

    from blockads_linux.gui.notifications import Notifier
    from blockads_linux.gui.pages.base import Context, Messages

    class Status(QObject):
        updated = pyqtSignal(dict)
        state_changed = pyqtSignal(str)
        status = None

    class Client(QObject):
        alert = pyqtSignal(str, str)
        replies: dict = {}

        def call(self, method, *args):
            return _Pending(self.replies[method])

    prefs = Prefs(QSettings(str(tmp_path / "gui.conf"), QSettings.Format.IniFormat))
    ctx = Context(Client(), Status(), prefs, Messages())
    notifier = Notifier(ctx, connection=None, clock=clock)
    notifier.connection = type("Off", (), {"isConnected": staticmethod(lambda: False)})()
    return notifier, ctx


def test_daily_summary_milestones_and_update_notifications(tmp_path, qapp):
    from blockads_linux.gui.notifications import milestone_for

    assert milestone_for(999) == 0 and milestone_for(1000) == 1000 and milestone_for(123_456) == 100_000
    evening = time.mktime((2026, 11, 15, 21, 5, 0, 0, 0, -1))
    now = [evening - 3600]
    notifier, ctx = fake_notifier(tmp_path, lambda: now[0])
    ctx.status.status = {"today": {"total": 2000, "blocked": 500}, "filters": {}}
    ctx.client.replies["GetStatistics"] = {"totals": {"blocked": 5000}}
    ctx.prefs.set("notify_daily_summary", True)
    notifier.tick()  # 20:05: no summary; first milestone look sets the baseline silently
    assert notifier.sent == [] and ctx.prefs.get("milestone_reached") == 1000
    now[0] = evening
    notifier.tick()
    assert notifier.sent[-1][0] == "BlockAds today" and "2\u202f000 queries, 500 blocked (25" in notifier.sent[-1][1]
    notifier.tick()  # once per day
    assert len(notifier.sent) == 1
    ctx.client.replies["GetStatistics"] = {"totals": {"blocked": 12_000}}
    now[0] += 3600  # the milestone check runs hourly
    notifier.tick()
    assert notifier.sent[-1] == ("Milestone reached", "BlockAds has blocked 10\u202f000 requests.")
    now[0] += 3600
    notifier.tick()
    assert len(notifier.sent) == 2

    # Filter updates: the first status is the baseline; "errors" (default) only reports failures.
    catalog = {"lists": [{"id": "a", "name": "List A", "enabled": True, "error": ""}], "custom": []}
    ctx.client.replies["GetFilterCatalog"] = catalog
    status = {"filters": {"generation": 1, "updated_at": 100, "rules": 10, "lists": 1}}
    ctx.status.updated.emit(status)
    ctx.status.updated.emit({"filters": {**status["filters"], "generation": 2, "updated_at": 200}})
    assert len(notifier.sent) == 2
    catalog["lists"][0]["error"] = "HTTP 404"
    ctx.status.updated.emit({"filters": {**status["filters"], "generation": 2, "updated_at": 300}})
    assert notifier.sent[-1][0] == "Some filter lists could not be updated" and "List A" in notifier.sent[-1][1]
    catalog["lists"][0]["error"] = ""
    ctx.prefs.set("notify_updates", "all")
    ctx.status.updated.emit({"filters": {**status["filters"], "generation": 3, "updated_at": 400}})
    assert notifier.sent[-1] == ("Filter lists updated", "10 rules from 1 lists.")
    ctx.prefs.set("notify_updates", "none")
    ctx.status.updated.emit({"filters": {**status["filters"], "generation": 4, "updated_at": 500}})
    assert len(notifier.sent) == 4


def test_theme_palettes(qapp):
    from PyQt6.QtGui import QPalette
    from blockads_linux.gui.theme import Theme
    theme = Theme(qapp)
    theme.apply("black", "blue")
    assert theme.dark and qapp.palette().color(QPalette.ColorRole.Window).name() == "#000000"
    assert qapp.palette().color(QPalette.ColorRole.Highlight).name() == "#1e88e5"
    theme.apply("light", "nope")
    assert not theme.dark and theme.accent == "teal"
    theme.apply("bogus")
    assert theme.name == "system"


def test_icons(qapp):
    from blockads_linux.gui.icons import state_icon
    for state in ("active", "paused", "off", "error"):
        assert not state_icon(state).isNull()


# --- end to end: the GUI against the real daemon ---------------------------------------


class AsyncThread:
    """An asyncio loop in a thread for the fake polkit and the fake upstream."""

    def __init__(self) -> None:
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self.loop.run_forever, daemon=True)
        self.thread.start()

    def run(self, coroutine, timeout=10):
        return asyncio.run_coroutine_threadsafe(coroutine, self.loop).result(timeout)

    def stop(self) -> None:
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(5)


class Daemon:
    def __init__(self, address: str, paths, tmp_path: Path) -> None:
        self.address = address
        self.paths = paths
        self.tmp_path = tmp_path
        self.process: subprocess.Popen | None = None
        self.port = 0
        self.lines: list[str] = []

    def start(self) -> None:
        env = dict(os.environ, PYTHONPATH=os.pathsep.join(sys.path))
        self.process = subprocess.Popen(
            [sys.executable, "-m", "blockads_linux.daemon", "--dev", "--listen", "127.0.0.1:0", "--no-netmon",
             "--state-dir", str(self.paths.root), "--state-poll", "0.1", "--dbus", self.address],
            stderr=subprocess.PIPE, text=True, env=env)
        for line in self.process.stderr:
            self.lines.append(line)
            if (match := re.search(r"serving DNS on udp \('127\.0\.0\.1', (\d+)\)", line)):
                self.port = int(match.group(1))
            if "D-Bus: serving" in line:
                break
        else:
            raise AssertionError("daemon exited early:\n" + "".join(self.lines))
        threading.Thread(target=lambda: self.lines.extend(self.process.stderr), daemon=True).start()

    def stop(self) -> None:
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()

    def ask(self, name: str) -> list[str]:
        import dns.message
        import dns.query
        import dns.rdatatype
        reply = dns.query.udp(dns.message.make_query(name, dns.rdatatype.A), "127.0.0.1", port=self.port, timeout=3)
        return [r.to_text() for rr in reply.answer for r in rr]


@pytest.fixture
def stack(tmp_path, qapp, monkeypatch):
    if not have_dbus_daemon():
        pytest.skip("needs dbus-daemon")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    paths = setup_state(tmp_path)
    background = AsyncThread()
    upstream = background.run(UdpServer().start())
    write_json(paths.settings, {"schema": 1, "filters": {"enabled": ["easylist"]},
                                "dns": {"upstream": [f"udp://127.0.0.1:{upstream.port}"], "fallback": []}})
    current = mf.load_manifest(paths.manifest)
    mf.publish(paths.manifest, paths.previous_manifest, mf.Manifest(lists={"easylist": current.lists["ads_list"]}))
    with private_bus() as address:
        polkit = FakePolkit(address)
        background.run(polkit.__aenter__())
        daemon = Daemon(address, paths, tmp_path)
        daemon.start()
        from blockads_linux.gui.app import Gui
        settings = QSettings(str(tmp_path / "gui.conf"), QSettings.Format.IniFormat)
        gui = Gui(qapp, address, Prefs(settings), tray=False)
        try:
            yield gui, daemon, polkit
        finally:
            gui.dispose()
            daemon.stop()
            background.run(polkit.__aexit__(None, None, None))
            upstream.close()
            QTest.qWait(50)
    background.stop()


def messages(gui):
    seen = []
    gui.ctx.messages.shown.connect(lambda text, error: seen.append((text, error)))
    return seen


def test_home_pause_resume_and_status(stack):
    gui, daemon, polkit = stack
    gui.show_window()
    home = gui.window.pages["home"]
    wait_until(lambda: home.state_label.text() == "Protected", what="status")
    assert gui.status.state == "active" and "2 rules from 1 lists" in home.state_detail.text()
    assert not gui.window.banner.isVisible()
    seen = messages(gui)
    home.toggle.click()  # Pause until resumed; polkit says yes
    wait_until(lambda: home.state_label.text() == "Paused", what="paused")
    assert gui.status.state == "paused" and "until resumed" in home.state_detail.text()
    assert daemon.ask("ads.example") == ["192.0.2.1"]
    assert ("Protection paused.", False) in seen
    assert any(action == dbus_api.WEAKEN for _n, action, _f, _c in polkit.checks)
    home.toggle.click()  # Resume (tighten)
    wait_until(lambda: home.state_label.text() == "Protected", what="resumed")
    assert daemon.ask("ads.example") == ["0.0.0.0"]


def test_weakening_needs_interactive_authorization(stack):
    gui, daemon, polkit = stack
    gui.show_window()
    rules = gui.window.pages["rules"]
    gui.window.show_page("rules")
    seen = messages(gui)
    # "challenge": allowed only when the call allows interactive authorization (the GUI always does)
    polkit.results[dbus_api.WEAKEN] = "challenge"
    rules.allow_list.input.setText("ads.example")
    rules.allow_list.add()
    wait_until(lambda: rules.allow_list.list.count() == 1, what="allow rule")
    assert polkit.checks[-1][1] == dbus_api.WEAKEN and polkit.checks[-1][2] & 1
    assert daemon.ask("ads.example") == ["192.0.2.1"]
    # "no": refused, explained, nothing changes
    polkit.results[dbus_api.WEAKEN] = "no"
    rules.allow_list.list.item(0).setSelected(True)
    rules.block_list.input.setText("tracker.example")
    rules.block_list.add()  # tighten: still allowed
    wait_until(lambda: rules.block_list.list.count() == 1, what="block rule")
    polkit.results[dbus_api.VIEW_LOGS] = "yes"
    rules.block_list.list.item(0).setSelected(True)
    polkit.results[dbus_api.WEAKEN] = "no"
    rules.block_list.remove()
    wait_until(lambda: any(error for _t, error in seen), what="denial message")
    assert any("Not authorized" in text for text, error in seen if error)
    assert daemon.ask("tracker.example") == ["0.0.0.0"]


def test_query_log_live_block_and_csv(stack, tmp_path, monkeypatch):
    gui, daemon, polkit = stack
    gui.show_window()
    gui.window.show_page("log")
    page = gui.window.pages["log"]
    assert daemon.ask("ads.example") == ["0.0.0.0"]
    assert daemon.ask("fine.example") == ["192.0.2.1"]
    wait_until(lambda: {r["name"] for r in page.model.rows} >= {"ads.example", "fine.example"}, 15,
               "live log entries")
    names = [page.model.rows[i]["name"] for i in range(page.model.rowCount())]
    assert names.index("fine.example") < names.index("ads.example")  # newest first
    blocked = next(r for r in page.model.rows if r["name"] == "ads.example")
    assert blocked["verdict"] == "blocked" and blocked["reason"] == "easylist"
    # filter: blocked only
    page.verdict.setCurrentIndex(page.verdict.findData("blocked"))
    wait_until(lambda: [r["name"] for r in page.model.rows] == ["ads.example"], what="filtered log")
    page.verdict.setCurrentIndex(0)
    wait_until(lambda: len(page.model.rows) >= 2, what="unfiltered log")
    # block a domain from the log
    row = next(i for i, r in enumerate(page.model.rows) if r["name"] == "fine.example")
    page.view.selectRow(row)
    assert "Domain: fine.example" in page.details.text()
    page.bulk(allow=False)
    wait_until(lambda: daemon.ask("fine.example") == ["0.0.0.0"], what="blocked from the log")
    # which list blocks it
    seen = messages(gui)
    page.which("ads.example")
    wait_until(lambda: seen, what="which-list answer")
    assert seen[-1][0] == "ads.example is blocked by: easylist"
    # CSV export pages through the log, with the formula guard and mode 0600
    target = tmp_path / "log.csv"
    page.export_csv.__func__  # noqa: B018 (exists)
    monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *a, **k: (str(target), ""))
    page.export_csv()
    wait_until(lambda: any("exported" in text for text, _e in seen), what="CSV export")
    rows = target.read_text().splitlines()
    assert rows[0].startswith("id,time_ms,name") and len(rows) >= 3
    assert oct(target.stat().st_mode & 0o777) == "0o600"


def test_filters_rules_dns_settings(stack, tmp_path, monkeypatch):
    gui, daemon, polkit = stack
    gui.show_window()
    window = gui.window
    seen = messages(gui)

    window.show_page("filters")
    filters = window.pages["filters"]
    wait_until(lambda: filters.table.rowCount() >= 1, what="catalog")
    assert "easylist" in [filters.table.item(r, 0).data(Qt.ItemDataRole.UserRole)
                          for r in range(filters.table.rowCount())]
    row = next(r for r in range(filters.table.rowCount())
               if filters.table.item(r, 0).data(Qt.ItemDataRole.UserRole) == "easylist")
    filters.table.item(row, 0).setCheckState(Qt.CheckState.Unchecked)  # DisableFilters (weaken: yes)
    wait_until(lambda: daemon.ask("ads.example") == ["192.0.2.1"], what="list disabled")
    filters.interval.setCurrentIndex(filters.interval.findData(6))
    filters._schedule()
    wait_until(lambda: any("schedule" in t for t, _e in seen), what="schedule saved")
    settings = json.loads(daemon.paths.settings.read_text())
    assert settings["filters"]["update_interval_hours"] == 6

    window.show_page("dns")
    dns_page = window.pages["dns"]
    wait_until(lambda: dns_page.radios["custom"].isChecked(), what="dns settings")
    dns_page.features["safesearch"].click()
    wait_until(lambda: json.loads(daemon.paths.settings.read_text())["dns"].get("safesearch") is True,
               what="safesearch on")
    dns_page.custom.setPlainText("not a server")
    dns_page.apply_upstream()
    wait_until(lambda: any(error for _t, error in seen), what="upstream refused")
    assert any("unrecognized upstream" in t for t, e in seen if e)
    dns_page.block_mode.setCurrentIndex(dns_page.block_mode.findData("nxdomain"))
    dns_page.block_ttl.setValue(60)
    dns_page.apply_response()
    wait_until(lambda: json.loads(daemon.paths.settings.read_text())["dns"].get("block_mode") == "nxdomain",
               what="block mode")

    # backup -> change -> restore
    window.show_page("settings")
    settings_page = window.pages["settings"]
    backup = tmp_path / "backup.json"
    monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *a, **k: (str(backup), ""))
    settings_page.backup()
    wait_until(backup.exists, what="backup written")
    document = json.loads(backup.read_text())
    assert document["settings"]["dns"]["block_mode"] == "nxdomain" and "rules" in document
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: QMessageBox.StandardButton.Yes)
    settings_page.reset()
    wait_until(lambda: json.loads(daemon.paths.settings.read_text())["dns"].get("block_mode") in (None, "null_ip"),
               what="reset")
    monkeypatch.setattr(QFileDialog, "getOpenFileName", lambda *a, **k: (str(backup), ""))
    settings_page.restore()
    wait_until(lambda: json.loads(daemon.paths.settings.read_text())["dns"].get("block_mode") == "nxdomain",
               what="restored")


def test_networks_page(stack):
    gui, daemon, polkit = stack
    gui.show_window()
    gui.window.show_page("networks")
    page = gui.window.pages["networks"]
    wait_until(lambda: gui.status.status is not None, what="status")
    # --no-netmon: no NetworkManager connection
    assert "No NetworkManager connection" in page.current_label.text() and not page.trust_button.isEnabled()
    assert page.empty.isVisible() and page.no_routes.isVisible()
    home = "11111111-2222-4333-8444-555555555555"
    status = dict(gui.status.status, network={
        "uuid": home, "name": "Home \u202eWi-Fi", "type": "802-11-wireless", "split_dns": [
            {"domain": "corp.example", "interface": "tun0", "vpn": True, "servers": ["10.8.0.1"]}]})
    page.show_status(status)
    assert page.current_label.text() == "Home \ufffdWi-Fi (Wi-Fi)"  # bidi override neutralized
    assert page.evil_twin.isVisible() and page.trust_button.isEnabled()
    assert page.routes.rowCount() == 1 and page.routes.item(0, 1).text() == "tun0 (VPN)"
    page.mode.setCurrentIndex(page.mode.findData("network_dns"))
    page.trust_current()  # weaken: polkit says yes

    def trusted():
        return json.loads(daemon.paths.settings.read_text()).get("trusted_networks", [])

    assert page.pin.isHidden()  # no access point reported
    wait_until(lambda: trusted() == [{"uuid": home, "name": "Home \u202eWi-Fi", "mode": "network_dns", "bssid": ""}],
               what="network trusted")
    wait_until(lambda: page.table.rowCount() == 1, what="table")
    page.show_status(status)
    assert "Keep filtering" in page.current_state.text()
    page.table.cellWidget(0, 1).setCurrentIndex(0)  # pause
    wait_until(lambda: trusted() and trusted()[0]["mode"] == "pause", what="mode changed")
    wait_until(lambda: page.table.cellWidget(0, 1) is not None
               and page.table.cellWidget(0, 1).currentData() == "pause", what="table refreshed")
    # Pin it to the current access point.
    ap = dict(status, network={**status["network"], "bssid": "aa:bb:cc:dd:ee:01"})
    page.show_status(ap)
    assert not page.pin.isHidden() and not page.pin.isChecked()
    page.pin.setChecked(True)
    page.trust_current()
    wait_until(lambda: trusted() and trusted()[0]["bssid"] == "aa:bb:cc:dd:ee:01", what="pinned")
    wait_until(lambda: "(only via aa:bb:cc:dd:ee:01)" in page.table.item(0, 0).text(), what="pin shown")
    page.show_status(ap)
    assert page.pin.isChecked() and "Pause filtering" in page.current_state.text()
    page.show_status(dict(status, network={**status["network"], "bssid": "aa:bb:cc:dd:ee:02"}))
    assert "this is another one" in page.current_state.text() and not page.pin.isChecked()
    page.table.cellWidget(0, 1).setCurrentIndex(1)  # changing the mode keeps the pin
    wait_until(lambda: trusted()[0]["mode"] == "network_dns", what="mode changed again")
    assert trusted()[0]["bssid"] == "aa:bb:cc:dd:ee:01"
    wait_until(lambda: page.table.cellWidget(0, 2) is not None, what="table refreshed")
    page.table.cellWidget(0, 2).click()
    wait_until(lambda: trusted() == [], what="removed")


def test_android_backup_import(stack, monkeypatch):
    gui, daemon, polkit = stack
    gui.show_window()
    gui.window.show_page("settings")
    page = gui.window.pages["settings"]
    seen = messages(gui)
    fixture = Path(__file__).resolve().parents[1] / "fixtures" / "android" / "blockads_settings_v2.json"
    monkeypatch.setattr(QFileDialog, "getOpenFileName", lambda *a, **k: (str(fixture), ""))
    page.restore()
    wait_until(lambda: any("Imported from BlockAds for Android" in t for t, _e in seen), what="android import")
    rules = json.loads(daemon.paths.rules.read_text())
    assert "||tracker.example.org^" in rules["rules"]
    assert any(domain == "cdn.example.net" for domain in rules["whitelist"])  # an entry, not a substring
    settings = json.loads(daemon.paths.settings.read_text())
    assert settings["dns"]["upstream"] == ["cloudflare_family"] and settings["dns"]["safesearch"] is True
    assert gui.prefs.get("theme") == "black" and gui.prefs.get("notify_daily_summary") is True
    assert page.boxes["notify_daily_summary"].isChecked()
    text = next(t for t, _e in seen if "Imported" in t)
    assert "4 domain rules, 3 filter lists" in text and "firewall rules do not exist" in text
    assert daemon.ask("tracker.example.org") == ["0.0.0.0"]


def test_rules_import(stack):
    gui, daemon, polkit = stack
    gui.window.show_page("rules")
    gui.show_window()
    rules = gui.window.pages["rules"]
    wait_until(lambda: rules.rules is not None and rules.block_list.count.text() != "", what="rules")
    rules.import_text("0.0.0.0 one.example two.example\n||three.example^\n@@||ads.example^\n")
    wait_until(lambda: rules.block_list.list.count() == 3 and rules.allow_list.list.count() == 1, 15,
               "imported rules")
    assert daemon.ask("two.example") == ["0.0.0.0"]
    assert daemon.ask("ads.example") == ["192.0.2.1"]


def test_daemon_goes_away_and_comes_back(stack):
    gui, daemon, polkit = stack
    gui.show_window()
    home = gui.window.pages["home"]
    wait_until(lambda: gui.status.state == "active", what="active")
    states = []
    gui.status.state_changed.connect(states.append)
    daemon.stop()
    wait_until(lambda: gui.status.state == "off", what="off")
    assert home.state_label.text() == "Not running" and gui.window.banner.isVisible()
    assert not home.toggle.isEnabled()  # no systemd on a test bus
    assert gui.notifier.sent[-1][0] == "Protection stopped"
    daemon.start()
    wait_until(lambda: gui.status.state == "active", 15, "back")
    assert not gui.window.banner.isVisible() and states == ["off", "active"]


# --- advanced page, self-test, onboarding -------------------------------------------------


def test_firewall_config_helpers(tmp_path):
    from blockads_linux.gui.pages.advanced import DEFAULTS, config_change, doctor_text, read_config, split_list
    assert read_config(tmp_path / "missing") == DEFAULTS
    conf = tmp_path / "firewall.conf"
    conf.write_text("# c\nport=153\nipv6=off\nblock_dot=false\nblock_webrtc=true\nbypass_cidrs=\n"
                    "bridge_interfaces=docker0,br-+\nbridge_port=154\nbogus\n")
    config = read_config(conf)
    assert config == {"ipv6": "off", "block_dot": False, "block_webrtc": True, "bypass_cidrs": [],
                      "bridge_interfaces": ["docker0", "br-+"]}
    assert config_change(config, {**config, "block_dot": True}) == {"block_dot": True}
    assert split_list(" a, b\nc ,, ") == ["a", "b", "c"]
    assert doctor_text([{"level": "warn", "check": "x", "detail": "y\x1b"}]) == "WARN  x: y�"
    assert doctor_text("nope") == ""


def fake_helper(tmp_path, code=0, output='{"state": null}'):
    record = tmp_path / "helper-stdin"
    script = tmp_path / "blockads-fw"
    script.write_text(f"#!/bin/sh\necho \"$@\" > {tmp_path}/helper-args\ncat > {record}\n"
                      f"printf '%s' '{output}'\nexit {code}\n")
    script.chmod(0o755)
    return script, record


def test_advanced_firewall_apply_and_diagnostics(stack, tmp_path):
    from blockads_linux.gui.pages.advanced import AdvancedPage
    gui, daemon, polkit = stack
    script, record = fake_helper(tmp_path)
    conf = tmp_path / "firewall.conf"
    conf.write_text("ipv6=auto\nblock_dot=true\n")
    page = AdvancedPage(gui.ctx, None, helper=str(script), conf_path=conf, pkexec=())
    seen = messages(gui)
    page.activate()
    assert page.block_dot.isChecked() and not page.bridges.isEnabled()
    page.apply_firewall()
    assert seen[-1] == ("Nothing to change.", False)
    page.block_webrtc.setChecked(True)
    page.bridges_on.setChecked(True)
    assert "docker0" in page.bridges.text()
    page.apply_firewall()
    wait_until(lambda: any(t == "Firewall options saved." for t, _e in seen), what="set-config")
    assert (tmp_path / "helper-args").read_text().split() == ["set-config"]
    sent = json.loads(record.read_text())
    assert sent["block_webrtc"] is True and "cni-podman+" in sent["bridge_interfaces"] and "ipv6" not in sent
    # pkexec dismissed -> 126
    script, record = fake_helper(tmp_path, code=126, output="")
    page.helper = str(script)
    page.block_dot.setChecked(False)
    page.apply_firewall()
    wait_until(lambda: any("not changed" in t for t, e in seen if e), what="denied")
    # diagnostics: doctor output rendered, missing helper reported
    script, _ = fake_helper(tmp_path, output='[{"level": "info", "check": "state", "detail": "applied=True"}]')
    page.helper = str(script)
    page.run_helper(["doctor"])
    wait_until(lambda: "INFO  state: applied=True" in page.output.toPlainText(), what="doctor")
    assert (tmp_path / "helper-args").read_text().split() == ["doctor", "--json"]
    page.helper = str(tmp_path / "missing-helper")
    page.run_helper(["status"])
    wait_until(lambda: "not installed" in page.output.toPlainText(), what="missing helper")


def test_diagnostics_export(stack, tmp_path, monkeypatch):
    from blockads_linux.gui.pages.advanced import AdvancedPage
    gui, daemon, polkit = stack
    script, _record = fake_helper(tmp_path, output='{"state": {"applied": true}}')
    page = AdvancedPage(gui.ctx, None, helper=str(script), conf_path=tmp_path / "firewall.conf", pkexec=())
    seen = messages(gui)
    out = tmp_path / "diag.json"
    monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *a, **k: (str(out), ""))
    page.save_diagnostics()
    wait_until(lambda: any(t.startswith("Diagnostics saved") for t, _e in seen), what="diagnostics")
    report = json.loads(out.read_text())
    assert oct(out.stat().st_mode & 0o777) == "0o600"
    assert report["status"]["filters"]["lists"] == 1 and report["firewall_doctor"] == {"state": {"applied": True}}
    assert report["environment"]["python"] and report["errors"] == {}
    assert [row["id"] for row in report["filter_lists"]] == ["easylist"]
    assert "rules" not in report and "query" not in json.dumps(report).lower().replace("query_log", "")


def test_selftest(stack):
    from blockads_linux.gui.selftest import SelfTest, verdict_text
    gui, daemon, polkit = stack
    results = []

    def run(resolver):
        test = SelfTest(gui.client, resolver, candidates=("not-listed.example", "ads.example"))
        test.finished.connect(lambda ok, text: results.append((ok, text)))
        test.start()
        wait_until(lambda: results, what="self-test")
        return results.pop()

    resolved = []
    ok, text = run(lambda name: (resolved.append(name), ("blocked", ["0.0.0.0"]))[1])
    assert ok and resolved == ["ads.example"] and "Working" in text
    ok, text = run(lambda name: ("resolved", ["192.0.2.1"]))
    assert not ok and "192.0.2.1" in text
    test = SelfTest(gui.client, lambda n: ("blocked", []), candidates=("not-listed.example",))
    test.finished.connect(lambda ok, text: results.append((ok, text)))
    test.start()
    wait_until(lambda: results, what="no candidate")
    assert results[-1][0] is False and "None of the test domains" in results[-1][1]
    assert verdict_text("x", "nxdomain", [])[0] is True
    assert verdict_text("x", "error", ["boom"]) == (False, "The test could not resolve x: boom")


def test_onboarding_wizard(stack, monkeypatch):
    from blockads_linux.gui.wizard import OnboardingWizard
    gui, daemon, polkit = stack
    monkeypatch.setattr("blockads_linux.gui.wizard.set_autostart", lambda enabled: None)
    wizard = OnboardingWizard(gui.ctx, gui.systemd)
    wizard.show()
    wizard.next()  # intro -> service
    wait_until(lambda: wizard.service_page.isComplete(), what="service running")
    wizard.next()  # -> dns
    wait_until(lambda: wizard.dns_page.current == [f"udp://127.0.0.1:{_upstream_port(daemon)}"],
               what="current dns")
    wizard.dns_page.radios["adguard"].setChecked(True)
    wizard.next()  # -> filters: SetUpstream(adguard)
    wait_until(lambda: json.loads(daemon.paths.settings.read_text())["dns"]["upstream"] == ["adguard"],
               what="dns saved")
    wizard.next()  # -> desktop
    wizard.desktop_page.tray.setChecked(False)
    wizard.next()  # -> test
    assert gui.prefs.get("tray") is False
    wizard.accept()
    assert gui.prefs.get("onboarded") is True


def _upstream_port(daemon) -> int:
    return int(json.loads(daemon.paths.settings.read_text())["dns"]["upstream"][0].rsplit(":", 1)[1])


# --- translations ---------------------------------------------------------------------------


def test_translations_are_complete(tmp_path):
    """Every extracted source has a pt_BR entry and every entry is still used (tools/i18n/update.py)."""
    import shutil
    import xml.etree.ElementTree as ET
    if shutil.which("pylupdate6") is None:
        pytest.skip("needs pylupdate6")
    from PyQt6.QtCore import PYQT_VERSION
    if PYQT_VERSION < 0x060600:  # PyQt 6.4's pylupdate6 does not see bare translate("Context", ...) calls
        pytest.skip("pylupdate6 from PyQt >= 6.6 needed to extract every string")
    root = Path(__file__).resolve().parents[2]
    sources = sorted(str(p) for p in (root / "src" / "blockads_linux" / "gui").rglob("*.py"))
    ts = tmp_path / "x.ts"
    subprocess.run(["pylupdate6", "--no-obsolete", *sources, "-ts", str(ts)], check=True, stdout=subprocess.DEVNULL)
    extracted = {m.find("source").text or "" for m in ET.parse(ts).iter("message")}
    import importlib.util
    spec = importlib.util.spec_from_file_location("pt_BR", root / "tools" / "i18n" / "pt_BR.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert sorted(extracted - set(module.T)) == [], "run tools/i18n/update.py after translating these"
    assert sorted(set(module.T) - extracted) == []
    for source, text in module.T.items():  # placeholders survive translation
        assert sorted(re.findall(r"%\d", source)) == sorted(re.findall(r"%\d", text)), source
    shipped = {m.find("source").text or "" for m in
               ET.parse(root / "src" / "blockads_linux" / "gui" / "i18n" / "blockads_pt_BR.ts").iter("message")}
    assert shipped == extracted, "the shipped .ts is stale: run tools/i18n/update.py"


def test_portuguese_is_loaded(qapp):
    from PyQt6.QtCore import QCoreApplication
    from blockads_linux.gui.app import install_translators
    translators = install_translators(qapp, "pt_BR")
    try:
        assert translators, "blockads_pt_BR.qm not found"
        assert QCoreApplication.translate("HomePage", "Home") == "Início"
        assert fmt.reason("custom") == "sua lista de bloqueados"
        assert fmt.duration(3700) == "1 h 1 min"
        from blockads_linux.gui.pages.filters import list_status
        assert list_status({"enabled": True, "downloaded": False}) == "Aguardando download"
    finally:
        for translator in translators:
            qapp.removeTranslator(translator)
    assert fmt.reason("custom") == "your blocklist"


def test_chart_axis_steps():
    from blockads_linux.gui.widgets.charts import _nice_max
    for value, top in ((0, 4), (1, 4), (4, 4), (5, 8), (17, 20), (99, 100), (1234, 2000)):
        assert _nice_max(value) == top
        assert top % 4 == 0 and top >= value


def test_single_instance(qapp):
    from PyQt6.QtNetwork import QLocalServer
    from blockads_linux.gui.app import signal_running_instance
    name = f"blockads-test-{os.getpid()}"
    assert signal_running_instance(name) is False
    server = QLocalServer()
    assert server.listen(name)
    received = []

    def connection():
        socket = server.nextPendingConnection()
        socket.readyRead.connect(lambda: received.append(bytes(socket.readAll())))

    server.newConnection.connect(connection)
    assert signal_running_instance(name) is True
    wait_until(lambda: received, what="show request")
    assert received == [b"show\n"]
    server.close()


def test_overlap_dialog(qapp):
    from blockads_linux.gui.pages.filters import OverlapDialog

    report = {"total_entries": 7, "unique_domains": 5, "overlapping_domains": 2, "redundant_entries": 2,
              "redundancy_percent": 28.57, "missing": ["late"],
              "names": {"a": "List A", "b": "List B", "late": "Late"},
              "lists": [{"id": "a", "total": 5, "shared": 2, "unique": 3, "shared_percent": 40.0},
                        {"id": "b", "total": 2, "shared": 2, "unique": 0, "shared_percent": 100.0}],
              "pairs": [{"a": "a", "b": "b", "shared": 2}]}

    class Client:
        def call(self, method, *args):
            assert method == "GetFilterOverlap"
            return _Pending(report)

    dialog = OverlapDialog(type("Ctx", (), {"client": Client()})())
    assert dialog.summary.text() == ("2 lists hold 7 entries for 5 different domains: "
                                     "2 entries (28.6%) are duplicates.")
    assert dialog.lists.rowCount() == 2 and dialog.lists.item(0, 0).text() == "List B"  # most shared first
    assert dialog.lists.item(0, 2).text() == "2 (100.0%)" and dialog.lists.item(0, 3).text() == "0"
    assert dialog.pairs.rowCount() == 1 and dialog.pairs.item(0, 2).text() == "2"
    assert "Every domain of List B" in dialog.note.text() and "Late" in dialog.note.text()
    dialog.show_report({**report, "lists": report["lists"][:1], "pairs": [], "missing": []})
    assert dialog.summary.text() == "Enable at least two lists to compare them." and dialog.note.isHidden()
