"""The installed GUI in a VM: against the installed daemon, real polkit and systemd.

Run by system_checks.sh `sec_gui` as alice inside her active local session
(offscreen Qt; no polkit agent is registered, so every action that needs a
password is refused, which is what this checks for weakening actions):

    python3 -I gui_vm.py main    # status, tighten, view-logs, weaken refused, helper, self-test
    python3 -I gui_vm.py start   # the service was stopped by root: the GUI starts it, no password

Prints PASS/FAIL/INFO lines for system_checks.sh.
"""

from __future__ import annotations

import os
import sys
import tempfile
import time

sys.path.insert(0, "/usr/lib/blockads-linux/python")
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import QSettings  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication, QMessageBox  # noqa: E402

from blockads_linux.gui.app import Gui, install_excepthook  # noqa: E402
from blockads_linux.gui.prefs import Prefs  # noqa: E402

FAILURES = 0
BLOCKED = "gui-bt.example.com"


def report(level: str, name: str, detail: str = "") -> None:
    print(f"{level:5} [gui] {name:<62} {detail}"[:400], flush=True)


def ok(name: str, condition: bool, detail: str = "") -> None:
    global FAILURES
    report("PASS" if condition else "FAIL", name, detail)
    FAILURES += not condition


def wait_until(predicate, timeout: float = 20.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        QTest.qWait(50)
    return predicate()


def build() -> tuple[QApplication, Gui, list]:
    app = QApplication.instance() or QApplication(["blockads"])
    install_excepthook()
    settings = QSettings(os.path.join(tempfile.mkdtemp(), "gui.conf"), QSettings.Format.IniFormat)
    gui = Gui(app, "system", Prefs(settings), tray=False)
    seen: list = []
    gui.ctx.messages.shown.connect(lambda text, error: seen.append((text, error)))
    gui.show_window()
    return app, gui, seen


def phase_main() -> None:
    app, gui, seen = build()
    home = gui.window.pages["home"]
    ok("status reached: protected", wait_until(lambda: gui.status.state == "active"),
       f"state={gui.status.state} label={home.state_label.text()!r}")
    health = (gui.status.status or {}).get("health") or {}
    ok("interception reported (applied by blockads-fw)", "ipv4" in health.get("interception", []),
       str(health.get("interception")))
    ok("no banner", not gui.window.banner.isVisible())

    # tighten: no password for the active local user
    rules = gui.window.pages["rules"]
    gui.window.show_page("rules")
    rules.block_list.input.setText(BLOCKED)
    rules.block_list.add()
    ok("block a domain (tighten), no password",
       wait_until(lambda: any(rules.block_list.list.item(i).text() == BLOCKED
                              for i in range(rules.block_list.list.count()))), seen[-1][0] if seen else "")

    # weaken without an agent: refused, explained, state unchanged
    gui.window.show_page("home")
    seen.clear()
    home.pause(0)
    ok("pause (weaken) refused without a polkit agent", wait_until(lambda: any(e for _t, e in seen)),
       seen[-1][0] if seen else "no message")
    QTest.qWait(500)
    ok("still protected after the refused pause", gui.status.state == "active", gui.status.state)

    # view-logs: allowed for the active session
    log = gui.window.pages["log"]
    gui.window.show_page("log")
    ok("query log loads (view-logs)", wait_until(lambda: log.model.rows or log.model.at_end) and not log.error.text(),
       f"{len(log.model.rows)} rows {log.error.text()!r}")

    # the self-test through the real system resolver (the blocked domain above is a candidate)
    from blockads_linux.gui.selftest import SelfTest
    results: list = []
    test = SelfTest(gui.client, candidates=(BLOCKED,))
    test.finished.connect(lambda passed, text: results.append((passed, text)))
    test.start()
    ok("self-test: applications get the blocked answer", wait_until(lambda: results, 30) and results[0][0],
       results[0][1] if results else "no result")

    # Advanced: the helper's status unprivileged; pkexec without an agent is refused
    advanced = gui.window.pages["advanced"]
    gui.window.show_page("advanced")
    advanced.run_helper(["status"])
    ok("Advanced: blockads-fw status --json", wait_until(lambda: '"applied": true' in advanced.output.toPlainText()),
       advanced.output.toPlainText()[:120].replace("\n", " "))
    advanced.run_helper(["doctor"])
    ok("Advanced: blockads-fw doctor --json", wait_until(lambda: "state:" in advanced.output.toPlainText()),
       advanced.output.toPlainText()[:160].replace("\n", " | "))
    seen.clear()
    advanced.block_webrtc.setChecked(not advanced.block_webrtc.isChecked())
    advanced.apply_firewall()
    ok("Advanced: pkexec set-config refused without an agent", wait_until(lambda: any(e for _t, e in seen), 60),
       seen[-1][0] if seen else "no message")
    QMessageBox.question = lambda *a, **k: QMessageBox.StandardButton.Yes  # the confirmation dialog
    seen.clear()
    advanced.stop_service()
    ok("Advanced: stopping the service needs authentication", wait_until(lambda: any(e for _t, e in seen), 60),
       seen[-1][0] if seen else "no message")
    ok("still protected after the refused stop", wait_until(lambda: gui.status.state == "active", 5), gui.status.state)
    gui.dispose()


def phase_start() -> None:
    app, gui, seen = build()
    home = gui.window.pages["home"]
    ok("service stopped by root: GUI shows not running", wait_until(lambda: gui.status.state == "off"),
       f"state={gui.status.state} banner={gui.window.banner.isVisible()}")
    ok("Start button enabled (system bus)", home.toggle.isEnabled(), home.toggle.text())
    home.toggle.click()
    ok("GUI starts the service without a password", wait_until(lambda: gui.status.state == "active", 40),
       f"state={gui.status.state} {seen[-1][0] if seen else ''}")
    gui.dispose()


if __name__ == "__main__":
    {"main": phase_main, "start": phase_start}[sys.argv[1]]()
    sys.exit(min(FAILURES, 125))
