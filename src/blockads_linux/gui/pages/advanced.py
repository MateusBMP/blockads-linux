"""Advanced: firewall options (``pkexec blockads-fw set-config``), helper status/doctor, stop the service.

The helper reads ``firewall.conf`` itself; the GUI only shows the current
values (the file is world-readable) and sends the changed keys as JSON on
stdin. Options other than the bridge take effect when the service restarts,
so after a successful change the GUI asks systemd to try-restart it.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from PyQt6.QtCore import QProcess
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from ...common import diagnostics
from .. import format as fmt
from ..dbus_client import CallError
from ..selftest import SelfTest
from ..systemd_client import UNITS_STOP
from .base import Card, Context, Page, heading, plain

HELPER = "/usr/lib/blockads-linux/blockads-fw"
CONF_PATH = Path("/etc/blockads-linux/firewall.conf")
DEFAULTS: dict[str, Any] = {"ipv6": "auto", "block_dot": True, "block_webrtc": False,
                            "bypass_cidrs": ["100.100.100.100/32", "fd7a:115c:a1e0::53/128"],
                            "bridge_interfaces": []}
SUGGESTED_BRIDGES = ["docker0", "br-+", "virbr+", "podman+", "cni-podman+", "lxcbr+", "incusbr+"]
HELPER_TIMEOUT_MS = 330_000  # the password prompt, then a possible service restart


def read_config(path: Path = CONF_PATH) -> dict[str, Any]:
    """The user-changeable keys of firewall.conf (defaults when missing or unreadable)."""
    config = dict(DEFAULTS)
    try:
        text = path.read_text("utf-8", errors="replace")[:65536]
    except OSError:
        return config
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = (part.strip() for part in line.split("=", 1))
        if key in ("block_dot", "block_webrtc"):
            config[key] = value.lower() == "true"
        elif key == "ipv6":
            config[key] = value if value in ("auto", "off") else "auto"
        elif key in ("bypass_cidrs", "bridge_interfaces"):
            config[key] = [item.strip() for item in value.split(",") if item.strip()]
    return config


def config_change(current: dict[str, Any], wanted: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in wanted.items() if current.get(key) != value}


def split_list(text: str) -> list[str]:
    return [item.strip() for item in text.replace("\n", ",").split(",") if item.strip()]


def doctor_text(checks: Any) -> str:
    if not isinstance(checks, list):
        return ""
    lines = []
    for check in checks[:100]:
        if isinstance(check, dict):
            lines.append(f"{fmt.safe(check.get('level', ''), 8).upper():5} {fmt.safe(check.get('check', ''), 80)}: "
                         f"{fmt.safe(check.get('detail', ''), 300)}")
    return "\n".join(lines)


class AdvancedPage(Page):
    title = "Advanced"
    icon = "preferences-system"
    key = "advanced"

    def __init__(self, ctx: Context, systemd=None, helper: str = HELPER, conf_path: Path = CONF_PATH,
                 pkexec: tuple[str, ...] = ("pkexec",), parent: QWidget | None = None) -> None:
        super().__init__(ctx, parent)
        self.title = self.tr("Advanced")
        self.systemd = systemd
        self.helper = helper
        self.conf_path = conf_path
        self.pkexec = pkexec  # tests run a fake helper without it
        self.config = dict(DEFAULTS)
        self.process: QProcess | None = None
        self.selftest: SelfTest | None = None
        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)
        body = QWidget()
        scroll.setWidget(body)
        layout = QVBoxLayout(body)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.addWidget(heading(self.tr("Advanced")))

        firewall = Card(self.tr("Firewall"))
        form = QFormLayout()
        self.ipv6 = QComboBox()
        self.ipv6.addItem(self.tr("Filter IPv6 too (when available)"), "auto")
        self.ipv6.addItem(self.tr("IPv4 only"), "off")
        self.block_dot = QCheckBox(self.tr("Block DNS over TLS (port 853), so apps cannot bypass the filter"))
        self.block_webrtc = QCheckBox(self.tr("Block STUN/WebRTC (can stop video calls)"))
        self.bypass = QLineEdit()
        self.bypass.setPlaceholderText("100.100.100.100/32, …")
        self.bridges_on = QCheckBox(self.tr("Filter containers and virtual machines (Docker, Podman, libvirt…)"))
        self.bridges = QLineEdit()
        self.bridges.setPlaceholderText(", ".join(SUGGESTED_BRIDGES))
        self.bridges_on.toggled.connect(self._bridges_toggled)
        form.addRow(self.tr("IPv6"), self.ipv6)
        form.addRow(self.block_dot)
        form.addRow(self.block_webrtc)
        form.addRow(self.tr("DNS servers never redirected"), self.bypass)
        form.addRow(self.bridges_on)
        form.addRow(self.tr("Bridge interfaces"), self.bridges)
        firewall.layout_.addLayout(form)
        row = QHBoxLayout()
        row.addWidget(plain(self.tr("Changing these asks for the administrator password and restarts the "
                                    "filter service.")), 1)
        self.apply_button = QPushButton(self.tr("Apply"))
        self.apply_button.clicked.connect(self.apply_firewall)
        row.addWidget(self.apply_button)
        firewall.layout_.addLayout(row)
        layout.addWidget(firewall)

        diagnostics = Card(self.tr("Diagnostics"))
        buttons = QHBoxLayout()
        for label, args in ((self.tr("Firewall status"), ["status"]), (self.tr("Run checks"), ["doctor"])):
            button = QPushButton(label)
            button.clicked.connect(lambda _c=False, a=args: self.run_helper(a))
            buttons.addWidget(button)
        self.selftest_button = QPushButton(self.tr("Test filtering"))
        self.selftest_button.clicked.connect(self.run_selftest)
        buttons.addWidget(self.selftest_button)
        save = QPushButton(self.tr("Save diagnostics…"))
        save.setObjectName("save_diagnostics")
        save.clicked.connect(self.save_diagnostics)
        buttons.addWidget(save)
        buttons.addStretch(1)
        diagnostics.layout_.addLayout(buttons)
        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        self.output.setMinimumHeight(160)
        diagnostics.add(self.output)
        layout.addWidget(diagnostics)

        service = Card(self.tr("Service"))
        service.add(plain(self.tr("Stopping the service turns DNS filtering off until it is started again or "
                                  "the computer restarts.")))
        stop_row = QHBoxLayout()
        self.stop_button = QPushButton(self.tr("Stop the filter service…"))
        self.stop_button.clicked.connect(self.stop_service)
        stop_row.addWidget(self.stop_button)
        stop_row.addStretch(1)
        service.layout_.addLayout(stop_row)
        layout.addWidget(service)
        layout.addStretch(1)

    def refresh(self) -> None:
        self.config = read_config(self.conf_path)
        self.ipv6.setCurrentIndex(max(0, self.ipv6.findData(self.config["ipv6"])))
        self.block_dot.setChecked(self.config["block_dot"])
        self.block_webrtc.setChecked(self.config["block_webrtc"])
        self.bypass.setText(", ".join(self.config["bypass_cidrs"]))
        self.bridges_on.setChecked(bool(self.config["bridge_interfaces"]))
        self.bridges.setText(", ".join(self.config["bridge_interfaces"]))
        self.bridges.setEnabled(bool(self.config["bridge_interfaces"]))
        has_systemd = self.systemd is not None and self.systemd.enabled
        self.stop_button.setEnabled(has_systemd)

    def _bridges_toggled(self, on: bool) -> None:
        self.bridges.setEnabled(on)
        if on and not split_list(self.bridges.text()):
            self.bridges.setText(", ".join(SUGGESTED_BRIDGES))

    def wanted(self) -> dict[str, Any]:
        return {"ipv6": self.ipv6.currentData(), "block_dot": self.block_dot.isChecked(),
                "block_webrtc": self.block_webrtc.isChecked(), "bypass_cidrs": split_list(self.bypass.text()),
                "bridge_interfaces": split_list(self.bridges.text()) if self.bridges_on.isChecked() else []}

    def apply_firewall(self) -> None:
        change = config_change(self.config, self.wanted())
        if not change:
            self.ctx.messages.info(self.tr("Nothing to change."))
            return
        self.apply_button.setEnabled(False)

        def done(code: int, output: str) -> None:
            self.apply_button.setEnabled(True)
            if code == 0:
                self.ctx.messages.info(self.tr("Firewall options saved."))
                if "bridge_interfaces" not in change:  # set-config restarts the service itself for the bridge
                    self._restart()
            elif code in (126, 127):  # pkexec: dismissed or not authorized
                self.ctx.messages.error(self.tr("Not authorized: the firewall options were not changed."))
            else:
                self.ctx.messages.error(self.tr("The firewall options were not changed: %1").replace(
                    "%1", fmt.safe(output.strip().splitlines()[-1] if output.strip() else str(code), 300)))
            self.refresh()

        self._start([*self.pkexec, self.helper, "set-config"], json.dumps(change).encode(), done)

    def _restart(self) -> None:
        if self.systemd is None or not self.systemd.enabled or self.ctx.status.status is None:
            return
        self.systemd.call_unit("TryRestartUnit", "blockadsd.service").then(
            lambda _job: self.ctx.status.refresh(),
            lambda error: self.ctx.messages.error(self.tr("Restart the service to apply: %1").replace(
                "%1", error.message)))

    def run_helper(self, args: list[str]) -> None:
        self.output.setPlainText(self.tr("Running…"))

        def done(code: int, output: str) -> None:
            if code == -1:
                self.output.setPlainText(self.tr("blockads-fw is not installed."))
                return
            try:
                document = json.loads(output)
            except ValueError:
                self.output.setPlainText(fmt.safe(output, 20000))
                return
            if args[0] == "doctor":
                self.output.setPlainText(doctor_text(document))
            else:
                self.output.setPlainText(fmt.safe(json.dumps(document, indent=1, sort_keys=True), 20000))

        self._start([self.helper, *args, "--json"], b"", done)

    def run_selftest(self) -> None:
        if self.selftest is None:
            self.selftest = SelfTest(self.client, parent=self)
            self.selftest.finished.connect(lambda ok, text: (self.selftest_button.setEnabled(True),
                                                             self.output.setPlainText(text)))
        self.selftest_button.setEnabled(False)
        self.output.setPlainText(self.tr("Testing…"))
        self.selftest.start()

    def save_diagnostics(self) -> None:
        """A local JSON report for bug reports (common/diagnostics.py: no log, rules or network names)."""
        path, _ = QFileDialog.getSaveFileName(self, self.tr("Save diagnostics"), "blockads-diagnostics.json",
                                              self.tr("JSON files (*.json)"))
        if not path:
            return
        parts: dict[str, Any] = {}
        errors: dict[str, str] = {}
        pending = {"status", "settings", "catalog", "firewall", "doctor"}

        def finish(key: str, value: Any = None, error: str = "") -> None:
            if error:
                errors[key] = error
            else:
                parts[key] = value
            pending.discard(key)
            if not pending:
                write()

        def write() -> None:
            report = diagnostics.build(**parts, errors=errors)
            try:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    handle.write(json.dumps(report, indent=2) + "\n")
            except OSError as exc:
                self.ctx.messages.error(self.tr("Cannot write the file: %1").replace("%1", exc.strerror or str(exc)))
                return
            self.ctx.messages.info(self.tr("Diagnostics saved. They stay on this computer until you share them."))

        def helper(key: str, command: str, then) -> None:
            def done(code: int, output: str) -> None:
                if code == -1:
                    finish(key, error="blockads-fw is not installed")
                else:
                    try:
                        finish(key, json.loads(output))
                    except ValueError:
                        finish(key, error=fmt.safe(output, 300))
                then()
            self._start([self.helper, command, "--json"], b"", done)

        for key, method in (("status", "GetStatus"), ("settings", "GetSettings"), ("catalog", "GetFilterCatalog")):
            self.client.call(method).then(
                lambda result, k=key: finish(k, result.get("settings") if k == "settings" else result),
                lambda error, k=key: finish(k, error=error.message))
        helper("firewall", "status", lambda: helper("doctor", "doctor", lambda: None))

    def _start(self, argv: list[str], stdin: bytes, done) -> None:
        process = QProcess(self)
        process.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
        self.process = process

        def finished(code: int, _status) -> None:
            output = bytes(process.readAll()).decode("utf-8", "replace")[:200_000]
            process.deleteLater()
            done(code, output)

        def failed(error: QProcess.ProcessError) -> None:
            if error == QProcess.ProcessError.FailedToStart:
                process.deleteLater()
                done(-1, "")

        process.finished.connect(finished)
        process.errorOccurred.connect(failed)
        process.start(argv[0], argv[1:])
        if stdin:
            process.write(stdin)
        process.closeWriteChannel()

    def stop_service(self) -> None:
        if self.systemd is None or not self.systemd.enabled:
            return
        answer = QMessageBox.question(self, self.tr("Stop filtering"), self.tr(
            "Stop the filter service? DNS keeps working, unfiltered, until you start it again."))
        if answer != QMessageBox.StandardButton.Yes:
            return

        units = list(UNITS_STOP)  # one at a time: polkit's auth_admin_keep asks once

        def next_unit(_job: Any = None) -> None:
            if not units:
                self.ctx.messages.info(self.tr("The filter service is stopped."))
                self.ctx.status.refresh()
                return
            self.systemd.stop(units.pop(0)).then(next_unit, failed)

        def failed(error: CallError) -> None:
            self.ctx.messages.error(self.tr("Could not stop the service: %1").replace("%1", error.message))
            self.ctx.status.refresh()

        next_unit()
