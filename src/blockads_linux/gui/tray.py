"""Tray icon: green/yellow/grey/red; toggle, pause 15 min / 1 h / until resumed, open, quit.

Quitting closes the GUI only; the daemon keeps filtering.
"""

from __future__ import annotations

from typing import Any

from PyQt6.QtCore import QObject, pyqtSignal
from PyQt6.QtGui import QAction
from PyQt6.QtWidgets import QMenu, QSystemTrayIcon

from . import format as fmt
from .icons import state_icon
from .pages.base import Context, error_text
from .format import QT_TRANSLATE_NOOP

TRAY_PAUSES = ((15 * 60, QT_TRANSLATE_NOOP("Tray", "Pause for 15 minutes")), (3600, QT_TRANSLATE_NOOP("Tray", "Pause for 1 hour")), (0, QT_TRANSLATE_NOOP("Tray", "Pause until resumed")))


def tooltip(state: str, status: dict[str, Any] | None) -> str:
    if state == "off" or status is None:
        return fmt.translate("Tray", "BlockAds: not running")
    if state == "paused":
        return "BlockAds: " + fmt.pause_text(status)
    today = status.get("today") or {}
    line = fmt.translate("Tray", "BlockAds: protected") if state == "active" else fmt.translate("Tray", "BlockAds: needs attention")
    if today.get("total"):
        line += "\n" + fmt.translate("Tray", "%1 blocked today").replace("%1", fmt.number(today.get("blocked", 0)))
    return line


class Tray(QObject):
    open_requested = pyqtSignal()
    quit_requested = pyqtSignal()
    start_requested = pyqtSignal()

    def __init__(self, ctx: Context, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.ctx = ctx
        self.icon = QSystemTrayIcon(state_icon("off"), self)
        self.icon.activated.connect(self._activated)
        menu = QMenu()
        self.menu = menu
        self.status_action = QAction("", menu)
        self.status_action.setEnabled(False)
        menu.addAction(self.status_action)
        menu.addSeparator()
        self.toggle_action = QAction("", menu)
        self.toggle_action.triggered.connect(self._toggle)
        menu.addAction(self.toggle_action)
        self.pause_actions = []
        for seconds, label in TRAY_PAUSES:
            action = QAction(self.tr(label), menu)
            action.triggered.connect(lambda _c=False, s=seconds: self.pause(s))
            menu.addAction(action)
            self.pause_actions.append(action)
        menu.addSeparator()
        open_action = QAction(self.tr("Open BlockAds"), menu)
        open_action.triggered.connect(self.open_requested)
        menu.addAction(open_action)
        quit_action = QAction(self.tr("Quit (filtering continues)"), menu)
        quit_action.triggered.connect(self.quit_requested)
        menu.addAction(quit_action)
        self.icon.setContextMenu(menu)
        ctx.status.state_changed.connect(self.update_state)
        ctx.status.updated.connect(self.update_state)
        ctx.status.unavailable.connect(self.update_state)
        self.update_state()

    def show(self) -> None:
        if QSystemTrayIcon.isSystemTrayAvailable():
            self.icon.show()

    def hide(self) -> None:
        self.icon.hide()

    @property
    def visible(self) -> bool:
        return self.icon.isVisible()

    def update_state(self, *_signal_args: object) -> None:
        state, status = self.ctx.status.state, self.ctx.status.status
        self.icon.setIcon(state_icon(state))
        text = tooltip(state, status)
        self.icon.setToolTip(text)
        self.status_action.setText(text.splitlines()[0])
        if status is None:
            self.toggle_action.setText(self.tr("Start protection"))
        elif status["protection"]["state"] == "paused":
            self.toggle_action.setText(self.tr("Resume protection"))
        else:
            self.toggle_action.setText(self.tr("Pause protection"))
        for action in self.pause_actions:
            action.setVisible(status is not None and status["protection"]["state"] != "paused")

    def _activated(self, reason: QSystemTrayIcon.ActivationReason) -> None:
        if reason in (QSystemTrayIcon.ActivationReason.Trigger, QSystemTrayIcon.ActivationReason.DoubleClick):
            self.open_requested.emit()

    def _toggle(self) -> None:
        status = self.ctx.status.status
        if status is None:
            self.start_requested.emit()
        elif status["protection"]["state"] == "paused":
            self._call("Resume", self.tr("Protection resumed."))
        else:
            self.pause(0)

    def pause(self, seconds: int) -> None:
        self._call("Pause", self.tr("Protection paused."), seconds)

    def _call(self, method: str, done: str, *args: Any) -> None:
        def ok(_result: Any) -> None:
            self.ctx.messages.info(done)
            self.ctx.status.refresh()

        self.ctx.client.call(method, *args).then(ok, lambda e: self.ctx.messages.error(error_text(e)))
