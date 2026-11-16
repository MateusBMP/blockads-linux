"""``blockads``: the desktop GUI.

One instance per user session: a second start asks the first to show its
window (``QLocalServer``) and exits. ``--hidden`` starts in the tray (autostart).
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import traceback
from pathlib import Path

from PyQt6.QtCore import QLibraryInfo, QLocale, QTranslator
from PyQt6.QtDBus import QDBusConnection
from PyQt6.QtNetwork import QLocalServer, QLocalSocket
from PyQt6.QtWidgets import QApplication

from ..common.legal import add_version_option
from .dbus_client import DaemonClient
from .main_window import MainWindow
from .notifications import Notifier
from .pages.advanced import AdvancedPage
from .pages.base import Context, Messages
from .prefs import Prefs
from .status import StatusModel
from .systemd_client import SystemdClient
from .theme import Theme
from .tray import Tray
from .wizard import OnboardingWizard

I18N_DIR = Path(__file__).resolve().parent / "i18n"
log = logging.getLogger("blockads.gui")


def install_excepthook() -> None:
    """PyQt aborts the process on an exception escaping a slot; log it and keep running."""
    def hook(kind, value, tb) -> None:
        log.error("unexpected error:\n%s", "".join(traceback.format_exception(kind, value, tb)))

    sys.excepthook = hook


def instance_name() -> str:
    return f"blockads-linux-gui-{os.getuid()}"


def signal_running_instance(name: str) -> bool:
    """True when another instance answered (it shows its window)."""
    socket = QLocalSocket()
    socket.connectToServer(name)
    if not socket.waitForConnected(500):
        return False
    socket.write(b"show\n")
    socket.flush()
    socket.waitForBytesWritten(500)
    socket.disconnectFromServer()
    return True


def install_translators(app: QApplication, language: str) -> list[QTranslator]:
    locale = QLocale() if language == "system" else QLocale(language)
    translators = []
    ours = QTranslator(app)
    if ours.load(locale, "blockads", "_", str(I18N_DIR)):
        app.installTranslator(ours)
        translators.append(ours)
    qt = QTranslator(app)
    if qt.load(locale, "qtbase", "_", QLibraryInfo.path(QLibraryInfo.LibraryPath.TranslationsPath)):
        app.installTranslator(qt)
        translators.append(qt)
    return translators


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="blockads", description="BlockAds desktop GUI")
    add_version_option(parser, "blockads")
    parser.add_argument("--bus", default="system",
                        help="the daemon's bus: system (default), session or a D-Bus address (development)")
    parser.add_argument("--hidden", action="store_true", help="start in the tray without opening the window")
    parser.add_argument("--page", default="home", help="page to open (home, filters, rules, log, statistics, …)")
    parser.add_argument("--no-single-instance", action="store_true", help=argparse.SUPPRESS)
    return parser


class Gui:
    """Everything one running GUI owns; built by ``main`` and by the tests."""

    def __init__(self, app: QApplication, bus: str, prefs: Prefs | None = None, *, tray: bool = True,
                 advanced: dict | None = None) -> None:
        self.app = app
        self.prefs = prefs or Prefs()
        self.theme = Theme(app)
        self.theme.apply(self.prefs.get("theme"), self.prefs.get("accent"))
        self.client = DaemonClient(bus, app)
        self.status = StatusModel(self.client, app)
        self.ctx = Context(self.client, self.status, self.prefs, Messages(app), self.theme)
        self.systemd = SystemdClient(self.client.connection, enabled=(bus == "system"), parent=app)
        self.window = MainWindow(self.ctx, self.systemd, [AdvancedPage(self.ctx, self.systemd, **(advanced or {}))])
        self.tray = Tray(self.ctx, app)
        self.tray.open_requested.connect(self.show_window)
        self.tray.quit_requested.connect(self.quit)
        self.tray.start_requested.connect(self.window.pages["home"].start_service)
        self.window.keep_in_tray = lambda: self.prefs.get("close_to_tray") and self.tray.visible
        self.notifier = Notifier(self.ctx, parent=app) if bus == "system" else Notifier(
            self.ctx, connection=_disconnected(), parent=app)
        if tray and self.prefs.get("tray"):
            self.tray.show()
        self.prefs_watch()
        self.status.start()

    def prefs_watch(self) -> None:
        settings_page = self.window.pages["settings"]
        box = settings_page.boxes["tray"]
        box.toggled.connect(lambda on: self.tray.show() if on else self.tray.hide())

    def onboard(self) -> OnboardingWizard:
        self.wizard = OnboardingWizard(self.ctx, self.systemd, self.window)
        self.wizard.show()
        return self.wizard

    def show_window(self) -> None:
        self.window.show()
        self.window.raise_()
        self.window.activateWindow()

    def dispose(self) -> None:
        """Delete everything this GUI owns (the tests build several in one QApplication)."""
        self.status.timer.stop()
        self.tray.hide()
        self.window.keep_in_tray = lambda: False
        self.window.close()
        for obj in (self.window, self.tray, self.notifier, self.status, self.systemd, self.client):
            obj.deleteLater()
        if self.client.bus not in ("system", "session"):
            QDBusConnection.disconnectFromBus(self.client.connection.name())

    def quit(self) -> None:
        self.tray.hide()
        self.app.quit()


def _disconnected() -> QDBusConnection:
    return QDBusConnection("blockads-none")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    install_excepthook()
    app = QApplication(sys.argv[:1])
    app.setApplicationName("blockads-linux")
    app.setApplicationDisplayName("BlockAds")
    app.setOrganizationName("blockads-linux")
    app.setDesktopFileName("io.github.mateusbmp.blockads-linux")
    app.setQuitOnLastWindowClosed(False)

    server = None
    if not args.no_single_instance:
        name = instance_name()
        if signal_running_instance(name):
            return 0
        QLocalServer.removeServer(name)
        server = QLocalServer(app)
        server.setSocketOptions(QLocalServer.SocketOption.UserAccessOption)
        server.listen(name)

    prefs = Prefs()
    install_translators(app, prefs.get("language"))
    gui = Gui(app, args.bus, prefs)
    gui.window.show_page(args.page)
    if server is not None:
        def connection() -> None:
            socket = server.nextPendingConnection()
            if socket is not None:
                socket.readyRead.connect(lambda: (socket.readAll(), gui.show_window()))
                socket.disconnected.connect(socket.deleteLater)
        server.newConnection.connect(connection)
    if not args.hidden or not gui.tray.visible:
        gui.show_window()
    if not prefs.get("onboarded") and not args.hidden:
        gui.onboard()
    app.lastWindowClosed.connect(lambda: None if gui.tray.visible else app.quit())
    return app.exec()
