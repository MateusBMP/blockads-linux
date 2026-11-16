"""Main window: left navigation, a stack of pages, a banner when the daemon is not running,
and a message bar for the results of actions."""

from __future__ import annotations

from PyQt6.QtCore import QSize, Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QCloseEvent, QIcon
from PyQt6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from .icons import app_icon
from .pages.about import AboutPage
from .pages.base import Context, Page
from .pages.dns import DnsPage
from .pages.filters import FiltersPage
from .pages.home import HomePage
from .pages.networks import NetworksPage
from .pages.querylog import QueryLogPage
from .pages.rules import RulesPage
from .pages.settings import SettingsPage
from .pages.statistics import StatisticsPage

MESSAGE_MS = 6000


class MainWindow(QMainWindow):
    hidden_to_tray = pyqtSignal()

    def __init__(self, ctx: Context, systemd=None, extra_pages: list[Page] | None = None) -> None:
        super().__init__()
        self.ctx = ctx
        self.keep_in_tray = lambda: False
        self.setWindowTitle("BlockAds")
        self.setWindowIcon(app_icon())
        self.resize(1040, 720)

        central = QWidget()
        self.setCentralWidget(central)
        outer = QVBoxLayout(central)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        self.banner = QLabel()
        self.banner.setObjectName("banner")
        self.banner.setTextFormat(Qt.TextFormat.PlainText)
        self.banner.setWordWrap(True)
        self.banner.setContentsMargins(16, 8, 16, 8)
        self.banner.setStyleSheet("#banner { background: #c62828; color: white; }")
        self.banner.hide()
        outer.addWidget(self.banner)

        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(0)
        outer.addLayout(row, 1)
        self.nav = QListWidget()
        self.nav.setObjectName("nav")
        self.nav.setFixedWidth(190)
        self.nav.setIconSize(QSize(20, 20))
        self.stack = QStackedWidget()
        row.addWidget(self.nav)
        row.addWidget(self.stack, 1)

        self.message = QLabel()
        self.message.setObjectName("message")
        self.message.setTextFormat(Qt.TextFormat.PlainText)
        self.message.setWordWrap(True)
        self.message.setContentsMargins(16, 6, 16, 6)
        self.message.hide()
        outer.addWidget(self.message)
        self._message_timer = QTimer(self)
        self._message_timer.setSingleShot(True)
        self._message_timer.timeout.connect(self.message.hide)

        self.pages: dict[str, Page] = {}
        pages: list[tuple[str, Page]] = [
            ("home", HomePage(ctx, systemd)),
            ("filters", FiltersPage(ctx)),
            ("rules", RulesPage(ctx)),
            ("log", QueryLogPage(ctx)),
            ("statistics", StatisticsPage(ctx)),
            ("dns", DnsPage(ctx)),
            ("networks", NetworksPage(ctx)),
        ]
        pages += [(getattr(page, "key", type(page).__name__.lower()), page) for page in extra_pages or []]
        pages += [("settings", SettingsPage(ctx)), ("about", AboutPage(ctx))]
        for key, page in pages:
            self.add_page(key, page)
        self.nav.currentRowChanged.connect(self._switch)
        self.nav.setCurrentRow(0)

        ctx.messages.shown.connect(self.show_message)
        ctx.status.updated.connect(self._status_ok)
        ctx.status.unavailable.connect(self._banner)

    def add_page(self, key: str, page: Page) -> None:
        item = QListWidgetItem(QIcon.fromTheme(page.icon), page.title)
        item.setData(Qt.ItemDataRole.UserRole, key)
        item.setSizeHint(QSize(0, 36))
        self.nav.addItem(item)
        self.stack.addWidget(page)
        self.pages[key] = page

    def show_page(self, key: str) -> None:
        for row in range(self.nav.count()):
            if self.nav.item(row).data(Qt.ItemDataRole.UserRole) == key:
                self.nav.setCurrentRow(row)
                return

    def current_page(self) -> Page:
        return self.stack.currentWidget()

    def _switch(self, row: int) -> None:
        previous = self.stack.currentWidget()
        if isinstance(previous, Page) and previous.active:
            previous.deactivate()
        self.stack.setCurrentIndex(row)
        page = self.stack.currentWidget()
        if isinstance(page, Page) and self.isVisible():
            page.activate()

    def showEvent(self, event) -> None:  # noqa: N802
        super().showEvent(event)
        self.ctx.status.set_fast(True)
        page = self.current_page()
        if isinstance(page, Page) and not page.active:
            page.activate()

    def hideEvent(self, event) -> None:  # noqa: N802
        super().hideEvent(event)
        self.ctx.status.set_fast(False)
        page = self.current_page()
        if isinstance(page, Page) and page.active:
            page.deactivate()

    def closeEvent(self, event: QCloseEvent) -> None:  # noqa: N802
        if self.keep_in_tray():
            event.ignore()
            self.hide()
            self.hidden_to_tray.emit()
            return
        super().closeEvent(event)

    def show_message(self, text: str, error: bool) -> None:
        self.message.setText(text)
        color = "#c62828" if error else self.palette().color(self.palette().ColorRole.Highlight).name()
        self.message.setStyleSheet(f"#message {{ background: {color}; color: white; }}")
        self.message.show()
        self._message_timer.start(MESSAGE_MS * (2 if error else 1))

    def _status_ok(self, _status: dict) -> None:
        self._banner(None)

    def _banner(self, error) -> None:
        if error is None:
            self.banner.hide()
            return
        if error.kind == "not_running":
            self.banner.setText(self.tr("The BlockAds service is not running: DNS is not filtered. "
                                        "Start it from the Home page."))
        else:
            self.banner.setText(error.message)
        self.banner.show()
