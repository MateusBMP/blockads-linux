"""Query log: newest first, live updates, filters, details, block/allow/copy, CSV export.

There are no per-query signals (the system bus broadcasts them to everyone):
while the page is visible it polls ``GetQueryLog(after_id)``. Older
entries load page by page as the table scrolls (``fetchMore``).
"""

from __future__ import annotations

import json
import os
import time
from typing import Any

from PyQt6.QtCore import QAbstractTableModel, QModelIndex, Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLineEdit,
    QMenu,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from ...common import dbus_api
from .. import format as fmt
from .. import theme
from ..dbus_client import CallError, DaemonClient
from .base import Context, Page, error_text, heading, plain
from ..format import QT_TRANSLATE_NOOP

PAGE = 200
MAX_ROWS = 20_000  # kept in memory; older rows are dropped from the view
LIVE_MS = 1000
HORIZON = 2**62
VERDICTS = (("", QT_TRANSLATE_NOOP("QueryLogPage", "All")), ("blocked", QT_TRANSLATE_NOOP("QueryLogPage", "Blocked")), ("forwarded", QT_TRANSLATE_NOOP("QueryLogPage", "Allowed")), ("local", QT_TRANSLATE_NOOP("QueryLogPage", "Local")), ("failed", QT_TRANSLATE_NOOP("QueryLogPage", "Failed")))
RANGES = ((0, QT_TRANSLATE_NOOP("QueryLogPage", "All time")), (3600, QT_TRANSLATE_NOOP("QueryLogPage", "Last hour")), (86400, QT_TRANSLATE_NOOP("QueryLogPage", "Last 24 hours")), (7 * 86400, QT_TRANSLATE_NOOP("QueryLogPage", "Last 7 days")))
COLUMNS = (QT_TRANSLATE_NOOP("QueryLogPage", "Time"), QT_TRANSLATE_NOOP("QueryLogPage", "Domain"), QT_TRANSLATE_NOOP("QueryLogPage", "Type"), QT_TRANSLATE_NOOP("QueryLogPage", "Result"), QT_TRANSLATE_NOOP("QueryLogPage", "Reason"))
QTYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV",
          64: "SVCB", 65: "HTTPS", 255: "ANY"}


def qtype_name(value: Any) -> str:
    if isinstance(value, int):
        return QTYPES.get(value, f"TYPE{value}")
    return fmt.safe(value, 12)


class LogModel(QAbstractTableModel):
    """Entries newest first. ``loading`` guards against overlapping calls."""

    loaded = pyqtSignal()
    failed = pyqtSignal(object)

    def __init__(self, client: DaemonClient, parent=None) -> None:
        super().__init__(parent)
        self.client = client
        self.rows: list[dict[str, Any]] = []
        self.query: dict[str, Any] = {}
        self.at_end = False
        self.loading = False
        self.generation = 0  # bumped on reset: replies to an older query are dropped

    # --- Qt model -------------------------------------------------------------------

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(COLUMNS)

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole):  # noqa: N802
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return fmt.translate("QueryLogPage", COLUMNS[section])
        return None

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        entry = self.rows[index.row()]
        column = index.column()
        if role == Qt.ItemDataRole.DisplayRole:
            if column == 0:
                return fmt.clock_ms(entry["time_ms"])
            if column == 1:
                return fmt.safe(entry["name"], 260)
            if column == 2:
                return qtype_name(entry.get("qtype"))
            if column == 3:
                return fmt.verdict(entry.get("verdict", ""))
            if column == 4:
                return fmt.reason(entry.get("reason", ""))
        if role == Qt.ItemDataRole.ForegroundRole and column == 3:
            if entry.get("verdict") == "blocked":
                return QColor(theme.BLOCKED)
            if entry.get("verdict") == "failed":
                return QColor(theme.STATUS["paused"])
        if role == Qt.ItemDataRole.ToolTipRole and column == 0:
            return fmt.stamp_ms(entry["time_ms"])
        if role == Qt.ItemDataRole.UserRole:
            return entry
        return None

    def canFetchMore(self, parent: QModelIndex = QModelIndex()) -> bool:  # noqa: N802
        return not parent.isValid() and not self.at_end and not self.loading and bool(self.rows)

    def fetchMore(self, parent: QModelIndex = QModelIndex()) -> None:  # noqa: N802
        if self.canFetchMore(parent):
            self._older()

    # --- loading ----------------------------------------------------------------------

    def reset(self, query: dict[str, Any]) -> None:
        self.generation += 1
        self.beginResetModel()
        self.rows = []
        self.query = query
        self.at_end = False
        self.loading = False
        self.endResetModel()
        self._older()

    def _call(self, filter_doc: dict[str, Any], after_id: int, limit: int, then) -> None:
        generation = self.generation
        self.loading = True

        def ok(result: dict[str, Any]) -> None:
            if generation != self.generation:
                return
            self.loading = False
            then(result.get("entries", []))
            self.loaded.emit()

        def failed(error: CallError) -> None:
            if generation != self.generation:
                return
            self.loading = False
            self.failed.emit(error)

        self.client.call("GetQueryLog", json.dumps(filter_doc), after_id, limit).then(ok, failed)

    def _older(self) -> None:
        before = self.rows[-1]["id"] if self.rows else HORIZON
        self._call({**self.query, "before_id": before}, 0, PAGE, self._append)

    def _append(self, entries: list[dict[str, Any]]) -> None:
        if len(entries) < PAGE:
            self.at_end = True
        room = MAX_ROWS - len(self.rows)
        entries = entries[:max(0, room)]
        if not entries:
            return
        self.beginInsertRows(QModelIndex(), len(self.rows), len(self.rows) + len(entries) - 1)
        self.rows.extend(entries)
        self.endInsertRows()

    def poll_newer(self) -> None:
        """Live mode: entries newer than the newest row, oldest first from the daemon."""
        if self.loading:
            return
        newest = self.rows[0]["id"] if self.rows else 0
        if not self.rows and not self.at_end:
            return
        self._call(self.query, newest, dbus_api.MAX_LOG_PAGE, self._prepend)

    def _prepend(self, entries: list[dict[str, Any]]) -> None:
        if not entries:
            return
        entries = list(reversed(entries))
        self.beginInsertRows(QModelIndex(), 0, len(entries) - 1)
        self.rows[:0] = entries
        self.endInsertRows()
        if len(self.rows) > MAX_ROWS:
            self.beginRemoveRows(QModelIndex(), MAX_ROWS, len(self.rows) - 1)
            del self.rows[MAX_ROWS:]
            self.endRemoveRows()
            self.at_end = False


def details_text(entry: dict[str, Any]) -> str:
    lines = [
        fmt.translate("QueryLogPage", "Domain: %1").replace("%1", fmt.safe(entry.get("name", ""), 260)),
        fmt.translate("QueryLogPage", "Time: %1").replace("%1", fmt.stamp_ms(entry.get("time_ms", 0))),
        fmt.translate("QueryLogPage", "Type: %1").replace("%1", qtype_name(entry.get("qtype"))),
        fmt.translate("QueryLogPage", "Result: %1").replace("%1", fmt.verdict(entry.get("verdict", ""))),
    ]
    if entry.get("reason"):
        lines.append(fmt.translate("QueryLogPage", "Reason: %1").replace("%1", fmt.reason(entry["reason"])))
    if entry.get("upstream"):
        lines.append(fmt.translate("QueryLogPage", "Answered by: %1 (%2)").replace("%1", fmt.safe(entry["upstream"], 120))
                     .replace("%2", fmt.tier(entry.get("tier", ""))))
    if entry.get("cached"):
        lines.append(fmt.translate("QueryLogPage", "From the cache"))
    if entry.get("elapsed_ms") is not None:
        lines.append(fmt.translate("QueryLogPage", "Time taken: %1 ms").replace("%1", str(entry.get("elapsed_ms"))))
    answers = entry.get("answers") or []
    if answers:
        lines.append(fmt.translate("QueryLogPage", "Answers: %1").replace("%1", ", ".join(fmt.safe(a, 60) for a in answers[:8])))
    return "\n".join(lines)


class QueryLogPage(Page):
    title = "Query log"
    icon = "view-history"

    def __init__(self, ctx: Context, parent: QWidget | None = None) -> None:
        super().__init__(ctx, parent)
        self.title = self.tr("Query log")
        self.recording = True
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        top = QHBoxLayout()
        top.addWidget(heading(self.tr("Query log")))
        top.addStretch(1)
        self.recording_label = plain(wrap=False)
        top.addWidget(self.recording_label)
        self.record_button = QPushButton()
        self.record_button.clicked.connect(self.toggle_recording)
        top.addWidget(self.record_button)
        layout.addLayout(top)

        filters = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText(self.tr("Search domains"))
        self.search.setClearButtonEnabled(True)
        self.verdict = QComboBox()
        for value, label in VERDICTS:
            self.verdict.addItem(self.tr(label), value)
        self.range = QComboBox()
        for seconds, label in RANGES:
            self.range.addItem(self.tr(label), seconds)
        filters.addWidget(self.search, 1)
        filters.addWidget(self.verdict)
        filters.addWidget(self.range)
        layout.addLayout(filters)
        self._debounce = QTimer(self)
        self._debounce.setSingleShot(True)
        self._debounce.setInterval(300)
        self._debounce.timeout.connect(self.reload)
        self.search.textChanged.connect(lambda _t: self._debounce.start())
        self.verdict.currentIndexChanged.connect(lambda _i: self.reload())
        self.range.currentIndexChanged.connect(lambda _i: self.reload())

        self.model = LogModel(ctx.client, self)
        self.model.failed.connect(self._failed)
        self.view = QTableView()
        self.view.setModel(self.model)
        self.view.verticalHeader().setVisible(False)
        self.view.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.view.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.view.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.view.customContextMenuRequested.connect(self._menu)
        header = self.view.horizontalHeader()
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        for column in (0, 2, 3, 4):
            header.setSectionResizeMode(column, QHeaderView.ResizeMode.ResizeToContents)
        self.details = plain()
        self.details.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.details.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
        self.view.selectionModel().currentRowChanged.connect(self._current)
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.addWidget(self.view)
        splitter.addWidget(self.details)
        splitter.setStretchFactor(0, 4)
        splitter.setStretchFactor(1, 1)
        layout.addWidget(splitter, 1)

        bottom = QHBoxLayout()
        for label, slot in ((self.tr("Block selected"), lambda: self.bulk(False)),
                            (self.tr("Allow selected"), lambda: self.bulk(True)),
                            (self.tr("Export CSV…"), self.export_csv),
                            (self.tr("Clear log…"), self.clear_log)):
            button = QPushButton(label)
            button.clicked.connect(slot)
            bottom.addWidget(button)
        bottom.addStretch(1)
        self.error = plain(wrap=False)
        bottom.addWidget(self.error)
        layout.addLayout(bottom)

        self.live = QTimer(self)
        self.live.setInterval(LIVE_MS)
        self.live.timeout.connect(self.model.poll_newer)
        self._loaded_once = False

    # --- lifecycle -------------------------------------------------------------------

    def activate(self) -> None:
        self.active = True
        if not self._loaded_once:
            self._loaded_once = True
            self.reload()
        if self.ctx.prefs.get("log_live"):
            self.live.start()
        self._recording_from_status()

    def deactivate(self) -> None:
        super().deactivate()
        self.live.stop()

    def refresh(self) -> None:
        self.reload()

    def query(self) -> dict[str, Any]:
        query: dict[str, Any] = {}
        if self.verdict.currentData():
            query["verdict"] = self.verdict.currentData()
        search = self.search.text().strip().lower()
        if search:
            query["search"] = search[:255]
        seconds = int(self.range.currentData() or 0)
        if seconds:
            query["since_ms"] = int((time.time() - seconds) * 1000)
        return query

    def reload(self) -> None:
        self.error.setText("")
        self.details.setText("")
        self.model.reset(self.query())

    def _failed(self, error: CallError) -> None:
        self.error.setText(error_text(error))

    def _recording_from_status(self) -> None:
        status = self.ctx.status.status or {}
        log = status.get("log")
        self.recording = bool(log.get("recording", True)) if log else True
        self.recording_label.setText("" if self.recording else self.tr("Not recording"))
        self.record_button.setText(self.tr("Pause recording") if self.recording else self.tr("Resume recording"))

    def toggle_recording(self) -> None:
        def then(settings: dict[str, Any]) -> None:
            retention = int(settings.get("settings", {}).get("logging", {}).get("retention_days", 7))
            self.act("SetLogging", not self.recording, retention,
                     done=self.tr("Recording resumed.") if not self.recording else self.tr("Recording paused."),
                     then=lambda _r: self.ctx.status.refresh())

        self.load("GetSettings", then=then)
        QTimer.singleShot(1500, self._recording_from_status)

    # --- selection and actions --------------------------------------------------------

    def selected(self) -> list[dict[str, Any]]:
        rows = sorted({index.row() for index in self.view.selectionModel().selectedRows()})
        return [self.model.rows[row] for row in rows if row < len(self.model.rows)]

    def _current(self, current: QModelIndex, _previous: QModelIndex) -> None:
        entry = self.model.data(current, Qt.ItemDataRole.UserRole) if current.isValid() else None
        self.details.setText(details_text(entry) if entry else "")

    def _menu(self, pos) -> None:
        entries = self.selected()
        if not entries:
            return
        menu = QMenu(self)
        menu.addAction(self.tr("Block"), lambda: self.bulk(False))
        menu.addAction(self.tr("Allow"), lambda: self.bulk(True))
        menu.addAction(self.tr("Copy domain"), lambda: QApplication.clipboard().setText(
            "\n".join(e["name"] for e in entries)))
        menu.addAction(self.tr("Which list blocks this?"), lambda: self.which(entries[0]["name"]))
        menu.exec(self.view.viewport().mapToGlobal(pos))

    def bulk(self, allow: bool) -> None:
        names = list(dict.fromkeys(e["name"].rstrip(".") for e in self.selected()))
        if not names:
            return
        method = "AddAllowRule" if allow else "AddBlockRule"
        done = self.tr("Added to the allowlist.") if allow else self.tr("Added to the blocklist.")
        for name in names[:100]:
            self.act(method, name, done=done, refresh=False)

    def which(self, name: str) -> None:
        def show(result: dict[str, Any]) -> None:
            if result.get("verdict") == "blocked":
                lists = ", ".join(fmt.safe(x, 80) for x in result.get("lists", [])) or fmt.reason(result["reason"])
                text = self.tr("%1 is blocked by: %2").replace("%1", fmt.safe(name, 200)).replace("%2", lists)
            else:
                text = self.tr("%1 is not blocked (%2).").replace("%1", fmt.safe(name, 200)).replace(
                    "%2", fmt.reason(result.get("reason", "")) or self.tr("no list matches"))
            self.ctx.messages.info(text)

        self.load("TestDomain", name.rstrip("."), then=show)

    def export_csv(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, self.tr("Export query log"), "blockads-log.csv",
                                              self.tr("CSV files (*.csv)"))
        if path:
            # PyQt holds bound methods of plain objects weakly: keep the export alive until it ends
            self.export = CsvExport(self, path, self.query())
            self.export.start()

    def clear_log(self) -> None:
        answer = QMessageBox.question(self, self.tr("Clear the query log"),
                                      self.tr("Delete every entry of the query log? Statistics are kept."))
        if answer == QMessageBox.StandardButton.Yes:
            self.act("ClearQueryLog", done=self.tr("Query log cleared."))


class CsvExport:
    """Pages through GetQueryLog (newest first) and writes the CSV with the formula guard."""

    LIMIT = 200_000

    def __init__(self, page: QueryLogPage, path: str, query: dict[str, Any]) -> None:
        self.page = page
        self.path = path
        self.query = query
        self.written = 0
        self.handle = None

    def start(self) -> None:
        try:
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            self.handle = os.fdopen(fd, "w", encoding="utf-8", newline="")
            self.handle.write(dbus_api.csv_rows([], header=True))
        except OSError as exc:
            self.page.ctx.messages.error(fmt.translate("QueryLogPage", "Cannot write the file: %1").replace(
                "%1", exc.strerror or str(exc)))
            return
        self._next(HORIZON)

    def _next(self, before: int) -> None:
        self.page.client.call("GetQueryLog", json.dumps({**self.query, "before_id": before}), 0,
                              dbus_api.MAX_LOG_PAGE).then(self._page, self._failed)

    def _page(self, result: dict[str, Any]) -> None:
        entries = result.get("entries", [])
        if entries:
            self.handle.write(dbus_api.csv_rows(entries, header=False))
            self.written += len(entries)
        if len(entries) < dbus_api.MAX_LOG_PAGE or self.written >= self.LIMIT:
            self.handle.close()
            self.page.ctx.messages.info(fmt.translate("QueryLogPage", "%1 entries exported.").replace("%1", fmt.number(self.written)))
            return
        self._next(entries[-1]["id"])

    def _failed(self, error: CallError) -> None:
        self.handle.close()
        self.page.ctx.messages.error(error_text(error))
