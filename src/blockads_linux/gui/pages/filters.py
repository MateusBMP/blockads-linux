"""Filters: the catalog by category, search, toggles, rule counts, update, custom lists, schedule."""

from __future__ import annotations

import json
from typing import Any

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QHeaderView,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QTabBar,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from .. import format as fmt
from .base import Context, Page, error_text, heading, plain
from ..format import QT_TRANSLATE_NOOP

CATEGORY_LABELS = {
    "enabled": QT_TRANSLATE_NOOP("FiltersPage", "Enabled"), "security": QT_TRANSLATE_NOOP("FiltersPage", "Security"), "ads": QT_TRANSLATE_NOOP("FiltersPage", "Ads"), "privacy": QT_TRANSLATE_NOOP("FiltersPage", "Privacy"), "social": QT_TRANSLATE_NOOP("FiltersPage", "Social"),
    "annoyances": QT_TRANSLATE_NOOP("FiltersPage", "Annoyances"), "regional": QT_TRANSLATE_NOOP("FiltersPage", "Regional"), "other": QT_TRANSLATE_NOOP("FiltersPage", "Other"), "custom": QT_TRANSLATE_NOOP("FiltersPage", "Custom"),
}
INTERVALS = ((0, QT_TRANSLATE_NOOP("FiltersPage", "Manually only")), (6, QT_TRANSLATE_NOOP("FiltersPage", "Every 6 hours")), (12, QT_TRANSLATE_NOOP("FiltersPage", "Every 12 hours")), (24, QT_TRANSLATE_NOOP("FiltersPage", "Every day")),
             (48, QT_TRANSLATE_NOOP("FiltersPage", "Every 2 days")))
COLUMNS = ("", QT_TRANSLATE_NOOP("FiltersPage", "Name"), QT_TRANSLATE_NOOP("FiltersPage", "Rules"), QT_TRANSLATE_NOOP("FiltersPage", "Updated"), QT_TRANSLATE_NOOP("FiltersPage", "Status"))


def list_status(entry: dict[str, Any]) -> str:
    if entry.get("retired"):
        return fmt.translate("FiltersPage", "Retired: %1").replace("%1", fmt.safe(entry["retired"], 80))
    if entry.get("error"):
        return fmt.translate("FiltersPage", "Error: %1").replace("%1", fmt.safe(entry["error"], 120))
    if entry.get("enabled") and not entry.get("downloaded"):
        return fmt.translate("FiltersPage", "Waiting for download")
    return ""


def visible(entry: dict[str, Any], category: str, search: str) -> bool:
    if category == "enabled" and not entry.get("enabled"):
        return False
    if category == "custom" and not entry.get("custom"):
        return False
    if category not in ("enabled", "custom") and entry.get("category") != category:
        return False
    if search:
        needle = search.lower()
        return any(needle in str(entry.get(key, "")).lower() for key in ("name", "description", "id"))
    return True


class CustomListDialog(QDialog):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(self.tr("Add a custom list"))
        form = QFormLayout(self)
        self.name = QLineEdit()
        self.name.setMaxLength(200)
        self.urls = QPlainTextEdit()
        self.urls.setPlaceholderText(self.tr("One https:// URL per line (hosts, adblock or plain domains)"))
        form.addRow(self.tr("Name"), self.name)
        form.addRow(self.tr("URLs"), self.urls)
        form.addRow(plain(self.tr("Adding a list URL lets the system download from a new host, so it "
                                  "needs an administrator password.")))
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        form.addRow(buttons)

    def value(self) -> dict[str, Any]:
        urls = [line.strip() for line in self.urls.toPlainText().splitlines() if line.strip()]
        return {"name": self.name.text().strip() or "Custom list", "urls": urls}


class OverlapDialog(QDialog):
    """How much the enabled lists duplicate each other (GetFilterOverlap)."""

    def __init__(self, ctx: Context, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(self.tr("Filter list overlap"))
        self.resize(720, 520)
        layout = QVBoxLayout(self)
        self.summary = plain(self.tr("Comparing the enabled lists…"))
        layout.addWidget(self.summary)
        self.lists = QTableWidget(0, 4)
        self.lists.setHorizontalHeaderLabels([self.tr("List"), self.tr("Domains"), self.tr("Also in another list"),
                                              self.tr("Only in this list")])
        self.pairs = QTableWidget(0, 3)
        self.pairs.setHorizontalHeaderLabels([self.tr("List"), self.tr("List"), self.tr("Shared domains")])
        for table in (self.lists, self.pairs):
            table.verticalHeader().setVisible(False)
            table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
            table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
            header = table.horizontalHeader()
            header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
            for column in range(1, table.columnCount()):
                header.setSectionResizeMode(column, QHeaderView.ResizeMode.ResizeToContents)
        self.pairs.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.lists, 3)
        layout.addWidget(plain(self.tr("Lists that share the most domains:")))
        layout.addWidget(self.pairs, 2)
        self.note = plain()
        layout.addWidget(self.note)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        ctx.client.call("GetFilterOverlap").then(self.show_report, self.failed)

    def failed(self, error: Any) -> None:
        self.summary.setText(error_text(error))

    def show_report(self, report: dict[str, Any]) -> None:
        names = report.get("names", {})

        def name(list_id: str) -> str:
            return fmt.safe(names.get(list_id, list_id), 120)

        def cell(text: str, number: bool = False) -> QTableWidgetItem:
            item = QTableWidgetItem(text)
            if number:
                item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            return item

        rows = sorted(report.get("lists", []), key=lambda r: -r["shared_percent"])
        if len(rows) < 2:
            self.summary.setText(self.tr("Enable at least two lists to compare them."))
        else:
            self.summary.setText(
                self.tr("%1 lists hold %2 entries for %3 different domains: %4 entries (%5%) are duplicates.")
                .replace("%1", str(len(rows))).replace("%2", fmt.number(report["total_entries"]))
                .replace("%3", fmt.number(report["unique_domains"]))
                .replace("%4", fmt.number(report["redundant_entries"]))
                .replace("%5", f"{report['redundancy_percent']:.1f}"))
        self.lists.setRowCount(len(rows))
        for row, entry in enumerate(rows):
            self.lists.setItem(row, 0, cell(name(entry["id"])))
            self.lists.setItem(row, 1, cell(fmt.number(entry["total"]), True))
            self.lists.setItem(row, 2, cell(f"{fmt.number(entry['shared'])} ({entry['shared_percent']:.1f}%)", True))
            self.lists.setItem(row, 3, cell(fmt.number(entry["unique"]), True))
        pairs = report.get("pairs", [])[:10]
        self.pairs.setRowCount(len(pairs))
        for row, pair in enumerate(pairs):
            self.pairs.setItem(row, 0, cell(name(pair["a"])))
            self.pairs.setItem(row, 1, cell(name(pair["b"])))
            self.pairs.setItem(row, 2, cell(fmt.number(pair["shared"]), True))
        notes = []
        covered = [name(r["id"]) for r in rows if r["total"] and r["unique"] == 0]
        if covered and len(rows) > 1:
            notes.append(self.tr("Every domain of %1 is also in another list: disabling it alone would unblock "
                                 "nothing.").replace("%1", ", ".join(covered)))
        if report.get("missing"):
            notes.append(self.tr("Not compared (not downloaded yet): %1")
                         .replace("%1", ", ".join(name(i) for i in report["missing"])))
        self.note.setText("\n".join(notes))
        self.note.setVisible(bool(notes))


class FiltersPage(Page):
    title = "Filters"
    icon = "view-filter"

    def __init__(self, ctx: Context, parent: QWidget | None = None) -> None:
        super().__init__(ctx, parent)
        self.title = self.tr("Filters")
        self.entries: list[dict[str, Any]] = []
        self.catalog: dict[str, Any] = {}
        self._filling = False

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        top = QHBoxLayout()
        top.addWidget(heading(self.tr("Filters")))
        top.addStretch(1)
        self.summary = plain(wrap=False)
        top.addWidget(self.summary)
        self.update_button = QPushButton(self.tr("Update now"))
        self.update_button.clicked.connect(lambda: self.act(
            "UpdateFiltersNow", done=self.tr("Update requested; lists are downloaded in the background.")))
        top.addWidget(self.update_button)
        self.overlap_button = QPushButton(self.tr("Overlap…"))
        self.overlap_button.setToolTip(self.tr("How much the enabled lists duplicate each other"))
        self.overlap_button.clicked.connect(lambda: OverlapDialog(self.ctx, self).exec())
        top.addWidget(self.overlap_button)
        layout.addLayout(top)

        self.tabs = QTabBar()
        self.categories = ["enabled", "security", "ads", "privacy", "social", "annoyances", "regional", "other",
                           "custom"]
        for key in self.categories:
            self.tabs.addTab(self.tr(CATEGORY_LABELS[key]))
        self.tabs.currentChanged.connect(lambda _i: self._fill())
        layout.addWidget(self.tabs)

        self.search = QLineEdit()
        self.search.setPlaceholderText(self.tr("Search lists"))
        self.search.setClearButtonEnabled(True)
        self.search.textChanged.connect(lambda _t: self._fill())
        layout.addWidget(self.search)

        self.table = QTableWidget(0, len(COLUMNS))
        self.table.setHorizontalHeaderLabels([self.tr(c) if c else "" for c in COLUMNS])
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        for column in (2, 3, 4):
            header.setSectionResizeMode(column, QHeaderView.ResizeMode.ResizeToContents)
        self.table.itemChanged.connect(self._changed)
        layout.addWidget(self.table, 1)

        bottom = QHBoxLayout()
        self.add_button = QPushButton(self.tr("Add custom list…"))
        self.add_button.clicked.connect(self.add_custom)
        self.remove_button = QPushButton(self.tr("Remove custom list"))
        self.remove_button.clicked.connect(self.remove_custom)
        bottom.addWidget(self.add_button)
        bottom.addWidget(self.remove_button)
        bottom.addStretch(1)
        bottom.addWidget(plain(self.tr("Update:"), wrap=False))
        self.interval = QComboBox()
        for hours, label in INTERVALS:
            self.interval.addItem(self.tr(label), hours)
        self.unmetered = QCheckBox(self.tr("Only on unmetered networks"))
        self.interval.activated.connect(lambda _i: self._schedule())
        self.unmetered.clicked.connect(lambda _c: self._schedule())
        bottom.addWidget(self.interval)
        bottom.addWidget(self.unmetered)
        layout.addLayout(bottom)

        ctx.client.filters_updated.connect(self._filters_updated)

    def _filters_updated(self, _generation: int) -> None:
        if self.active:
            self.refresh()

    def refresh(self) -> None:
        self.load("GetFilterCatalog", then=self.show_catalog)

    def show_catalog(self, catalog: dict[str, Any]) -> None:
        self.catalog = catalog
        entries = [dict(e) for e in catalog.get("lists", []) if not (e.get("retired") and not e.get("enabled"))]
        entries += [dict(e, custom=True, category="custom", description=", ".join(e.get("urls", [])))
                    for e in catalog.get("custom", [])]
        self.entries = entries
        enabled = [e for e in entries if e.get("enabled")]
        rules = sum(int(e.get("rules", 0)) for e in enabled)
        self.summary.setText(self.tr("%1 enabled, %2 rules").replace("%1", str(len(enabled)))
                             .replace("%2", fmt.number(rules)))
        index = self.interval.findData(catalog.get("update_interval_hours", 24))
        self.interval.setCurrentIndex(max(0, index))
        self.unmetered.setChecked(bool(catalog.get("unmetered_only")))
        self._fill()

    def _fill(self) -> None:
        category = self.categories[max(0, self.tabs.currentIndex())]
        search = self.search.text().strip()
        rows = [e for e in self.entries if visible(e, category, search)]
        rows.sort(key=lambda e: (not e.get("enabled"), str(e.get("name", "")).lower()))
        self._filling = True
        self.table.setRowCount(len(rows))
        for row, entry in enumerate(rows):
            check = QTableWidgetItem()
            check.setFlags(Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
            check.setCheckState(Qt.CheckState.Checked if entry.get("enabled") else Qt.CheckState.Unchecked)
            check.setData(Qt.ItemDataRole.UserRole, entry["id"])
            if entry.get("retired") and not entry.get("enabled"):
                check.setFlags(Qt.ItemFlag.ItemIsSelectable)
            name = QTableWidgetItem(fmt.safe(entry.get("name", entry["id"]), 120))
            name.setToolTip(fmt.safe(entry.get("description", ""), 1000))
            name.setData(Qt.ItemDataRole.UserRole, entry["id"])
            count = int(entry.get("rules") or 0) if entry.get("downloaded") else int(entry.get("approx_rules") or 0)
            rules = QTableWidgetItem(fmt.number(count) if count else "")
            if not entry.get("downloaded") and count:
                rules.setText("≈" + rules.text())
            rules.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            updated = QTableWidgetItem(fmt.when(entry.get("changed_at", 0)) if entry.get("downloaded") else "")
            status = QTableWidgetItem(list_status(entry))
            for column, item in enumerate((check, name, rules, updated, status)):
                self.table.setItem(row, column, item)
        self._filling = False
        self.remove_button.setEnabled(category == "custom")

    def _changed(self, item: QTableWidgetItem) -> None:
        if self._filling or item.column() != 0:
            return
        list_id = item.data(Qt.ItemDataRole.UserRole)
        enable = item.checkState() == Qt.CheckState.Checked
        if enable:
            self.act("EnableFilters", [list_id], done=self.tr("List enabled; it is downloaded in the background."))
        else:
            self.act("DisableFilters", [list_id], done=self.tr("List disabled."))

    def selected_id(self) -> str | None:
        row = self.table.currentRow()
        item = self.table.item(row, 0) if row >= 0 else None
        return item.data(Qt.ItemDataRole.UserRole) if item is not None else None

    def add_custom(self) -> None:
        dialog = CustomListDialog(self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        value = dialog.value()
        if not value["urls"]:
            self.ctx.messages.error(self.tr("Enter at least one URL."))
            return
        self.act("AddCustomFilter", json.dumps(value), done=self.tr("Custom list added."))

    def remove_custom(self) -> None:
        list_id = self.selected_id()
        if list_id and any(e["id"] == list_id and e.get("custom") for e in self.entries):
            self.act("RemoveCustomFilter", list_id, done=self.tr("Custom list removed."))

    def _schedule(self) -> None:
        self.act("SetFilterSchedule", int(self.interval.currentData()), self.unmetered.isChecked(),
                 done=self.tr("Update schedule saved."))
