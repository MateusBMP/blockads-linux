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
from .base import Context, Page, heading, plain
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
