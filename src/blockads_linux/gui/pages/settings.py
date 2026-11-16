"""Settings: appearance, language, tray, notifications, query log, autostart, backup/restore/reset."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from PyQt6.QtCore import QStandardPaths
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from ...common import android_import, dbus_api
from .. import theme
from .base import Card, Context, Page, heading, plain
from ..format import QT_TRANSLATE_NOOP, translate

UPDATE_STYLES = (("all", QT_TRANSLATE_NOOP("SettingsPage", "Every update")),
                 ("errors", QT_TRANSLATE_NOOP("SettingsPage", "Only failures")),
                 ("none", QT_TRANSLATE_NOOP("SettingsPage", "Never")))
LANGUAGES = (("system", QT_TRANSLATE_NOOP("SettingsPage", "System default")), ("en", "English"), ("pt_BR", "Português (Brasil)"))
ACCENT_LABELS = {"teal": QT_TRANSLATE_NOOP("SettingsPage", "Teal"), "blue": QT_TRANSLATE_NOOP("SettingsPage", "Blue"),
                 "indigo": QT_TRANSLATE_NOOP("SettingsPage", "Indigo"),
                 "purple": QT_TRANSLATE_NOOP("SettingsPage", "Purple"),
                 "green": QT_TRANSLATE_NOOP("SettingsPage", "Green"),
                 "orange": QT_TRANSLATE_NOOP("SettingsPage", "Orange")}
AUTOSTART_NAME = "io.github.mateusbmp.blockads-linux.desktop"


def autostart_path() -> Path:
    base = QStandardPaths.writableLocation(QStandardPaths.StandardLocation.ConfigLocation) or \
        os.path.expanduser("~/.config")
    return Path(base) / "autostart" / AUTOSTART_NAME


def autostart_entry() -> str:
    return ("[Desktop Entry]\nType=Application\nName=BlockAds\nExec=blockads --hidden\n"
            "Icon=io.github.mateusbmp.blockads-linux\nX-GNOME-Autostart-enabled=true\nNoDisplay=true\n")


def set_autostart(enabled: bool, path: Path | None = None) -> None:
    path = path or autostart_path()
    if enabled:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(autostart_entry())
    else:
        path.unlink(missing_ok=True)


def backup_document(settings: dict[str, Any], rules: dict[str, Any]) -> dict[str, Any]:
    """The same format as ``blockadsctl backup``."""
    return {"api": dbus_api.API_VERSION, "settings": settings, "rules": rules}


class SettingsPage(Page):
    title = "Settings"
    icon = "configure"

    def __init__(self, ctx: Context, parent: QWidget | None = None) -> None:
        super().__init__(ctx, parent)
        self.title = self.tr("Settings")
        self._filling = False
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
        layout.addWidget(heading(self.tr("Settings")))
        prefs = ctx.prefs

        look = Card(self.tr("Appearance"))
        form = QFormLayout()
        self.theme = QComboBox()
        for key, label in (("system", self.tr("System")), ("light", self.tr("Light")),
                           ("dark", self.tr("Dark")), ("black", self.tr("Black"))):
            self.theme.addItem(label, key)
        self.accent = QComboBox()
        for key in theme.ACCENTS:
            self.accent.addItem(self.tr(ACCENT_LABELS.get(key, key)), key)
        self.language = QComboBox()
        for key, label in LANGUAGES:
            self.language.addItem(self.tr(label) if key == "system" else label, key)
        form.addRow(self.tr("Theme"), self.theme)
        form.addRow(self.tr("Accent colour"), self.accent)
        form.addRow(self.tr("Language"), self.language)
        look.layout_.addLayout(form)
        look.add(plain(self.tr("A new language is used the next time BlockAds starts.")))
        layout.addWidget(look)
        self.theme.setCurrentIndex(max(0, self.theme.findData(prefs.get("theme"))))
        self.accent.setCurrentIndex(max(0, self.accent.findData(prefs.get("accent"))))
        self.language.setCurrentIndex(max(0, self.language.findData(prefs.get("language"))))
        self.theme.activated.connect(lambda _i: self._appearance())
        self.accent.activated.connect(lambda _i: self._appearance())
        self.language.activated.connect(lambda _i: prefs.set("language", self.language.currentData()))

        desktop = Card(self.tr("Desktop"))
        self.boxes: dict[str, QCheckBox] = {}
        for key, label in (("tray", self.tr("Show an icon in the system tray")),
                           ("close_to_tray", self.tr("Closing the window keeps BlockAds in the tray")),
                           ("notify_status", self.tr("Notify when protection stops or needs attention")),
                           ("notify_daily_summary", self.tr("Daily summary at 21:00")),
                           ("notify_milestones", self.tr("Notify on blocking milestones")),
                           ("log_live", self.tr("Live query log"))):
            box = QCheckBox(label)
            box.setChecked(prefs.get(key))
            box.toggled.connect(lambda checked, k=key: self._pref(k, checked))
            self.boxes[key] = box
            desktop.add(box)
        updates_row = QHBoxLayout()
        updates_row.addWidget(plain(self.tr("Filter update notifications"), wrap=False))
        self.notify_updates = QComboBox()
        for key, label in UPDATE_STYLES:
            self.notify_updates.addItem(self.tr(label), key)
        self.notify_updates.setCurrentIndex(max(0, self.notify_updates.findData(prefs.get("notify_updates"))))
        self.notify_updates.activated.connect(
            lambda _i: prefs.set("notify_updates", self.notify_updates.currentData()))
        updates_row.addWidget(self.notify_updates)
        updates_row.addStretch(1)
        desktop.layout_.addLayout(updates_row)
        self.autostart = QCheckBox(self.tr("Start BlockAds in the tray when I log in"))
        self.autostart.setChecked(autostart_path().exists())
        self.autostart.toggled.connect(self._autostart)
        desktop.add(self.autostart)
        layout.addWidget(desktop)

        logging = Card(self.tr("Query log"))
        self.log_enabled = QCheckBox(self.tr("Record DNS queries"))
        self.retention = QSpinBox()
        self.retention.setRange(1, 365)
        self.retention.setSuffix(self.tr(" days"))
        row = QHBoxLayout()
        row.addWidget(self.log_enabled)
        row.addStretch(1)
        row.addWidget(plain(self.tr("Keep for"), wrap=False))
        row.addWidget(self.retention)
        save = QPushButton(self.tr("Apply"))
        save.clicked.connect(self._logging)
        row.addWidget(save)
        logging.layout_.addLayout(row)
        logging.add(plain(self.tr("Query names stay on this computer. Changing these asks for the administrator "
                                  "password.")))
        layout.addWidget(logging)

        data = Card(self.tr("Backup"))
        row = QHBoxLayout()
        for label, slot in ((self.tr("Back up…"), self.backup), (self.tr("Restore…"), self.restore),
                            (self.tr("Reset to defaults…"), self.reset)):
            button = QPushButton(label)
            button.clicked.connect(slot)
            row.addWidget(button)
        row.addStretch(1)
        data.layout_.addLayout(row)
        layout.addWidget(data)
        layout.addStretch(1)

    def refresh(self) -> None:
        self.load("GetSettings", then=self.show_settings)

    def show_settings(self, result: dict[str, Any]) -> None:
        logging = result.get("settings", {}).get("logging", {})
        self.log_enabled.setChecked(bool(logging.get("enabled", True)))
        self.retention.setValue(int(logging.get("retention_days", 7)))

    def _appearance(self) -> None:
        self.ctx.prefs.set("theme", self.theme.currentData())
        self.ctx.prefs.set("accent", self.accent.currentData())
        if self.ctx.theme is not None:
            self.ctx.theme.apply(self.theme.currentData(), self.accent.currentData())

    def _pref(self, key: str, value: bool) -> None:
        self.ctx.prefs.set(key, value)

    def _autostart(self, enabled: bool) -> None:
        try:
            set_autostart(enabled)
        except OSError as exc:
            self.ctx.messages.error(self.tr("Cannot change autostart: %1").replace("%1", exc.strerror or str(exc)))

    def _logging(self) -> None:
        self.act("SetLogging", self.log_enabled.isChecked(), self.retention.value(),
                 done=self.tr("Query log settings saved."))

    # --- backup -----------------------------------------------------------------------

    def backup(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, self.tr("Back up settings"), "blockads-backup.json",
                                              self.tr("JSON files (*.json)"))
        if not path:
            return
        parts: dict[str, Any] = {}

        def write() -> None:
            document = backup_document(parts["settings"], parts["rules"])
            try:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    handle.write(json.dumps(document, indent=2) + "\n")
            except OSError as exc:
                self.ctx.messages.error(self.tr("Cannot write the file: %1").replace("%1", exc.strerror or str(exc)))
                return
            self.ctx.messages.info(self.tr("Backup saved."))

        def got(key: str, value: dict[str, Any]) -> None:
            parts[key] = value
            if len(parts) == 2:
                write()

        self.load("GetSettings", then=lambda r: got("settings", r["settings"]))
        self.load("GetRules", then=lambda r: got("rules", r["rules"]))

    def restore(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, self.tr("Restore settings"), "",
                                              self.tr("JSON files (*.json);;All files (*)"))
        if not path:
            return
        try:
            with open(path, "rb") as handle:
                data = handle.read(android_import.MAX_INPUT + 1)
        except OSError as exc:
            self.ctx.messages.error(self.tr("Cannot read the file: %1").replace("%1", exc.strerror or str(exc)))
            return
        try:
            document = json.loads(data)
        except ValueError:
            self.ctx.messages.error(self.tr("This is not a BlockAds backup."))
            return
        if android_import.is_android_backup(document):
            self.import_android(document)
            return
        if len(data) > dbus_api.MAX_JSON:
            self.ctx.messages.error(self.tr("The backup is too large."))
            return
        if not isinstance(document, dict) or not {"settings", "rules"} & set(document):
            self.ctx.messages.error(self.tr("This is not a BlockAds backup."))
            return
        document = {key: document[key] for key in ("settings", "rules") if key in document}
        self.act("ImportBackup", json.dumps(document), done=self.tr("Settings restored."))

    def import_android(self, document: dict[str, Any]) -> None:
        """Merge a BlockAds for Android backup into the current settings and rules."""
        parts: dict[str, Any] = {}

        def send() -> None:
            result = android_import.convert(document, parts["settings"], parts["rules"])
            text = json.dumps(result.backup)
            if len(text.encode()) > dbus_api.MAX_JSON:
                self.ctx.messages.error(self.tr("The backup is too large."))
                return

            def imported(_result: Any) -> None:
                self.apply_prefs(result.prefs)
                self.ctx.messages.info(android_report(result.report))

            self.act("ImportBackup", text, then=imported)

        def got(key: str, value: dict[str, Any]) -> None:
            parts[key] = value
            if len(parts) == 2:
                send()

        self.load("GetSettings", then=lambda r: got("settings", r["settings"]))
        self.load("GetRules", then=lambda r: got("rules", r["rules"]))

    def apply_prefs(self, prefs: dict[str, Any]) -> None:
        for key, value in prefs.items():
            self.ctx.prefs.set(key, value)
            if key in self.boxes:
                self.boxes[key].setChecked(bool(value))
        if "theme" in prefs:
            self.theme.setCurrentIndex(max(0, self.theme.findData(prefs["theme"])))
            if self.ctx.theme is not None:
                self.ctx.theme.apply(prefs["theme"], self.ctx.prefs.get("accent"))
        if "language" in prefs:
            self.language.setCurrentIndex(max(0, self.language.findData(prefs["language"])))

    def reset(self) -> None:
        answer = QMessageBox.question(self, self.tr("Reset settings"), self.tr(
            "Reset every setting to its default? Your blocklist and allowlist are kept."))
        if answer == QMessageBox.StandardButton.Yes:
            self.act("ResetSettings", done=self.tr("Settings reset."))


def android_report(report: dict[str, int]) -> str:
    """One line for the message bar: what an Android import added and skipped (no names)."""
    rules = report.get("rules", 0) + report.get("whitelist", 0)
    lists = report.get("lists", 0) + report.get("custom_lists", 0)
    text = (translate("SettingsPage", "Imported from BlockAds for Android: %1 domain rules, %2 filter lists.")
            .replace("%1", str(rules)).replace("%2", str(lists)))
    if report.get("dns"):
        text += " " + translate("SettingsPage", "DNS server set.")
    if report.get("apps_skipped") or report.get("firewall_skipped"):
        text += " " + translate(
            "SettingsPage", "Per-app settings and firewall rules do not exist on Linux and were skipped.")
    if any(report.get(k) for k in ("rules_skipped", "lists_skipped", "dns_skipped", "disabled_rules_skipped",
                                    "profiles_skipped")):
        text += " " + translate("SettingsPage", "Some entries could not be used and were skipped.")
    return text
