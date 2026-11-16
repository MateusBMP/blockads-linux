"""Onboarding: explanation, service check and start, DNS choice, filter preset,
tray and autostart, self-test. Shown once (``prefs.onboarded``); changes are applied
as the user leaves each page, so cancelling half-way keeps what was already chosen.
"""

from __future__ import annotations

import json
from typing import Any

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QButtonGroup,
    QCheckBox,
    QLabel,
    QPushButton,
    QRadioButton,
    QVBoxLayout,
    QWizard,
    QWizardPage,
)

from .dbus_client import CallError
from .format import QT_TRANSLATE_NOOP
from .pages.base import Context, error_text, plain
from .pages.dns import PRESETS
from .pages.settings import autostart_path, set_autostart
from .selftest import SelfTest

#: Optional additions on the filter page: (label, catalog ids). Ids not in the catalog are skipped.
EXTRA_LISTS = (
    (QT_TRANSLATE_NOOP("FiltersChoicePage", "Social media trackers and widgets"), ("adg_adguard_social_media_filter",)),
    (QT_TRANSLATE_NOOP("FiltersChoicePage", "Annoyances: cookie banners and pop-ups"), ("adg_adguard_cookie_notices_filter", "adg_adguard_popups_filter")),
)


class IntroPage(QWizardPage):
    def __init__(self) -> None:
        super().__init__()
        self.setTitle(self.tr("Welcome to BlockAds"))
        layout = QVBoxLayout(self)
        layout.addWidget(plain(self.tr(
            "BlockAds filters the DNS of this whole computer: ads, trackers, malware and phishing sites are "
            "blocked for every application and user.\n\n"
            "A small service runs in the background with no special rights; a separate helper redirects "
            "DNS to it with firewall rules and removes them whenever the service stops, so your internet "
            "keeps working.\n\n"
            "Turning protection on never needs a password. Turning it off or allowing a domain asks for the "
            "administrator password.")))


class ServicePage(QWizardPage):
    def __init__(self, ctx: Context, systemd) -> None:
        super().__init__()
        self.ctx = ctx
        self.systemd = systemd
        self.setTitle(self.tr("The filter service"))
        layout = QVBoxLayout(self)
        self.label = plain()
        layout.addWidget(self.label)
        self.start_button = QPushButton(self.tr("Start the service"))
        self.start_button.clicked.connect(self.start)
        layout.addWidget(self.start_button)
        layout.addStretch(1)
        ctx.status.updated.connect(self._update)
        ctx.status.unavailable.connect(self._update)

    def initializePage(self) -> None:  # noqa: N802
        self._update()
        self.ctx.status.refresh()

    def _update(self, *_signal_args: object) -> None:
        running = self.ctx.status.status is not None
        self.label.setText(self.tr("The service is running.") if running else self.tr(
            "The service is not running yet. Start it to turn protection on."))
        self.start_button.setVisible(not running)
        self.start_button.setEnabled(self.systemd is not None and self.systemd.enabled)
        self.completeChanged.emit()

    def isComplete(self) -> bool:  # noqa: N802
        return self.ctx.status.status is not None

    def start(self) -> None:
        self.start_button.setEnabled(False)

        def failed(error: CallError) -> None:
            self.label.setText(self.tr("Could not start the service: %1").replace("%1", error.message))
            self.start_button.setEnabled(True)

        self.systemd.start("blockadsd.service").then(lambda _job: self.ctx.status.refresh(), failed)


class DnsChoicePage(QWizardPage):
    def __init__(self, ctx: Context) -> None:
        super().__init__()
        self.ctx = ctx
        self.setTitle(self.tr("DNS server"))
        self.setSubTitle(self.tr("Where allowed queries are answered. Quad9 is encrypted and blocks known "
                                 "malware domains."))
        layout = QVBoxLayout(self)
        self.group = QButtonGroup(self)
        self.radios: dict[str, QRadioButton] = {}
        for key, name in (*PRESETS, ("system", self.tr("Your network's DNS (not encrypted)"))):
            radio = QRadioButton(name)
            self.group.addButton(radio)
            self.radios[key] = radio
            layout.addWidget(radio)
        layout.addWidget(plain(self.tr("Changing it from the recommended choice asks for the administrator "
                                       "password.")))
        self.current: list[str] = ["quad9"]
        self.radios["quad9"].setChecked(True)

    def initializePage(self) -> None:  # noqa: N802
        def show(result: dict[str, Any]) -> None:
            upstream = list(result.get("settings", {}).get("dns", {}).get("upstream") or ["quad9"])
            self.current = upstream
            if len(upstream) == 1 and upstream[0] in self.radios:
                self.radios[upstream[0]].setChecked(True)

        self.ctx.client.call("GetSettings").then(show, lambda _e: None)

    def chosen(self) -> str:
        return next((key for key, radio in self.radios.items() if radio.isChecked()), "quad9")

    def validatePage(self) -> bool:  # noqa: N802
        choice = self.chosen()
        if [choice] != self.current:
            self.ctx.client.call("SetUpstream", json.dumps({"upstream": [choice]})).then(
                lambda _r: self.ctx.messages.info(self.tr("DNS server saved.")),
                lambda error: self.ctx.messages.error(error_text(error)))
        return True


class FiltersChoicePage(QWizardPage):
    def __init__(self, ctx: Context) -> None:
        super().__init__()
        self.ctx = ctx
        self.setTitle(self.tr("Filter lists"))
        layout = QVBoxLayout(self)
        layout.addWidget(plain(self.tr(
            "The recommended lists block ads, trackers, malware and phishing with very few false positives:\n"
            "StevenBlack Unified, EasyPrivacy, URLhaus/Online Malicious URL Blocklist, Phishing URL Blocklist, "
            "Dandelion Sprout's Anti-Malware List and uBlock Origin Badware risks.")))
        self.extras: list[tuple[QCheckBox, tuple[str, ...]]] = []
        for label, ids in EXTRA_LISTS:
            box = QCheckBox(self.tr(label))
            layout.addWidget(box)
            self.extras.append((box, ids))
        layout.addWidget(plain(self.tr("You can enable any of the 100 lists later on the Filters page.")))
        layout.addStretch(1)
        self.catalog_ids: set[str] = set()

    def initializePage(self) -> None:  # noqa: N802
        def show(catalog: dict[str, Any]) -> None:
            self.catalog_ids = {entry["id"] for entry in catalog.get("lists", [])}
            for box, ids in self.extras:
                box.setVisible(any(i in self.catalog_ids for i in ids))

        self.ctx.client.call("GetFilterCatalog").then(show, lambda _e: None)

    def validatePage(self) -> bool:  # noqa: N802
        ids = [i for box, group in self.extras if box.isChecked() for i in group if i in self.catalog_ids]
        if ids:
            self.ctx.client.call("EnableFilters", ids).then(
                lambda _r: self.ctx.messages.info(self.tr("Lists enabled; they download in the background.")),
                lambda error: self.ctx.messages.error(error_text(error)))
        return True


class DesktopPage(QWizardPage):
    def __init__(self, ctx: Context) -> None:
        super().__init__()
        self.ctx = ctx
        self.setTitle(self.tr("Desktop"))
        layout = QVBoxLayout(self)
        self.tray = QCheckBox(self.tr("Show an icon in the system tray"))
        self.tray.setChecked(ctx.prefs.get("tray"))
        self.autostart = QCheckBox(self.tr("Start BlockAds in the tray when I log in"))
        self.autostart.setChecked(True)
        layout.addWidget(self.tray)
        layout.addWidget(self.autostart)
        layout.addWidget(plain(self.tr("Filtering itself does not depend on this window: it starts with the "
                                       "computer.")))
        layout.addStretch(1)

    def validatePage(self) -> bool:  # noqa: N802
        self.ctx.prefs.set("tray", self.tray.isChecked())
        try:
            if self.autostart.isChecked() != autostart_path().exists():
                set_autostart(self.autostart.isChecked())
        except OSError as exc:
            self.ctx.messages.error(str(exc))
        return True


class TestPage(QWizardPage):
    def __init__(self, ctx: Context) -> None:
        super().__init__()
        self.setTitle(self.tr("Test"))
        layout = QVBoxLayout(self)
        layout.addWidget(plain(self.tr("Check that applications on this computer get filtered answers.")))
        self.button = QPushButton(self.tr("Run the test"))
        layout.addWidget(self.button)
        self.result = QLabel()
        self.result.setWordWrap(True)
        self.result.setTextFormat(Qt.TextFormat.PlainText)
        layout.addWidget(self.result)
        layout.addStretch(1)
        self.test = SelfTest(ctx.client, parent=self)
        self.button.clicked.connect(self.run)
        self.test.finished.connect(self.show_result)

    def run(self) -> None:
        self.button.setEnabled(False)
        self.result.setText(self.tr("Testing…"))
        self.test.start()

    def show_result(self, ok: bool, text: str) -> None:
        self.button.setEnabled(True)
        self.result.setText(("✔ " if ok else "✘ ") + text)


class OnboardingWizard(QWizard):
    def __init__(self, ctx: Context, systemd=None, parent=None) -> None:
        super().__init__(parent)
        self.ctx = ctx
        self.setWindowTitle(self.tr("Set up BlockAds"))
        self.setWizardStyle(QWizard.WizardStyle.ModernStyle)
        self.service_page = ServicePage(ctx, systemd)
        self.dns_page = DnsChoicePage(ctx)
        self.filters_page = FiltersChoicePage(ctx)
        self.desktop_page = DesktopPage(ctx)
        self.test_page = TestPage(ctx)
        for page in (IntroPage(), self.service_page, self.dns_page, self.filters_page, self.desktop_page,
                     self.test_page):
            self.addPage(page)
        self.finished.connect(self._done)

    def _done(self, _result: int) -> None:
        self.ctx.prefs.set("onboarded", True)
