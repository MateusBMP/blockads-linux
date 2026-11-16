"""About: version, licence, upstream credit, list attributions, the network-contact statement."""

from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QLabel, QScrollArea, QVBoxLayout, QWidget

from ... import __version__
from .base import Card, Context, Page, heading, plain

UPSTREAM = "https://github.com/pass-with-high-score/blockads-android"


class AboutPage(Page):
    title = "About"
    icon = "help-about"

    def __init__(self, ctx: Context, parent: QWidget | None = None) -> None:
        super().__init__(ctx, parent)
        self.title = self.tr("About")
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
        layout.addWidget(heading("BlockAds for Linux"))
        layout.addWidget(plain(self.tr("Version %1").replace("%1", __version__)))
        layout.addWidget(plain(self.tr(
            "System-wide DNS filtering of ads, trackers, malware and phishing. A port of BlockAds for "
            "Android to the Linux desktop.")))

        licence = Card(self.tr("Licence"))
        link = QLabel(self.tr('Free software under the GNU General Public License, version 3. Based on '
                              '<a href="%1">blockads-android</a>; the filter catalog, rule syntax and DoH list '
                              'are derived from it.').replace("%1", UPSTREAM))
        link.setTextFormat(Qt.TextFormat.RichText)
        link.setOpenExternalLinks(True)
        link.setWordWrap(True)
        licence.add(link)
        licence.add(plain(self.tr("Every filter list belongs to its authors and keeps its own licence; the "
                                  "Filters page shows where each one comes from.")))
        layout.addWidget(licence)

        privacy = Card(self.tr("What this computer contacts"))
        privacy.add(plain(self.tr(
            "Only the DNS servers you chose and the addresses of the filter lists you enabled. Nothing "
            "else: no telemetry, no accounts, no remote compilation of lists. Your query log and "
            "statistics never leave this computer.")))
        layout.addWidget(privacy)
        layout.addStretch(1)
