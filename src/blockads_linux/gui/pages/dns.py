"""DNS: provider preset or custom servers (URL or sdns:// stamp), fallback, encrypted-only,
block response and TTL, SafeSearch/YouTube, DoH bypass list, CNAME check, VPN DNS.

Validation of custom servers is the daemon's (``SetUpstream`` builds the
configuration and refuses what it cannot use); the GUI only splits lines.
"""

from __future__ import annotations

import json
from typing import Any

from PyQt6.QtWidgets import (
    QButtonGroup,
    QCheckBox,
    QComboBox,
    QFormLayout,
    QHBoxLayout,
    QPlainTextEdit,
    QPushButton,
    QRadioButton,
    QScrollArea,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from .base import Card, Context, Page, heading, plain
from ..format import QT_TRANSLATE_NOOP

# Mirrors daemon/upstream/presets.py PRESETS (kept in sync by a unit test); the GUI
# does not import the transports.
PRESETS = (
    ("quad9", "Quad9"),
    ("adguard", "AdGuard DNS"),
    ("cloudflare", "Cloudflare DNS"),
    ("cloudflare_family", "Cloudflare Family"),
    ("google", "Google DNS"),
    ("opendns", "OpenDNS"),
    ("opendns_family", "OpenDNS FamilyShield"),
    ("dnsbunker", "DNSBunker"),
)
BLOCK_MODES = (("null_ip", QT_TRANSLATE_NOOP("DnsPage", "0.0.0.0 / :: (recommended)")), ("nxdomain", QT_TRANSLATE_NOOP("DnsPage", "NXDOMAIN (no such domain)")),
               ("refused", QT_TRANSLATE_NOOP("DnsPage", "REFUSED")))
FEATURE_BOXES = (
    ("safesearch", QT_TRANSLATE_NOOP("DnsPage", "SafeSearch (Google, Bing)")),
    ("youtube_restricted", QT_TRANSLATE_NOOP("DnsPage", "YouTube Restricted mode")),
    ("doh_blocklist", QT_TRANSLATE_NOOP("DnsPage", "Block known DNS-over-HTTPS servers (stops browsers bypassing the filter)")),
    ("cname_check", QT_TRANSLATE_NOOP("DnsPage", "Block CNAME cloaking (trackers hidden behind first-party names)")),
)


def upstream_choice(dns: dict[str, Any]) -> tuple[str, list[str]]:
    """Settings -> ("system" | preset id | "custom", custom lines)."""
    upstream = list(dns.get("upstream") or ["quad9"])
    if upstream == ["system"]:
        return "system", []
    if len(upstream) == 1 and upstream[0] in dict(PRESETS):
        return upstream[0], []
    return "custom", upstream


class DnsPage(Page):
    title = "DNS"
    icon = "network-server"

    def __init__(self, ctx: Context, parent: QWidget | None = None) -> None:
        super().__init__(ctx, parent)
        self.title = self.tr("DNS")
        self.dns: dict[str, Any] = {}
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
        layout.addWidget(heading(self.tr("DNS")))

        server = Card(self.tr("DNS server"))
        self.choices = QButtonGroup(self)
        self.radios: dict[str, QRadioButton] = {}
        options = [("system", self.tr("Network's DNS (from your router or VPN; not encrypted)"))]
        options += [(key, f"{name} " + self.tr("(encrypted, DNS over HTTPS)")) for key, name in PRESETS]
        options += [("custom", self.tr("Custom servers"))]
        for key, label in options:
            radio = QRadioButton(label)
            radio.setObjectName(f"upstream_{key}")
            self.radios[key] = radio
            self.choices.addButton(radio)
            server.add(radio)
        self.custom = QPlainTextEdit()
        self.custom.setPlaceholderText(self.tr(
            "One per line: sdns://… stamp, https://IP/dns-query#name, tls://IP#name, udp://IP"))
        self.custom.setMaximumHeight(90)
        server.add(self.custom)
        self.encrypted_only = QCheckBox(self.tr("Encrypted only: never fall back to plain DNS"))
        self.vpn_dns = QCheckBox(self.tr("Use a VPN's own DNS for its domains"))
        server.add(self.encrypted_only)
        server.add(self.vpn_dns)
        apply_row = QHBoxLayout()
        apply_row.addStretch(1)
        self.apply_button = QPushButton(self.tr("Apply"))
        self.apply_button.clicked.connect(self.apply_upstream)
        apply_row.addWidget(self.apply_button)
        server.layout_.addLayout(apply_row)
        server.add(plain(self.tr("Changing the DNS server or allowing plain DNS asks for the administrator "
                                 "password.")))
        layout.addWidget(server)

        blocking = Card(self.tr("Blocked answers"))
        form = QFormLayout()
        self.block_mode = QComboBox()
        for key, label in BLOCK_MODES:
            self.block_mode.addItem(self.tr(label), key)
        self.block_ttl = QSpinBox()
        self.block_ttl.setRange(0, 86400)
        self.block_ttl.setSuffix(" s")
        form.addRow(self.tr("Response"), self.block_mode)
        form.addRow(self.tr("Time to live"), self.block_ttl)
        blocking.layout_.addLayout(form)
        response_row = QHBoxLayout()
        response_row.addStretch(1)
        response_apply = QPushButton(self.tr("Apply"))
        response_apply.clicked.connect(self.apply_response)
        response_row.addWidget(response_apply)
        blocking.layout_.addLayout(response_row)
        layout.addWidget(blocking)

        features = Card(self.tr("Protection"))
        self.features: dict[str, QCheckBox] = {}
        for key, label in FEATURE_BOXES:
            box = QCheckBox(self.tr(label))
            box.setObjectName(f"feature_{key}")
            box.clicked.connect(lambda checked, k=key: self.set_feature(k, checked))
            self.features[key] = box
            features.add(box)
        features.add(plain(self.tr("Turning a protection on needs no password; turning it off does.")))
        layout.addWidget(features)
        layout.addStretch(1)

    def refresh(self) -> None:
        self.load("GetSettings", then=self.show_settings)

    def show_settings(self, result: dict[str, Any]) -> None:
        dns = result.get("settings", {}).get("dns", {})
        self.dns = dns
        self._filling = True
        choice, lines = upstream_choice(dns)
        self.radios[choice].setChecked(True)
        self.custom.setPlainText("\n".join(lines))
        self.encrypted_only.setChecked(bool(dns.get("encrypted_only")))
        self.vpn_dns.setChecked(bool(dns.get("vpn_dns", True)))
        index = self.block_mode.findData(dns.get("block_mode", "null_ip"))
        self.block_mode.setCurrentIndex(max(0, index))
        self.block_ttl.setValue(int(dns.get("block_ttl", 10)))
        for key, box in self.features.items():
            box.setChecked(bool(dns.get(key)))
        read_only = bool(result.get("read_only"))
        for widget in (self.apply_button, *self.features.values()):
            widget.setEnabled(not read_only)
        self._filling = False

    def selected_upstream(self) -> list[str]:
        for key, radio in self.radios.items():
            if radio.isChecked():
                if key == "custom":
                    return [line.strip() for line in self.custom.toPlainText().splitlines() if line.strip()][:8]
                return [key]
        return ["quad9"]

    def apply_upstream(self) -> None:
        upstream = self.selected_upstream()
        if not upstream:
            self.ctx.messages.error(self.tr("Enter at least one custom server."))
            return
        document = {"upstream": upstream, "encrypted_only": self.encrypted_only.isChecked(),
                    "vpn_dns": self.vpn_dns.isChecked()}
        self.act("SetUpstream", json.dumps(document), done=self.tr("DNS server saved."))

    def apply_response(self) -> None:
        self.act("SetBlockedResponse", self.block_mode.currentData(), self.block_ttl.value(),
                 done=self.tr("Blocked-answer settings saved."))

    def set_feature(self, key: str, enabled: bool) -> None:
        if self._filling:
            return
        self.act("EnableFeature" if enabled else "DisableFeature", key,
                 done=self.tr("Saved."))
