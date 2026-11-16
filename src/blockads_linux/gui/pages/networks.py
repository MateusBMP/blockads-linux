"""Networks: trusted networks (NetworkManager connections), the current network, and split DNS.

A trusted network is keyed by its NetworkManager connection UUID and has a
mode: ``pause`` (no filtering while it is the primary connection) or
``network_dns`` (keep filtering, but ask that network's DNS first). The
daemon acts on it (``GetStatus.protection.trusted_network``); this page edits
the list with ``SetTrustedNetworks`` (a weakening action: the admin password).

Names come from the network (SSIDs): they are shown as plain text only.
"""

from __future__ import annotations

import json
from typing import Any

from PyQt6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QPushButton,
    QScrollArea,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from .. import format as fmt
from ..format import QT_TRANSLATE_NOOP
from .base import Card, Context, Page, heading, plain

MODES = (("pause", QT_TRANSLATE_NOOP("NetworksPage", "Pause filtering")),
         ("network_dns", QT_TRANSLATE_NOOP("NetworksPage", "Keep filtering, use the network's DNS")))
WIRELESS = "802-11-wireless"
TYPES = {WIRELESS: QT_TRANSLATE_NOOP("NetworksPage", "Wi-Fi"),
         "802-3-ethernet": QT_TRANSLATE_NOOP("NetworksPage", "Wired"),
         "gsm": QT_TRANSLATE_NOOP("NetworksPage", "Mobile broadband"),
         "vpn": QT_TRANSLATE_NOOP("NetworksPage", "VPN"),
         "wireguard": QT_TRANSLATE_NOOP("NetworksPage", "WireGuard")}


class NetworksPage(Page):
    title = "Networks"
    icon = "network-wireless"

    def __init__(self, ctx: Context, parent: QWidget | None = None) -> None:
        super().__init__(ctx, parent)
        self.title = self.tr("Networks")
        self.networks: list[dict[str, Any]] = []
        self.network: dict[str, Any] = {}
        self.read_only = False
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
        layout.addWidget(heading(self.tr("Networks")))

        current = Card(self.tr("Current network"))
        self.current_label = current.add(plain())
        self.current_label.setObjectName("current_network")
        self.current_state = current.add(plain())
        row = QHBoxLayout()
        self.mode = QComboBox()
        for key, label in MODES:
            self.mode.addItem(self.tr(label), key)
        self.trust_button = QPushButton(self.tr("Trust this network"))
        self.trust_button.setObjectName("trust_current")
        self.trust_button.clicked.connect(self.trust_current)
        row.addWidget(self.mode)
        row.addWidget(self.trust_button)
        row.addStretch(1)
        current.layout_.addLayout(row)
        self.evil_twin = current.add(plain(self.tr(
            "NetworkManager recognizes a Wi-Fi network by its name. Another network with the same name "
            "(an \"evil twin\") would be trusted too: trust only networks you control, and prefer \"Keep "
            "filtering\" for public ones.")))
        self.evil_twin.setObjectName("evil_twin_warning")
        layout.addWidget(current)

        trusted = Card(self.tr("Trusted networks"))
        self.table = QTableWidget(0, 3)
        self.table.setObjectName("trusted_table")
        self.table.setHorizontalHeaderLabels([self.tr("Name"), self.tr("When connected"), ""])
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table.setMinimumHeight(140)
        trusted.add(self.table)
        self.empty = trusted.add(plain(self.tr("No trusted networks. Filtering applies on every network.")))
        trusted.add(plain(self.tr(
            "Changes ask for the administrator password. While a VPN is the primary connection, trust "
            "follows the VPN's connection, not the network under it.")))
        layout.addWidget(trusted)

        split = Card(self.tr("Split DNS"))
        split.add(plain(self.tr(
            "Domains your networks and VPNs announce are always sent to their own DNS servers, so "
            "internal names never leak to the public resolver. A VPN's DNS for everything else is set "
            "on the DNS page.")))
        self.routes = QTableWidget(0, 3)
        self.routes.setObjectName("split_dns_table")
        self.routes.setHorizontalHeaderLabels([self.tr("Domain"), self.tr("Interface"), self.tr("DNS servers")])
        self.routes.verticalHeader().setVisible(False)
        self.routes.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.routes.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.routes.setMinimumHeight(120)
        split.add(self.routes)
        self.no_routes = split.add(plain(self.tr("No network announces its own domains.")))
        layout.addWidget(split)
        layout.addStretch(1)

        ctx.status.updated.connect(self.show_status)
        ctx.status.unavailable.connect(self.show_unavailable)

    # --- data ------------------------------------------------------------------------

    def refresh(self) -> None:
        self.load("GetSettings", then=self.show_settings)
        if self.ctx.status.status is not None:
            self.show_status(self.ctx.status.status)

    def show_settings(self, result: dict[str, Any]) -> None:
        self.networks = [dict(n) for n in result.get("settings", {}).get("trusted_networks", [])]
        self.read_only = bool(result.get("read_only"))
        self._fill_table()
        self._update_current()

    def show_status(self, status: dict[str, Any]) -> None:
        self.network = status.get("network") or {}
        self._update_current()
        routes = self.network.get("split_dns") or []
        self.routes.setRowCount(len(routes))
        for row, route in enumerate(routes):
            interface = fmt.safe(route.get("interface", ""), 40)
            if route.get("vpn"):
                interface += " (" + self.tr("VPN") + ")"
            for column, text in enumerate((fmt.safe(route.get("domain", ""), 253), interface,
                                           ", ".join(fmt.safe(s, 60) for s in route.get("servers", [])))):
                self.routes.setItem(row, column, QTableWidgetItem(text))
        self.routes.setVisible(bool(routes))
        self.no_routes.setVisible(not routes)

    def show_unavailable(self, _error: object) -> None:
        self.network = {}
        self._update_current()

    def _update_current(self) -> None:
        uuid = self.network.get("uuid", "")
        if not uuid:
            self.current_label.setText(self.tr("No NetworkManager connection is active."))
            self.current_state.setText("")
            self.trust_button.setEnabled(False)
            self.mode.setEnabled(False)
            self.evil_twin.setVisible(False)
            return
        kind = TYPES.get(self.network.get("type", ""))
        name = fmt.safe(self.network.get("name") or uuid, 100)
        self.current_label.setText(f"{name} ({self.tr(kind)})" if kind else name)
        entry = next((n for n in self.networks if n["uuid"] == uuid), None)
        if entry is None:
            self.current_state.setText(self.tr("Not trusted: filtered with your DNS settings."))
            self.trust_button.setText(self.tr("Trust this network"))
        else:
            self.current_state.setText(self.tr("Trusted: %1").replace("%1", self.tr(dict(MODES)[entry["mode"]])))
            self.trust_button.setText(self.tr("Change mode"))
            self.mode.setCurrentIndex(max(0, self.mode.findData(entry["mode"])))
        self.trust_button.setEnabled(not self.read_only)
        self.mode.setEnabled(not self.read_only)
        self.evil_twin.setVisible(self.network.get("type") == WIRELESS)

    def _fill_table(self) -> None:
        self._filling = True
        self.table.setRowCount(len(self.networks))
        for row, network in enumerate(self.networks):
            item = QTableWidgetItem(fmt.safe(network.get("name") or network["uuid"], 100))
            item.setToolTip(network["uuid"])
            self.table.setItem(row, 0, item)
            combo = QComboBox()
            for key, label in MODES:
                combo.addItem(self.tr(label), key)
            combo.setCurrentIndex(max(0, combo.findData(network["mode"])))
            combo.setEnabled(not self.read_only)
            combo.currentIndexChanged.connect(lambda _i, uuid=network["uuid"], box=combo: self.set_mode(uuid, box))
            self.table.setCellWidget(row, 1, combo)
            remove = QPushButton(self.tr("Remove"))
            remove.setEnabled(not self.read_only)
            remove.clicked.connect(lambda _c, uuid=network["uuid"]: self.remove(uuid))
            self.table.setCellWidget(row, 2, remove)
        self.table.setVisible(bool(self.networks))
        self.empty.setVisible(not self.networks)
        self._filling = False

    # --- actions ---------------------------------------------------------------------

    def save(self, networks: list[dict[str, Any]], done: str) -> None:
        document = {"networks": [{"uuid": n["uuid"], "name": n.get("name", ""), "mode": n["mode"]}
                                 for n in networks]}
        self.act("SetTrustedNetworks", json.dumps(document), done=done)

    def trust_current(self) -> None:
        uuid = self.network.get("uuid", "")
        if not uuid:
            return
        entry = {"uuid": uuid, "name": str(self.network.get("name", ""))[:200], "mode": self.mode.currentData()}
        networks = [n for n in self.networks if n["uuid"] != uuid] + [entry]
        self.save(networks, self.tr("Trusted networks saved."))

    def set_mode(self, uuid: str, box: QComboBox) -> None:
        if self._filling:
            return
        networks = [{**n, "mode": box.currentData()} if n["uuid"] == uuid else n for n in self.networks]
        self.save(networks, self.tr("Trusted networks saved."))

    def remove(self, uuid: str) -> None:
        self.save([n for n in self.networks if n["uuid"] != uuid], self.tr("Network removed."))

