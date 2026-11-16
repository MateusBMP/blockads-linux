"""Home: shield, main toggle and pause menu, today's totals, 24 h chart, recent/top blocked, health."""

from __future__ import annotations

import time
from typing import Any

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QAction, QColor
from PyQt6.QtWidgets import (
    QApplication,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMenu,
    QPushButton,
    QScrollArea,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from .. import format as fmt
from .. import theme
from ..dbus_client import CallError
from ..netspeed import SpeedMeter
from ..status import overall_state
from ..widgets.charts import BarChart
from .base import Card, Context, Page, error_text, heading, plain
from ..format import QT_TRANSLATE_NOOP

PAUSE_CHOICES = ((15 * 60, QT_TRANSLATE_NOOP("HomePage", "15 minutes")), (3600, QT_TRANSLATE_NOOP("HomePage", "1 hour")), (8 * 3600, QT_TRANSLATE_NOOP("HomePage", "8 hours")), (0, QT_TRANSLATE_NOOP("HomePage", "Until resumed")))
LOG_HORIZON = 2**62  # "before the newest": GetQueryLog's before_id for the latest entries


def pause_menu(parent: QWidget, pause) -> QMenu:
    menu = QMenu(parent)
    for seconds, label in PAUSE_CHOICES:
        action = QAction(parent.tr(label), menu)
        action.triggered.connect(lambda _checked=False, s=seconds: pause(s))
        menu.addAction(action)
    return menu


class HomePage(Page):
    title = "Home"
    icon = "go-home"

    def __init__(self, ctx: Context, systemd=None, parent: QWidget | None = None) -> None:
        super().__init__(ctx, parent)
        self.title = self.tr("Home")
        self.systemd = systemd
        self.speed = SpeedMeter()
        self.status: dict[str, Any] | None = None

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
        layout.setSpacing(12)

        # shield + toggle
        shield = Card()
        row = QHBoxLayout()
        self.dot = QLabel()
        self.dot.setFixedSize(18, 18)
        self.state_label = heading("")
        self.state_detail = plain()
        texts = QVBoxLayout()
        texts.addWidget(self.state_label)
        texts.addWidget(self.state_detail)
        row.addWidget(self.dot, 0, Qt.AlignmentFlag.AlignTop)
        row.addLayout(texts, 1)
        self.toggle = QPushButton()
        self.toggle.setObjectName("mainToggle")
        self.toggle.setMinimumWidth(140)
        self.toggle.clicked.connect(self._toggle)
        self.pause_button = QToolButton()
        self.pause_button.setText(self.tr("Pause for…"))
        self.pause_button.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        self.pause_button.setMenu(pause_menu(self, self.pause))
        row.addWidget(self.toggle)
        row.addWidget(self.pause_button)
        shield.layout_.addLayout(row)
        layout.addWidget(shield)

        # totals
        totals = Card(self.tr("Today"))
        grid = QGridLayout()
        self.totals: dict[str, QLabel] = {}
        for column, (key, label) in enumerate((("total", self.tr("Queries")), ("blocked", self.tr("Blocked")),
                                               ("rate", self.tr("Block rate")), ("saved", self.tr("Data saved")),
                                               ("uptime", self.tr("Uptime")), ("speed", self.tr("Network")))):
            value = heading("–")
            value.setObjectName(f"total_{key}")
            grid.addWidget(value, 0, column)
            grid.addWidget(plain(label), 1, column)
            self.totals[key] = value
        totals.layout_.addLayout(grid)
        layout.addWidget(totals)

        chart_card = Card(self.tr("Last 24 hours"))
        self.chart = BarChart()
        chart_card.add(self.chart)
        layout.addWidget(chart_card)

        lists = QHBoxLayout()
        recent_card = Card(self.tr("Recently blocked"))
        self.recent = QListWidget()
        self.recent.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.recent.customContextMenuRequested.connect(lambda pos: self._domain_menu(self.recent, pos))
        recent_card.add(self.recent)
        top_card = Card(self.tr("Top blocked today"))
        self.top = QListWidget()
        self.top.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.top.customContextMenuRequested.connect(lambda pos: self._domain_menu(self.top, pos))
        top_card.add(self.top)
        lists.addWidget(recent_card)
        lists.addWidget(top_card)
        layout.addLayout(lists)

        health = Card(self.tr("Health"))
        self.health = plain()
        self.health.setObjectName("health")
        health.add(self.health)
        layout.addWidget(health)
        layout.addStretch(1)

        self.timer = QTimer(self)
        self.timer.setInterval(2000)
        self.timer.timeout.connect(self._tick)
        ctx.status.updated.connect(self.show_status)
        ctx.status.unavailable.connect(self.show_unavailable)
        self.show_unavailable(None)

    # --- lifecycle --------------------------------------------------------------

    def activate(self) -> None:
        super().activate()
        self.timer.start()
        self.speed.sample()

    def deactivate(self) -> None:
        super().deactivate()
        self.timer.stop()

    def refresh(self) -> None:
        if self.status is None:
            return
        self.load("GetStatistics", "24h", then=self._statistics)
        self.load("GetQueryLog", '{"verdict":"blocked","before_id":%d}' % LOG_HORIZON, 0, 10, then=self._recent,
                  failed=lambda _e: self.recent.clear())
        self.load("GetTopDomains", 1, True, 10, then=self._top, failed=lambda _e: self.top.clear())

    def _tick(self) -> None:
        down, up = self.speed.sample()
        self.totals["speed"].setText(f"↓{fmt.size(down)}/s ↑{fmt.size(up)}/s")
        if self.active and self.status is not None and self.ctx.status.timer.interval():
            self._ticks = getattr(self, "_ticks", 0) + 1
            if self._ticks % 5 == 0:  # lists and chart every 10 s; the status itself polls every 2 s
                self.refresh()

    # --- status -------------------------------------------------------------------

    def show_unavailable(self, error: CallError | None) -> None:
        first = self.status is not None
        self.status = None
        self._paint_dot("off")
        self.state_label.setText(self.tr("Not running"))
        self.state_detail.setText(error_text(error) if error and error.kind != "not_running"
                                  else self.tr("The filter service is stopped: DNS is not filtered."))
        self.toggle.setText(self.tr("Start"))
        self.toggle.setEnabled(self.systemd is not None and self.systemd.enabled)
        self.pause_button.setEnabled(False)
        for key in ("total", "blocked", "rate", "saved", "uptime"):
            self.totals[key].setText("–")
        self.health.setText("")
        if first:
            self.recent.clear()
            self.top.clear()

    def show_status(self, status: dict[str, Any]) -> None:
        first = self.status is None
        self.status = status
        state = overall_state(status, True)
        self._paint_dot(state)
        protection = status["protection"]["state"]
        if protection in ("paused", "trusted"):
            self.state_label.setText(self.tr("Paused"))
            self.state_detail.setText(fmt.pause_text(status) + " — " + self.tr("DNS is not filtered."))
            # On a trusted network, Resume would change nothing: that is the Networks page's.
            self.toggle.setText(self.tr("Resume") if protection == "paused" else self.tr("Pause"))
        else:
            self.state_label.setText(self.tr("Protected") if state == "active" else self.tr("Needs attention"))
            filters = status["filters"]
            self.state_detail.setText(self.tr("%1 rules from %2 lists").replace(
                "%1", fmt.number(filters["rules"])).replace("%2", str(filters["lists"])))
            self.toggle.setText(self.tr("Pause"))
        self.toggle.setEnabled(True)
        self.pause_button.setEnabled(True)
        today = status.get("today") or {}
        total, blocked = int(today.get("total", 0)), int(today.get("blocked", 0))
        self.totals["total"].setText(fmt.number(total))
        self.totals["blocked"].setText(fmt.number(blocked))
        self.totals["rate"].setText(fmt.percent(blocked, total))
        self.totals["saved"].setText(fmt.data_saved(blocked))
        self.totals["uptime"].setText(fmt.duration(status.get("uptime_s", 0)))
        self.health.setText(health_text(status))
        if first and self.active:
            self.refresh()

    def _paint_dot(self, state: str) -> None:
        color = QColor(theme.STATUS[state])
        self.dot.setStyleSheet(f"background: {color.name()}; border-radius: 9px;")
        self.dot.setToolTip(state)

    # --- actions --------------------------------------------------------------------

    def _toggle(self) -> None:
        if self.status is None:
            self.start_service()
        elif self.status["protection"]["state"] == "paused":
            self.act("Resume", done=self.tr("Protection resumed."))
        else:
            self.pause(0)

    def pause(self, seconds: int) -> None:
        self.act("Pause", seconds, done=self.tr("Protection paused."))

    def start_service(self) -> None:
        if self.systemd is None or not self.systemd.enabled:
            return
        self.toggle.setEnabled(False)

        def failed(error: CallError) -> None:
            self.toggle.setEnabled(True)
            self.ctx.messages.error(self.tr("Could not start the service: %1").replace("%1", error.message))

        self.systemd.start("blockadsd.service").then(lambda _job: self.ctx.status.refresh(), failed)

    def _domain_menu(self, widget: QListWidget, pos) -> None:
        item = widget.itemAt(pos)
        if item is None:
            return
        domain = item.data(Qt.ItemDataRole.UserRole)
        menu = QMenu(self)
        menu.addAction(self.tr("Allow this domain"), lambda: self.act(
            "AddAllowRule", domain, done=self.tr("Added to the allowlist.")))
        menu.addAction(self.tr("Copy"), lambda: QApplication.clipboard().setText(domain))
        menu.exec(widget.mapToGlobal(pos))

    # --- data -------------------------------------------------------------------------

    def _statistics(self, stats: dict[str, Any]) -> None:
        self.chart.set_data(series_buckets(stats))

    def _recent(self, result: dict[str, Any]) -> None:
        self.recent.clear()
        for entry in result.get("entries", []):
            item = QListWidgetItem(f"{fmt.clock_ms(entry['time_ms'])}  {fmt.safe(entry['name'], 120)}")
            item.setData(Qt.ItemDataRole.UserRole, entry["name"])
            item.setToolTip(fmt.reason(entry.get("reason", "")))
            self.recent.addItem(item)

    def _top(self, result: dict[str, Any]) -> None:
        self.top.clear()
        for entry in result.get("domains", []):
            item = QListWidgetItem(f"{fmt.number(entry['count']):>8}  {fmt.safe(entry['name'], 120)}")
            item.setData(Qt.ItemDataRole.UserRole, entry["name"])
            self.top.addItem(item)


def series_buckets(stats: dict[str, Any]) -> list[tuple[str, int, int]]:
    period = stats.get("period", "24h")
    out = []
    for bucket in stats.get("series", []):
        out.append((bucket_label(period, bucket.get("bucket")), int(bucket.get("total", 0)),
                    int(bucket.get("blocked", 0))))
    return out


def bucket_label(period: str, key: Any) -> str:
    """Series keys: hour numbers (24h), local day numbers (7d/4w), month numbers (12m)."""
    try:
        key = int(key)
    except (TypeError, ValueError):
        return fmt.safe(key, 12)
    if period == "24h":
        return time.strftime("%H", time.localtime(key * 3600))
    if period in ("7d", "4w"):
        return time.strftime("%d/%m", time.gmtime(key * 86400))
    year, month = divmod(key, 12)
    return f"{month + 1:02d}/{year % 100:02d}"


DOH_RECENT_S = 24 * 3600


def bypass_warnings(status: dict[str, Any], now: float | None = None) -> list[str]:
    """Ways applications may be skipping the filter."""
    bypass = status.get("bypass") or {}
    lines = []
    if bypass.get("resolved_dot") == "yes":
        lines.append(fmt.translate("HomePage", "systemd-resolved sends DNS over TLS (DNSOverTLS=yes): what it "
                                               "resolves bypasses the filter. Set DNSOverTLS=no or opportunistic in "
                                               "/etc/systemd/resolved.conf."))
    last = int(bypass.get("doh_last") or 0)
    if not bypass.get("doh_blocklist") and last and (now if now is not None else time.time()) - last < DOH_RECENT_S:
        lines.append(fmt.translate("HomePage", "An application looked up a DNS-over-HTTPS server: a browser with "
                                               "secure DNS on bypasses the filter. Turn on \"Block known "
                                               "DNS-over-HTTPS servers\" on the DNS page, or turn secure DNS off in "
                                               "the browser."))
    return lines


def health_text(status: dict[str, Any]) -> str:
    lines = []
    health = status.get("health")
    if health is not None and health.get("interception_expected") and not health.get("interception"):
        lines.append(fmt.translate("HomePage", "Interception: not active — the firewall redirect is not applied, so applications "
                        "are not filtered."))
    elif health is not None:
        families = ", ".join(health.get("interception") or []) or fmt.translate("HomePage", "none (development mode)")
        line = fmt.translate("HomePage", "Interception: %1").replace("%1", families.replace("ipv4", "IPv4").replace("ipv6", "IPv6"))
        if health.get("interception_error"):
            line += " — " + fmt.safe(health["interception_error"])
        lines.append(line)
    upstream = status.get("upstream") or {}
    active = upstream.get("active")
    if active:
        lock = fmt.translate("HomePage", "encrypted") if active.get("encrypted") else fmt.translate("HomePage", "not encrypted")
        lines.append(fmt.translate("HomePage", "DNS server: %1 (%2, %3)").replace("%1", fmt.safe(active.get("label", ""), 120))
                     .replace("%2", fmt.tier(active.get("tier", ""))).replace("%3", lock))
    elif upstream.get("tiers"):
        first = upstream["tiers"][0]
        lock = fmt.translate("HomePage", "encrypted") if first.get("encrypted") else fmt.translate("HomePage", "not encrypted")
        lines.append(fmt.translate("HomePage", "DNS server: %1 (%2)").replace(
            "%1", ", ".join(fmt.safe(u, 80) for u in first.get("upstreams", [])[:2])).replace("%2", lock))
    if upstream.get("captive"):
        lines.append(fmt.translate("HomePage", "Captive portal: using the network's DNS until you sign in."))
    lines += bypass_warnings(status)
    if upstream.get("clock_suspect"):
        lines.append(fmt.translate("HomePage", "Certificates look expired or not yet valid: is the clock right?"))
    filters = status.get("filters", {})
    if filters.get("missing"):
        lines.append(fmt.translate("HomePage", "%1 lists not downloaded yet").replace("%1", str(len(filters["missing"]))))
    lines.append(fmt.translate("HomePage", "Lists updated: %1").replace("%1", fmt.when(filters.get("updated_at", 0))))
    log = status.get("log")
    if log is not None and not log.get("recording", True):
        lines.append(fmt.translate("HomePage", "The query log is not recording."))
    for problem in status.get("problems", []):
        lines.append(fmt.translate("HomePage", "Problem: %1").replace("%1", fmt.safe(problem)))
    for alert in status.get("alerts", []):
        lines.append(fmt.translate("HomePage", "Alert: %1").replace("%1", fmt.safe(alert.get("message", ""))))
    if status.get("read_only"):
        lines.append(fmt.translate("HomePage", "Settings are read-only (written by a newer version)."))
    return "\n".join(lines)
