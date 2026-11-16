"""Statistics: 24h/7d/4w/12m chart, totals, block reasons, top domains."""

from __future__ import annotations

from typing import Any

from PyQt6.QtWidgets import (
    QGridLayout,
    QHBoxLayout,
    QListWidget,
    QTabBar,
    QVBoxLayout,
    QWidget,
)

from .. import format as fmt
from ..widgets.charts import BarChart, DonutChart
from .base import Card, Context, Page, heading, plain
from .home import series_buckets
from ..format import QT_TRANSLATE_NOOP

PERIODS = (("24h", QT_TRANSLATE_NOOP("StatisticsPage", "24 hours"), 1), ("7d", QT_TRANSLATE_NOOP("StatisticsPage", "7 days"), 7), ("4w", QT_TRANSLATE_NOOP("StatisticsPage", "4 weeks"), 28), ("12m", QT_TRANSLATE_NOOP("StatisticsPage", "12 months"), 365))


def reason_slices(reasons: dict[str, int]) -> list[tuple[str, int]]:
    """Group list ids under their list (a reason may name several, comma-joined)."""
    out: dict[str, int] = {}
    for reason, count in reasons.items():
        key = fmt.reason(reason.split(",")[0]) if reason else fmt.reason("")
        out[key] = out.get(key, 0) + int(count)
    return sorted(out.items(), key=lambda item: -item[1])


class StatisticsPage(Page):
    title = "Statistics"
    icon = "office-chart-bar"

    def __init__(self, ctx: Context, parent: QWidget | None = None) -> None:
        super().__init__(ctx, parent)
        self.title = self.tr("Statistics")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.addWidget(heading(self.tr("Statistics")))
        self.tabs = QTabBar()
        for _key, label, _days in PERIODS:
            self.tabs.addTab(self.tr(label))
        self.tabs.currentChanged.connect(lambda _i: self.refresh())
        layout.addWidget(self.tabs)

        totals = Card()
        grid = QGridLayout()
        self.values = {}
        for column, (key, label) in enumerate((("total", self.tr("Queries")), ("blocked", self.tr("Blocked")),
                                               ("rate", self.tr("Block rate")), ("cached", self.tr("From cache")),
                                               ("failed", self.tr("Failed")), ("saved", self.tr("Data saved")))):
            value = heading("–")
            grid.addWidget(value, 0, column)
            grid.addWidget(plain(label), 1, column)
            self.values[key] = value
        totals.layout_.addLayout(grid)
        layout.addWidget(totals)

        self.chart = BarChart()
        chart_card = Card(self.tr("Queries"))
        chart_card.add(self.chart)
        layout.addWidget(chart_card, 2)

        row = QHBoxLayout()
        reasons_card = Card(self.tr("Why queries were blocked"))
        self.donut = DonutChart()
        reasons_card.add(self.donut)
        row.addWidget(reasons_card, 1)
        top_blocked = Card(self.tr("Top blocked"))
        self.top_blocked = QListWidget()
        top_blocked.add(self.top_blocked)
        row.addWidget(top_blocked, 1)
        top_all = Card(self.tr("Top queried"))
        self.top_all = QListWidget()
        top_all.add(self.top_all)
        row.addWidget(top_all, 1)
        layout.addLayout(row, 2)

    def period(self) -> tuple[str, int]:
        key, _label, days = PERIODS[max(0, self.tabs.currentIndex())]
        return key, days

    def refresh(self) -> None:
        key, days = self.period()
        self.load("GetStatistics", key, then=self.show_statistics)
        self.load("GetTopDomains", days, True, 15, then=lambda r: self._top(self.top_blocked, r),
                  failed=lambda _e: self.top_blocked.clear())
        self.load("GetTopDomains", days, False, 15, then=lambda r: self._top(self.top_all, r),
                  failed=lambda _e: self.top_all.clear())

    def show_statistics(self, stats: dict[str, Any]) -> None:
        totals = stats.get("totals") or {}
        total, blocked = int(totals.get("total", 0)), int(totals.get("blocked", 0))
        self.values["total"].setText(fmt.number(total))
        self.values["blocked"].setText(fmt.number(blocked))
        self.values["rate"].setText(fmt.percent(blocked, total))
        self.values["cached"].setText(fmt.number(int(totals.get("cached", 0))))
        self.values["failed"].setText(fmt.number(int(totals.get("failed", 0))))
        self.values["saved"].setText(fmt.data_saved(blocked))
        self.chart.set_data(series_buckets(stats))
        self.donut.set_data(reason_slices(stats.get("reasons") or {}))

    @staticmethod
    def _top(widget: QListWidget, result: dict[str, Any]) -> None:
        widget.clear()
        for entry in result.get("domains", []):
            widget.addItem(f"{fmt.number(entry['count']):>8}  {fmt.safe(entry['name'], 120)}")
