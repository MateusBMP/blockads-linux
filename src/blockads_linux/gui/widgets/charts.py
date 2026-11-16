"""QPainter charts (QtCharts is not a dependency): a stacked bar chart and a donut.

Both take plain data and repaint; hovering shows the exact values in a tooltip.
"""

from __future__ import annotations

import math

from PyQt6.QtCore import QPointF, QRectF, QSize, Qt
from PyQt6.QtGui import QColor, QFontMetrics, QPainter, QPainterPath, QPalette, QPen
from PyQt6.QtWidgets import QSizePolicy, QToolTip, QWidget

from .. import theme
from ..format import number, safe

DONUT_COLORS = ("#e53935", "#fb8c00", "#fdd835", "#8e24aa", "#1e88e5", "#00897b", "#6d4c41", "#757575")


def _nice_max(value: int, ticks: int = 4) -> int:
    """The axis top: ``ticks`` equal integer steps of 1, 2, 2.5 or 5 x 10^k covering ``value``."""
    raw = max(1.0, value / ticks)
    exponent = 10 ** int(math.floor(math.log10(raw)))
    for step in (1, 2, 2.5, 5, 10):
        size = step * exponent
        if size >= raw and float(size).is_integer():
            return int(size) * ticks
    return 10 * exponent * ticks  # pragma: no cover


class BarChart(QWidget):
    """Buckets of (label, total, blocked): allowed stacked on blocked."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.buckets: list[tuple[str, int, int]] = []
        self.setMouseTracking(True)
        self.setMinimumHeight(160)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

    def sizeHint(self) -> QSize:
        return QSize(480, 200)

    def set_data(self, buckets: list[tuple[str, int, int]]) -> None:
        self.buckets = list(buckets)
        self.update()

    def _plot(self) -> tuple[QRectF, float]:
        metrics = QFontMetrics(self.font())
        left = metrics.horizontalAdvance(number(self._top())) + 10
        rect = QRectF(left, 8, max(1.0, self.width() - left - 8), max(1.0, self.height() - metrics.height() - 16))
        slot = rect.width() / max(1, len(self.buckets))
        return rect, slot

    def _top(self) -> int:
        return _nice_max(max((total for _, total, _ in self.buckets), default=0))

    def paintEvent(self, _event) -> None:  # noqa: N802 (Qt API)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        palette = self.palette()
        text = palette.color(QPalette.ColorRole.WindowText)
        grid = palette.color(QPalette.ColorRole.Mid)
        rect, slot = self._plot()
        top = self._top()
        metrics = QFontMetrics(self.font())
        painter.setPen(QPen(grid, 1, Qt.PenStyle.DotLine))
        for i in range(5):
            y = rect.bottom() - rect.height() * i / 4
            painter.drawLine(QPointF(rect.left(), y), QPointF(rect.right(), y))
            painter.setPen(text)
            label = number(top * i // 4)
            painter.drawText(QRectF(0, y - metrics.height() / 2, rect.left() - 6, metrics.height()),
                             Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter, label)
            painter.setPen(QPen(grid, 1, Qt.PenStyle.DotLine))
        if not self.buckets:
            painter.setPen(text)
            painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, self.tr("No data yet"))
            return
        allowed_color, blocked_color = QColor(theme.ALLOWED), QColor(theme.BLOCKED)
        bar = max(1.0, slot * 0.7)
        every = max(1, int(math.ceil(len(self.buckets) / max(1, rect.width() / 48))))
        painter.setPen(Qt.PenStyle.NoPen)
        for i, (label, total, blocked) in enumerate(self.buckets):
            x = rect.left() + slot * i + (slot - bar) / 2
            h_total = rect.height() * total / top
            h_blocked = rect.height() * min(blocked, total) / top
            painter.setBrush(allowed_color)
            painter.drawRect(QRectF(x, rect.bottom() - h_total, bar, h_total - h_blocked))
            painter.setBrush(blocked_color)
            painter.drawRect(QRectF(x, rect.bottom() - h_blocked, bar, h_blocked))
            if i % every == 0:
                painter.setPen(text)
                painter.drawText(QRectF(x - slot, rect.bottom() + 4, bar + 2 * slot, metrics.height()),
                                 Qt.AlignmentFlag.AlignHCenter, label)
                painter.setPen(Qt.PenStyle.NoPen)

    def bucket_at(self, x: float) -> int | None:
        rect, slot = self._plot()
        if not self.buckets or not rect.left() <= x <= rect.right():
            return None
        return min(len(self.buckets) - 1, int((x - rect.left()) // slot))

    def mouseMoveEvent(self, event) -> None:  # noqa: N802
        index = self.bucket_at(event.position().x())
        if index is None:
            QToolTip.hideText()
            return
        label, total, blocked = self.buckets[index]
        QToolTip.showText(event.globalPosition().toPoint(),
                          self.tr("%1\n%2 queries, %3 blocked").replace("%1", label)
                          .replace("%2", number(total)).replace("%3", number(blocked)), self)


class DonutChart(QWidget):
    """Slices of (label, count), largest first; at most 8 (the rest is "Other")."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.slices: list[tuple[str, int]] = []
        self.setMinimumSize(220, 160)
        self.setMouseTracking(True)

    def sizeHint(self) -> QSize:
        return QSize(320, 200)

    def set_data(self, slices: list[tuple[str, int]]) -> None:
        items = sorted(((safe(label, 60), int(count)) for label, count in slices if count > 0),
                       key=lambda item: -item[1])
        if len(items) > len(DONUT_COLORS):
            rest = sum(count for _, count in items[len(DONUT_COLORS) - 1:])
            items = items[: len(DONUT_COLORS) - 1] + [(self.tr("Other"), rest)]
        self.slices = items
        self.update()

    def _ring(self) -> QRectF:
        side = min(self.height() - 16, self.width() * 0.45)
        return QRectF(8, (self.height() - side) / 2, side, side)

    def paintEvent(self, _event) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        text = self.palette().color(QPalette.ColorRole.WindowText)
        ring = self._ring()
        total = sum(count for _, count in self.slices)
        if not total:
            painter.setPen(text)
            painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, self.tr("No data yet"))
            return
        angle = 90.0 * 16
        for i, (_label, count) in enumerate(self.slices):
            span = -360.0 * 16 * count / total
            path = QPainterPath()
            path.arcMoveTo(ring, angle / 16)
            path.arcTo(ring, angle / 16, span / 16)
            inner = ring.adjusted(ring.width() * 0.22, ring.height() * 0.22,
                                  -ring.width() * 0.22, -ring.height() * 0.22)
            path.arcTo(inner, (angle + span) / 16, -span / 16)
            path.closeSubpath()
            painter.fillPath(path, QColor(DONUT_COLORS[i % len(DONUT_COLORS)]))
            angle += span
        metrics = QFontMetrics(self.font())
        x = ring.right() + 16
        y = max(8.0, (self.height() - len(self.slices) * (metrics.height() + 4)) / 2)
        for i, (label, count) in enumerate(self.slices):
            painter.fillRect(QRectF(x, y + 3, 10, 10), QColor(DONUT_COLORS[i % len(DONUT_COLORS)]))
            painter.setPen(text)
            line = f"{label}  {number(count)} ({100 * count / total:.0f}%)"
            painter.drawText(QRectF(x + 16, y, self.width() - x - 20, metrics.height() + 2),
                             Qt.AlignmentFlag.AlignVCenter, metrics.elidedText(
                                 line, Qt.TextElideMode.ElideRight, int(self.width() - x - 20)))
            y += metrics.height() + 4
