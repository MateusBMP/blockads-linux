"""The shield icon, painted (no image files): one per state colour, used by the tray and the window."""

from __future__ import annotations

from functools import lru_cache

from PyQt6.QtCore import QPointF, Qt
from PyQt6.QtGui import QBrush, QColor, QIcon, QPainter, QPainterPath, QPen, QPixmap

from . import theme


def shield_path(size: float) -> QPainterPath:
    s = size
    path = QPainterPath(QPointF(s * 0.5, s * 0.06))
    path.lineTo(s * 0.88, s * 0.2)
    path.cubicTo(s * 0.88, s * 0.58, s * 0.72, s * 0.82, s * 0.5, s * 0.95)
    path.cubicTo(s * 0.28, s * 0.82, s * 0.12, s * 0.58, s * 0.12, s * 0.2)
    path.closeSubpath()
    return path


def shield_pixmap(color: str, size: int, mark: str = "check") -> QPixmap:
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setPen(QPen(QColor(color).darker(140), max(1.0, size / 24)))
    painter.setBrush(QBrush(QColor(color)))
    painter.drawPath(shield_path(size))
    pen = QPen(QColor("#ffffff"), max(1.5, size / 10), Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap,
               Qt.PenJoinStyle.RoundJoin)
    painter.setPen(pen)
    s = size
    if mark == "check":
        painter.drawPolyline([QPointF(s * 0.32, s * 0.5), QPointF(s * 0.45, s * 0.63), QPointF(s * 0.68, s * 0.38)])
    elif mark == "pause":
        painter.drawLine(QPointF(s * 0.42, s * 0.34), QPointF(s * 0.42, s * 0.66))
        painter.drawLine(QPointF(s * 0.58, s * 0.34), QPointF(s * 0.58, s * 0.66))
    elif mark == "off":
        painter.drawLine(QPointF(s * 0.35, s * 0.5), QPointF(s * 0.65, s * 0.5))
    elif mark == "error":
        painter.drawLine(QPointF(s * 0.5, s * 0.3), QPointF(s * 0.5, s * 0.56))
        painter.drawPoint(QPointF(s * 0.5, s * 0.7))
    painter.end()
    return pixmap


@lru_cache(maxsize=8)
def state_icon(state: str) -> QIcon:
    mark = {"active": "check", "paused": "pause", "off": "off", "error": "error"}.get(state, "off")
    color = theme.STATUS.get(state, theme.STATUS["off"])
    icon = QIcon()
    for size in (16, 22, 24, 32, 48, 64, 128):
        icon.addPixmap(shield_pixmap(color, size, mark))
    return icon


def app_icon() -> QIcon:
    themed = QIcon.fromTheme("io.github.mateusbmp.blockads-linux")
    return themed if not themed.isNull() else state_icon("active")
