"""Fusion style with our palettes: system, light, dark, black, plus an accent.

"system" follows the desktop: ``QStyleHints.colorScheme()`` on Qt >= 6.5; on
older Qt (Debian 12 has 6.4) the platform palette's window luminance decides.
"""

from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QGuiApplication, QPalette
from PyQt6.QtWidgets import QApplication, QStyleFactory

THEMES = ("system", "light", "dark", "black")
ACCENTS = {
    "teal": "#00897b",
    "blue": "#1e88e5",
    "indigo": "#5c6bc0",
    "purple": "#8e24aa",
    "green": "#43a047",
    "orange": "#f4511e",
}
DEFAULT_ACCENT = "teal"

# Status colours (tray, shield, charts). Chosen to read on light and dark backgrounds.
STATUS = {"active": "#2e7d32", "paused": "#f9a825", "off": "#757575", "error": "#c62828"}
BLOCKED = "#e53935"
ALLOWED = "#43a047"


def system_is_dark(app: QGuiApplication, base: QPalette | None = None) -> bool:
    hints = app.styleHints()
    scheme = getattr(hints, "colorScheme", None)
    if scheme is not None:
        value = scheme()
        if value == Qt.ColorScheme.Dark:
            return True
        if value == Qt.ColorScheme.Light:
            return False
    palette = base or app.palette()
    return palette.color(QPalette.ColorRole.Window).lightness() < 128


def _palette(dark: bool, black: bool, accent: QColor) -> QPalette:
    p = QPalette()
    if dark:
        window = QColor("#000000" if black else "#202124")
        base = QColor("#0a0a0a" if black else "#18191b")
        alt = QColor("#141414" if black else "#26272a")
        text = QColor("#e8eaed")
        button = QColor("#121212" if black else "#2b2c2f")
        mid = QColor("#3c4043")
        disabled = QColor("#7f8388")
    else:
        window = QColor("#f5f6f7")
        base = QColor("#ffffff")
        alt = QColor("#f0f1f3")
        text = QColor("#1f1f1f")
        button = QColor("#eceef1")
        mid = QColor("#c5c8cc")
        disabled = QColor("#9aa0a6")
    roles = QPalette.ColorRole
    for role, color in ((roles.Window, window), (roles.Base, base), (roles.AlternateBase, alt),
                        (roles.Button, button), (roles.WindowText, text), (roles.Text, text),
                        (roles.ButtonText, text), (roles.ToolTipBase, base), (roles.ToolTipText, text),
                        (roles.PlaceholderText, disabled), (roles.Mid, mid),
                        (roles.Highlight, accent), (roles.Link, accent),
                        (roles.HighlightedText, QColor("#ffffff"))):
        p.setColor(role, color)
    for role in (roles.WindowText, roles.Text, roles.ButtonText):
        p.setColor(QPalette.ColorGroup.Disabled, role, disabled)
    return p


class Theme:
    """Applies a theme/accent to the application and remembers the platform palette for "system"."""

    def __init__(self, app: QApplication) -> None:
        self.app = app
        self.platform_palette = QPalette(app.palette())
        self.name = "system"
        self.accent = DEFAULT_ACCENT
        self.dark = False
        hints = app.styleHints()
        if hasattr(hints, "colorSchemeChanged"):
            hints.colorSchemeChanged.connect(lambda _scheme: self.name == "system" and self.apply())

    def apply(self, name: str | None = None, accent: str | None = None) -> None:
        if name is not None:
            self.name = name if name in THEMES else "system"
        if accent is not None:
            self.accent = accent if accent in ACCENTS else DEFAULT_ACCENT
        style = QStyleFactory.create("Fusion")
        if style is not None:
            self.app.setStyle(style)
        self.dark = (system_is_dark(self.app, self.platform_palette) if self.name == "system"
                     else self.name in ("dark", "black"))
        self.app.setPalette(_palette(self.dark, self.name == "black", QColor(ACCENTS[self.accent])))

    def accent_color(self) -> QColor:
        return QColor(ACCENTS[self.accent])
