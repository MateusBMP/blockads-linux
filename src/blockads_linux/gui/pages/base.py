"""What every page shares: the client, the status model, and how results are reported."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from PyQt6.QtCore import QObject, Qt, pyqtSignal
from PyQt6.QtWidgets import QFrame, QLabel, QVBoxLayout, QWidget

from ..dbus_client import CallError, DaemonClient
from ..format import translate
from ..prefs import Prefs
from ..status import StatusModel


class Messages(QObject):
    """Feedback for the message bar: ``shown(text, is_error)``."""

    shown = pyqtSignal(str, bool)

    def info(self, text: str) -> None:
        self.shown.emit(text, False)

    def error(self, text: str) -> None:
        self.shown.emit(text, True)


@dataclass
class Context:
    client: DaemonClient
    status: StatusModel
    prefs: Prefs
    messages: Messages
    theme: Any = None


def error_text(error: CallError) -> str:
    if error.kind == "not_running":
        return translate("Page", "The blockads service is not running.")
    if error.kind == "denied":
        return translate("Page", "Not authorized: the action needs an administrator password.")
    if error.kind == "read_only":
        return translate("Page", "The settings were written by a newer version and are read-only.")
    return error.message





class Page(QWidget):
    """A page of the main window. ``activate``/``deactivate`` follow visibility."""

    title = ""
    icon = ""

    def __init__(self, ctx: Context, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.ctx = ctx
        self.client = ctx.client
        self.active = False

    def activate(self) -> None:
        self.active = True
        self.refresh()

    def deactivate(self) -> None:
        self.active = False

    def refresh(self) -> None:
        pass

    def act(self, method: str, *args: Any, done: str = "", then: Callable[[Any], None] | None = None,
            refresh: bool = True) -> None:
        """Call a changing method; report the outcome; refresh the status (and the page)."""

        def ok(result: Any) -> None:
            if done:
                self.ctx.messages.info(done)
            if then is not None:
                then(result)
            if refresh:
                self.ctx.status.refresh()
                self.refresh()

        def failed(error: CallError) -> None:
            self.ctx.messages.error(error_text(error))
            if refresh:
                self.refresh()

        self.client.call(method, *args).then(ok, failed)

    def load(self, method: str, *args: Any, then: Callable[[Any], None],
             failed: Callable[[CallError], None] | None = None) -> None:
        def on_error(error: CallError) -> None:
            if failed is not None:
                failed(error)
            elif error.kind != "not_running":
                self.ctx.messages.error(error_text(error))

        self.client.call(method, *args).then(then, on_error)


def heading(text: str) -> QLabel:
    label = QLabel(text)
    font = label.font()
    font.setPointSizeF(font.pointSizeF() * 1.5)
    font.setBold(True)
    label.setFont(font)
    return label


def subheading(text: str) -> QLabel:
    label = QLabel(text)
    font = label.font()
    font.setBold(True)
    label.setFont(font)
    return label


def plain(text: str = "", *, wrap: bool = True) -> QLabel:
    """A label that never interprets markup (network data goes here)."""
    label = QLabel(text)
    label.setTextFormat(Qt.TextFormat.PlainText)
    label.setWordWrap(wrap)
    return label


class Card(QFrame):
    def __init__(self, title: str = "", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setFrameShape(QFrame.Shape.StyledPanel)
        self.setObjectName("card")
        self.layout_ = QVBoxLayout(self)
        self.layout_.setContentsMargins(12, 10, 12, 10)
        if title:
            self.layout_.addWidget(subheading(title))

    def add(self, widget: QWidget) -> QWidget:
        self.layout_.addWidget(widget)
        return widget
