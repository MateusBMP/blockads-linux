"""The GUI's own preferences (per desktop user, not the daemon's settings).

Stored with ``QSettings`` in ``~/.config/blockads-linux/gui.conf``. Values
are read through typed accessors with defaults, so a hand-edited or corrupt
file never breaks the GUI.
"""

from __future__ import annotations

from typing import Any

from PyQt6.QtCore import QSettings

DEFAULTS: dict[str, Any] = {
    "theme": "system",
    "accent": "teal",
    "language": "system",  # "system", "en", "pt_BR"
    "tray": True,
    "close_to_tray": True,
    "notify_status": True,
    "notify_updates": "errors",  # "all" | "errors" | "none" (update notification style)
    "notify_daily_summary": False,
    "notify_milestones": True,
    "daily_summary_sent": "",  # local date (YYYY-MM-DD) of the last daily summary
    "milestone_reached": -1,  # the highest milestone already announced; -1: no baseline yet
    "onboarded": False,
    "log_live": True,
}


class Prefs:
    def __init__(self, settings: QSettings | None = None) -> None:
        self.settings = settings or QSettings("blockads-linux", "gui")

    def get(self, key: str) -> Any:
        default = DEFAULTS[key]
        value = self.settings.value(key, default)
        if isinstance(default, bool):
            if isinstance(value, str):
                return value.lower() in ("true", "1", "yes")
            return bool(value)
        if isinstance(default, str):
            return str(value) if isinstance(value, str) else default
        if isinstance(default, int):
            try:
                return int(value)
            except (TypeError, ValueError):
                return default
        return value  # pragma: no cover

    def set(self, key: str, value: Any) -> None:
        if key not in DEFAULTS:
            raise KeyError(key)
        self.settings.setValue(key, value)
        self.settings.sync()
