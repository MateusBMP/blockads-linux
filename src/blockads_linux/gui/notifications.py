"""Desktop notifications over ``org.freedesktop.Notifications`` (session bus).

Bodies are escaped: notification servers may interpret a markup subset, and
alerts can carry text that came from the network.

Besides status changes and alerts, the GUI sends:

* the daily summary at 21:00 local time (``notify_daily_summary``), once per
  day, while the GUI or its tray runs; a GUI started later that evening
  sends it then;
* milestones: the blocked total of the last 12 months crossing 1 000,
  10 000, ... (``notify_milestones``). The first count seen only sets the
  baseline, so turning BlockAds on never announces old milestones;
* filter updates (``notify_updates``: ``all``, ``errors`` or ``none``) when
  the manifest generation or its update time changes.

All of them come from the daemon's ``view`` methods: no query names.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

from PyQt6.QtCore import QMetaType, QObject, QTimer
from PyQt6.QtDBus import QDBusArgument, QDBusConnection, QDBusMessage

from . import format as fmt
from .pages.base import Context

SERVICE = ("org.freedesktop.Notifications", "/org/freedesktop/Notifications", "org.freedesktop.Notifications")
APP_NAME = "BlockAds"
ICON = "io.github.mateusbmp.blockads-linux"
SUMMARY_HOUR = 21
MILESTONES = (1_000, 10_000, 100_000, 1_000_000, 10_000_000, 100_000_000)
TICK_MS = 60_000
MILESTONE_EVERY_S = 3600


def milestone_for(blocked: int) -> int:
    """The highest milestone ``blocked`` has reached (0: none)."""
    return max((m for m in MILESTONES if blocked >= m), default=0)


class Notifier(QObject):
    def __init__(self, ctx: Context, connection: QDBusConnection | None = None, parent: QObject | None = None,
                 clock: Callable[[], float] = time.time) -> None:
        super().__init__(parent)
        self.ctx = ctx
        self.clock = clock
        self._filters: tuple[int, int] | None = None  # (generation, updated_at) last seen
        self._milestone_checked = 0.0
        self.connection = connection if connection is not None else QDBusConnection.sessionBus()
        self.sent: list[tuple[str, str]] = []  # for tests
        self._last_state: str | None = None
        self._ids: dict[str, int] = {}
        ctx.status.state_changed.connect(self._state)
        ctx.status.updated.connect(self._status)
        ctx.client.alert.connect(self._alert)
        self.timer = QTimer(self)
        self.timer.setInterval(TICK_MS)
        self.timer.timeout.connect(self.tick)
        self.timer.start()

    def notify(self, key: str, summary: str, body: str = "", urgency: int = 1) -> None:
        self.sent.append((summary, body))
        if not self.connection.isConnected():
            return
        message = QDBusMessage.createMethodCall(*SERVICE, "Notify")
        hints = {"urgency": QDBusArgument(urgency, QMetaType.Type.UChar.value),
                 "desktop-entry": ICON}
        message.setArguments([APP_NAME, QDBusArgument(self._ids.get(key, 0), QMetaType.Type.UInt.value), ICON,
                              summary, fmt.html(body, 500), [], hints, -1])
        self.connection.asyncCall(message, 5000)  # never block; the reply is not needed

    def _state(self, state: str) -> None:
        previous, self._last_state = self._last_state, state
        if previous is None or not self.ctx.prefs.get("notify_status"):
            return
        if state == "off":
            self.notify("state", fmt.translate("Notifier", "Protection stopped"), fmt.translate("Notifier", "The BlockAds service is not running: DNS is not "
                                                              "filtered."), 2)
        elif state == "error":
            self.notify("state", fmt.translate("Notifier", "Protection needs attention"), fmt.translate("Notifier", "Open BlockAds for details."), 2)
        elif state == "paused":
            status: dict[str, Any] = self.ctx.status.status or {}
            self.notify("state", fmt.translate("Notifier", "Protection paused"), fmt.pause_text(status))
        elif state == "active" and previous in ("off", "error", "paused"):
            self.notify("state", fmt.translate("Notifier", "Protection active"), "")

    def _alert(self, kind: str, message: str) -> None:
        if self.ctx.prefs.get("notify_status"):
            self.notify("alert", fmt.translate("Notifier", "BlockAds alert"), f"{kind}: {message}", 2)

    # --- daily summary, milestones, filter updates ------------------------------------

    def tick(self) -> None:
        """Every minute: the daily summary when due, the milestone check every hour."""
        status = self.ctx.status.status
        if status is None:
            return
        self._daily_summary(status)
        now = self.clock()
        if self.ctx.prefs.get("notify_milestones") and now - self._milestone_checked >= MILESTONE_EVERY_S:
            self._milestone_checked = now
            self.ctx.client.call("GetStatistics", "12m").then(self._milestone, lambda _error: None)

    def _daily_summary(self, status: dict[str, Any]) -> None:
        if not self.ctx.prefs.get("notify_daily_summary"):
            return
        local = time.localtime(self.clock())
        today = time.strftime("%Y-%m-%d", local)
        if local.tm_hour < SUMMARY_HOUR or self.ctx.prefs.get("daily_summary_sent") == today:
            return
        self.ctx.prefs.set("daily_summary_sent", today)
        totals = status.get("today") or {}
        total, blocked = int(totals.get("total", 0)), int(totals.get("blocked", 0))
        if not total:
            body = fmt.translate("Notifier", "No DNS queries today.")
        else:
            body = (fmt.translate("Notifier", "%1 queries, %2 blocked (%3).")
                    .replace("%1", fmt.number(total)).replace("%2", fmt.number(blocked))
                    .replace("%3", fmt.percent(blocked, total)))
            if blocked:
                body += " " + fmt.translate("Notifier", "About %1 of data saved.").replace(
                    "%1", fmt.data_saved(blocked))
        self.notify("summary", fmt.translate("Notifier", "BlockAds today"), body)

    def _milestone(self, statistics: Any) -> None:
        if not isinstance(statistics, dict):
            return
        blocked = int((statistics.get("totals") or {}).get("blocked", 0))
        reached = milestone_for(blocked)
        previous = self.ctx.prefs.get("milestone_reached")
        if previous < 0:  # first look: the baseline, silently
            self.ctx.prefs.set("milestone_reached", reached)
            return
        if reached > previous:
            self.ctx.prefs.set("milestone_reached", reached)
            self.notify("milestone", fmt.translate("Notifier", "Milestone reached"),
                        fmt.translate("Notifier", "BlockAds has blocked %1 requests.").replace(
                            "%1", fmt.number(reached)))

    def _status(self, status: dict[str, Any]) -> None:
        filters = status.get("filters") or {}
        seen = (int(filters.get("generation", 0)), int(filters.get("updated_at", 0)))
        previous, self._filters = self._filters, seen
        if previous is None or seen == previous or seen[1] == 0:
            return
        style = self.ctx.prefs.get("notify_updates")
        if style == "none":
            return
        self.ctx.client.call("GetFilterCatalog").then(
            lambda catalog: self._updated(catalog, status, style), lambda _error: None)

    def _updated(self, catalog: Any, status: dict[str, Any], style: str) -> None:
        if not isinstance(catalog, dict):
            return
        rows = [r for r in catalog.get("lists", []) + catalog.get("custom", []) if r.get("enabled")]
        failed = [r for r in rows if r.get("error")]
        filters = status.get("filters") or {}
        if failed:
            names = ", ".join(fmt.safe(r.get("name") or r.get("id", ""), 60) for r in failed[:3])
            if len(failed) > 3:
                names += ", …"
            self.notify("update", fmt.translate("Notifier", "Some filter lists could not be updated"),
                        fmt.translate("Notifier", "%1 failed: %2. The previous versions stay in use.")
                        .replace("%1", str(len(failed))).replace("%2", names), 1)
        elif style == "all":
            self.notify("update", fmt.translate("Notifier", "Filter lists updated"),
                        fmt.translate("Notifier", "%1 rules from %2 lists.")
                        .replace("%1", fmt.number(int(filters.get("rules", 0))))
                        .replace("%2", str(int(filters.get("lists", 0)))))
