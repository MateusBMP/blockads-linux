"""Text for the GUI: numbers, times, reasons, and safe display of network data.

Domain names, list names and server labels come from the network or from
files the daemon read: they are shown as plain text only (``safe``), never as
rich text, and escaped where a widget interprets markup (``html``).
"""

from __future__ import annotations

import html as _html
import re
import time
from typing import Any

from PyQt6.QtCore import QCoreApplication

_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f​-‏‪-‮⁦-⁩]")
AVG_RESPONSE_BYTES = 1500  # Android's "data saved" estimate per blocked query


def translate(context: str, text: str) -> str:
    """``QCoreApplication.translate``; pylupdate6 extracts ``translate("Context", "literal")`` calls."""
    return QCoreApplication.translate(context, text)


def QT_TRANSLATE_NOOP(context: str, text: str) -> str:  # noqa: N802 (the name pylupdate6 looks for)
    """Marks a literal for extraction; translate it where it is shown."""
    return text


def safe(text: Any, limit: int = 300) -> str:
    """Plain text without control or bidi characters, cut at ``limit``."""
    value = _CONTROL.sub("�", str(text))
    return value if len(value) <= limit else value[: limit - 1] + "…"


def html(text: Any, limit: int = 300) -> str:
    return _html.escape(safe(text, limit), quote=True)


def number(value: int | float) -> str:
    return f"{int(value):,}".replace(",", " ")  # thin no-break space: locale-neutral grouping


def percent(part: int, whole: int) -> str:
    return f"{100.0 * part / whole:.1f}%" if whole else "0%"


def size(nbytes: int | float) -> str:
    value = float(nbytes)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TB"  # pragma: no cover


def data_saved(blocked: int) -> str:
    return size(blocked * AVG_RESPONSE_BYTES)


def duration(seconds: int | float) -> str:
    seconds = int(seconds)
    days, rest = divmod(seconds, 86400)
    hours, rest = divmod(rest, 3600)
    minutes = rest // 60
    if days:
        return translate("format", "%1 d %2 h").replace("%1", str(days)).replace("%2", str(hours))
    if hours:
        return translate("format", "%1 h %2 min").replace("%1", str(hours)).replace("%2", str(minutes))
    if minutes:
        return translate("format", "%1 min").replace("%1", str(minutes))
    return translate("format", "%1 s").replace("%1", str(seconds))


def when(ts: int | float, now: float | None = None) -> str:
    """A Unix time as local date/time; "never" for 0."""
    if not ts:
        return translate("format", "never")
    now = time.time() if now is None else now
    if time.strftime("%Y%m%d", time.localtime(ts)) == time.strftime("%Y%m%d", time.localtime(now)):
        return time.strftime("%H:%M", time.localtime(ts))
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts))


def clock_ms(ms: int) -> str:
    return time.strftime("%H:%M:%S", time.localtime(ms / 1000))


def stamp_ms(ms: int) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ms / 1000))


def reason(value: str) -> str:
    """A log/TestDomain reason; a filter list id is shown as is."""
    labels = {
        "": "",
        "custom": translate("format", "your blocklist"),
        "custom_allow": translate("format", "your allowlist"),
        "whitelist": translate("format", "your whitelist"),
        "filter_list": translate("format", "a filter list"),
        "doh_bypass_protection": translate("format", "DoH bypass protection"),
        "doh_canary": translate("format", "Firefox DoH canary"),
        "invalid_tld": translate("format", "invalid top-level domain"),
        "paused": translate("format", "protection paused"),
        "trusted_network": translate("format", "trusted network"),
        "internal_allow": translate("format", "needed by the system"),
        "safesearch": translate("format", "SafeSearch"),
        "youtube_restricted": translate("format", "YouTube Restricted"),
        "preferred_ip": translate("format", "preferred IP type"),
        "upstream_dns": translate("format", "blocked by the DNS server"),
    }
    if value.startswith("cname:"):
        return translate("format", "CNAME cloaking: %1").replace("%1", safe(value[6:].replace(",", ", "), 80))
    return labels.get(value, safe(value.replace(",", ", "), 80))


def verdict(value: str) -> str:
    return {"blocked": translate("format", "Blocked"), "forwarded": translate("format", "Allowed"), "allowed": translate("format", "Allowed"),
            "local": translate("format", "Local"), "failed": translate("format", "Failed")}.get(value, safe(value, 20))


def tier(value: str) -> str:
    return {"route": translate("format", "local network route"), "captive": translate("format", "captive portal"),
            "trusted": translate("format", "trusted network DNS"), "vpn": translate("format", "VPN"),
            "configured": translate("format", "configured"), "fallback": translate("format", "fallback"), "network": translate("format", "network DNS"),
            "ntp-rescue": translate("format", "clock rescue")}.get(value, safe(value, 40))


def pause_text(status: dict[str, Any]) -> str:
    protection = status.get("protection", {})
    if protection.get("state") == "trusted":
        network = protection.get("trusted_network") or {}
        return translate("format", "Paused on a trusted network (%1)").replace(
            "%1", safe(network.get("name") or translate("format", "unnamed"), 60))
    until = protection.get("paused_until", 0)
    if until:
        return translate("format", "Paused until %1").replace("%1", when(until))
    return translate("format", "Paused until resumed")
