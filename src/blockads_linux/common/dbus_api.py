"""The daemon's D-Bus API: names, methods, polkit actions and limits.
Shared by the daemon, ``blockadsctl`` and the GUI.

Complex payloads are versioned JSON strings (``"api": API_VERSION``).
Every method belongs to exactly one polkit action; the daemon checks it on
every call (only ``view`` decisions are cached).
"""

from __future__ import annotations

import csv
import io
from dataclasses import dataclass
from typing import Iterable

BUS_NAME = "io.github.mateusbmp.BlockAds1"
OBJECT_PATH = "/io/github/mateusbmp/BlockAds1"
INTERFACE = "io.github.mateusbmp.BlockAds1.Daemon"
ERROR_PREFIX = "io.github.mateusbmp.BlockAds1.Error."
API_VERSION = 1

ACTION_PREFIX = "io.github.mateusbmp.blockads."
VIEW = ACTION_PREFIX + "view"
VIEW_LOGS = ACTION_PREFIX + "view-logs"
TIGHTEN = ACTION_PREFIX + "tighten"
WEAKEN = ACTION_PREFIX + "weaken"
FIREWALL = ACTION_PREFIX + "firewall"  # pkexec blockads-fw set-config; never checked by the daemon
DAEMON_ACTIONS = (VIEW, VIEW_LOGS, TIGHTEN, WEAKEN)

# Limits. jeepney's own queues are unbounded; these are enforced by the daemon.
MAX_STRING = 4096
MAX_JSON = 64 * 1024
MAX_ARRAY = 1000
MAX_INFLIGHT_PER_CALLER = 8
MAX_LOG_PAGE = 500
MAX_PAUSE_SECONDS = 30 * 86400
VIEW_CACHE_SECONDS = 60.0
AUTH_TIMEOUT = 300.0  # an interactive polkit prompt


@dataclass(frozen=True, slots=True)
class Method:
    name: str
    in_sig: str
    out_sig: str
    action: str
    args: tuple[str, ...] = ()  # argument names, for introspection
    json_args: tuple[int, ...] = ()  # indexes of JSON string arguments (MAX_JSON instead of MAX_STRING)
    out: str = "result"


def _m(name: str, in_sig: str, out_sig: str, action: str, args: tuple[str, ...] = (),
       json_args: tuple[int, ...] = (), out: str = "result") -> Method:
    return Method(name, in_sig, out_sig, action, args, json_args, out)


METHODS: dict[str, Method] = {m.name: m for m in (
    # view
    _m("GetStatus", "", "s", VIEW, out="status_json"),
    _m("GetStatistics", "s", "s", VIEW, ("period",), out="statistics_json"),
    _m("GetFilterCatalog", "", "s", VIEW, out="catalog_json"),
    _m("GetFilterOverlap", "", "s", VIEW, out="overlap_json"),
    _m("GetSettings", "", "s", VIEW, out="settings_json"),
    _m("GetRules", "", "s", VIEW, out="rules_json"),
    _m("TestDomain", "s", "s", VIEW, ("domain",), out="verdict_json"),
    # view-logs
    _m("GetQueryLog", "stu", "s", VIEW_LOGS, ("filter_json", "after_id", "limit"), (0,), out="entries_json"),
    _m("GetTopDomains", "ubu", "s", VIEW_LOGS, ("days", "blocked", "limit"), out="domains_json"),
    # tighten
    _m("AddBlockRule", "s", "", TIGHTEN, ("domain",)),
    _m("RemoveAllowRule", "s", "", TIGHTEN, ("domain",)),
    _m("EnableFilters", "as", "", TIGHTEN, ("ids",)),
    _m("UpdateFiltersNow", "", "", TIGHTEN),
    _m("Resume", "", "", TIGHTEN),
    _m("EnableFeature", "s", "", TIGHTEN, ("feature",)),
    # weaken
    _m("Pause", "t", "", WEAKEN, ("seconds",)),
    _m("DisableFilters", "as", "", WEAKEN, ("ids",)),
    _m("AddAllowRule", "s", "", WEAKEN, ("domain",)),
    _m("RemoveBlockRule", "s", "", WEAKEN, ("domain",)),
    _m("DisableFeature", "s", "", WEAKEN, ("feature",)),
    _m("SetUpstream", "s", "", WEAKEN, ("upstream_json",), (0,)),
    _m("SetTrustedNetworks", "s", "", WEAKEN, ("networks_json",), (0,)),
    _m("AddCustomFilter", "s", "s", WEAKEN, ("filter_json",), (0,), out="id"),
    _m("RemoveCustomFilter", "s", "", WEAKEN, ("id",)),
    _m("SetLogging", "bu", "", WEAKEN, ("enabled", "retention_days")),
    _m("ClearQueryLog", "", "", WEAKEN),
    _m("SetBlockedResponse", "su", "", WEAKEN, ("mode", "ttl")),
    _m("SetFilterSchedule", "ub", "", WEAKEN, ("interval_hours", "unmetered_only")),
    _m("ImportBackup", "s", "", WEAKEN, ("backup_json",), (0,)),
    _m("ResetSettings", "", "", WEAKEN),
)}

#: Signals carry no domain names (the system bus broadcasts them to everyone).
SIGNALS: dict[str, tuple[str, tuple[str, ...]]] = {
    "StatusChanged": ("s", ("summary_json",)),
    "FiltersUpdated": ("t", ("generation",)),
    "Alert": ("ss", ("kind", "message")),
}

#: Read-only properties (Properties.Set is refused by the bus policy and the daemon).
PROPERTIES: dict[str, str] = {"Version": "s", "ApiVersion": "u"}

#: EnableFeature (tighten) / DisableFeature (weaken): settings booleans where
#: True filters more. -> (section, field)
FEATURES: dict[str, tuple[str, str]] = {
    "safesearch": ("dns", "safesearch"),
    "youtube_restricted": ("dns", "youtube_restricted"),
    "doh_blocklist": ("dns", "doh_blocklist"),
    "cname_check": ("dns", "cname_check"),
    "encrypted_only": ("dns", "encrypted_only"),
}


def error_name(short: str) -> str:
    return ERROR_PREFIX + short


def introspection_xml() -> str:
    def args(sig: str, names: Iterable[str], direction: str | None) -> str:
        out = []
        for name, part in zip(names, _split_signature(sig)):
            d = f' direction="{direction}"' if direction else ""
            out.append(f'      <arg name="{name}" type="{part}"{d}/>')
        return "\n".join(out)

    parts = ['<!DOCTYPE node PUBLIC "-//freedesktop//DTD D-BUS Object Introspection 1.0//EN"',
             ' "http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd">',
             "<node>", f'  <interface name="{INTERFACE}">']
    for method in METHODS.values():
        body = "\n".join(filter(None, [args(method.in_sig, method.args, "in"),
                                       args(method.out_sig, (method.out,), "out")]))
        parts.append(f'    <method name="{method.name}">' + (f"\n{body}\n    " if body else "") + "</method>")
    for name, (sig, names) in SIGNALS.items():
        parts.append(f'    <signal name="{name}">\n{args(sig, names, None)}\n    </signal>')
    for name, sig in PROPERTIES.items():
        parts.append(f'    <property name="{name}" type="{sig}" access="read"/>')
    parts.append("  </interface>")
    parts.append('  <interface name="org.freedesktop.DBus.Introspectable">\n'
                 '    <method name="Introspect"><arg name="xml" type="s" direction="out"/></method>\n'
                 "  </interface>")
    parts.append('  <interface name="org.freedesktop.DBus.Properties">\n'
                 '    <method name="Get"><arg type="s" direction="in"/><arg type="s" direction="in"/>'
                 '<arg type="v" direction="out"/></method>\n'
                 '    <method name="GetAll"><arg type="s" direction="in"/><arg type="a{sv}" direction="out"/></method>\n'
                 "  </interface>")
    parts.append('  <interface name="org.freedesktop.DBus.Peer">\n    <method name="Ping"/>\n  </interface>')
    parts.append("</node>")
    return "\n".join(parts) + "\n"


def _split_signature(sig: str) -> list[str]:
    """Complete types of a signature ("sas" -> ["s", "as"])."""
    out, i = [], 0
    while i < len(sig):
        j = _end_of_type(sig, i)
        out.append(sig[i:j])
        i = j
    return out


def _end_of_type(sig: str, i: int) -> int:
    ch = sig[i]
    if ch == "a":
        return _end_of_type(sig, i + 1)
    if ch in "({":
        close = ")" if ch == "(" else "}"
        i += 1
        while sig[i] != close:
            i = _end_of_type(sig, i)
        return i + 1
    return i + 1


# --- CSV export (the client writes it from GetQueryLog pages) ----------------------

CSV_FIELDS = ("id", "time_ms", "name", "qtype", "verdict", "reason", "upstream", "tier", "cached",
              "elapsed_ms", "answers")


def csv_cell(value: object) -> str:
    """Formula-injection guard: a cell a spreadsheet would evaluate gets a leading quote."""
    text = ";".join(map(str, value)) if isinstance(value, (list, tuple)) else str(value)
    if text and text[0] in "=+-@\t\r|":
        return "'" + text
    return text


def csv_rows(entries: Iterable[dict], *, header: bool = True) -> str:
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    if header:
        writer.writerow(CSV_FIELDS)
    for entry in entries:
        writer.writerow([csv_cell(entry.get(name, "")) for name in CSV_FIELDS])
    return out.getvalue()
