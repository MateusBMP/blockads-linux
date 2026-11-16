"""The local diagnostics export.

A JSON report a user can attach to a bug report: versions, the platform,
the daemon's status, its settings, the filter lists' state and the
firewall helper's ``status``/``doctor`` output. It is written locally and
sent nowhere.

What could identify the user or their networks is left out or redacted:
no query log, no domain rules (counts only), no network or connection
names, UUIDs or split-DNS domains, and custom list URLs keep only their
host.
"""

from __future__ import annotations

import platform
import sys
import time
from importlib import metadata
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .. import __version__

REPORT_VERSION = 1
PACKAGES = ("jeepney", "dnspython", "httpx", "httpcore", "h2", "PyQt6", "aioquic")


def environment(os_release: Path = Path("/etc/os-release")) -> dict[str, Any]:
    info: dict[str, Any] = {
        "blockads_linux": __version__,
        "python": sys.version.split()[0],
        "kernel": platform.release(),
        "machine": platform.machine(),
        "os": _os_name(os_release),
        "packages": {},
    }
    for name in PACKAGES:
        try:
            info["packages"][name] = metadata.version(name)
        except metadata.PackageNotFoundError:
            continue
    return info


def _os_name(path: Path) -> str:
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("PRETTY_NAME="):
                return line.split("=", 1)[1].strip().strip('"')[:200]
    except OSError:
        pass
    return ""


def _host(url: Any) -> str:
    try:
        return urlsplit(str(url)).hostname or ""
    except ValueError:
        return ""


def redact_status(status: dict[str, Any]) -> dict[str, Any]:
    status = dict(status)
    protection = dict(status.get("protection") or {})
    if protection.get("trusted_network"):
        protection["trusted_network"] = {"mode": protection["trusted_network"].get("mode")}
    status["protection"] = protection
    network = status.get("network")
    if isinstance(network, dict):
        status["network"] = {**{k: v for k, v in network.items() if k not in ("name", "uuid", "split_dns")},
                             "split_dns_routes": len(network.get("split_dns") or [])}
    return status


def redact_settings(settings: dict[str, Any]) -> dict[str, Any]:
    settings = dict(settings)
    settings["trusted_networks"] = [{"mode": n.get("mode")} for n in settings.get("trusted_networks") or []]
    filters = dict(settings.get("filters") or {})
    filters["custom"] = [{"id": c.get("id"), "enabled": c.get("enabled"),
                          "hosts": sorted({_host(u) for u in c.get("urls") or []})}
                         for c in filters.get("custom") or []]
    settings["filters"] = filters
    return settings


def summarize_catalog(catalog: dict[str, Any]) -> list[dict[str, Any]]:
    rows = [r for r in (catalog.get("lists") or []) + (catalog.get("custom") or []) if r.get("enabled")]
    return [{key: row.get(key) for key in ("id", "downloaded", "rules", "changed_at", "checked_at", "error")}
            for row in rows]


def build(*, status: Any = None, settings: Any = None, catalog: Any = None, firewall: Any = None,
          doctor: Any = None, errors: dict[str, str] | None = None,
          env: dict[str, Any] | None = None, now: float | None = None) -> dict[str, Any]:
    """The report; a part that could not be read is ``None`` with the reason in ``errors``."""
    return {
        "report": REPORT_VERSION,
        "created": int(now if now is not None else time.time()),
        "environment": env if env is not None else environment(),
        "status": redact_status(status) if isinstance(status, dict) else None,
        "settings": redact_settings(settings) if isinstance(settings, dict) else None,
        "filter_lists": summarize_catalog(catalog) if isinstance(catalog, dict) else None,
        "firewall_status": firewall,
        "firewall_doctor": doctor,
        "errors": dict(errors or {}),
    }
