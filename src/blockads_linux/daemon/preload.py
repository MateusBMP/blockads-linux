"""Import everything the daemon may need, at startup.

A package or Python upgrade replaces files under a running daemon. Anything
imported lazily afterwards would come from the new version and could crash
or mismatch, before the 60 s install check (``health``) restarts us. So the
daemon imports its own modules, dnspython's record types (loaded on demand
by dnspython), the HTTP stack and the codecs it uses before serving.

Optional modules that are not installed are skipped.
"""

from __future__ import annotations

import importlib
import logging
import pkgutil

log = logging.getLogger(__name__)

#: Packages imported with all their submodules.
PACKAGES = (
    "blockads_linux.common",
    "blockads_linux.filters",
    "blockads_linux.daemon",
    "dns",
)
#: Single modules that are imported lazily by their users.
MODULES = (
    "encodings.idna",
    "encodings.ascii",
    "encodings.latin_1",
    "encodings.utf_8",
    "encodings.punycode",
    "stringprep",
    "unicodedata",
    "ssl",
    "sqlite3",
    "json",
    "httpx",
    "httpcore",
    "h2.connection",
    "hpack",
    "h11",
    "jeepney",
    "jeepney.io.asyncio",
    "idna",
)
#: Submodules that are never needed and may pull in optional extras or other platforms.
SKIP = ("dns.win32util", "dns.quic", "dns.dnssec", "dns.dnssecalgs", "dns._trio_backend", "dns._trio_",
        "dns._curio_backend",  # dnspython < 2.4: needs the optional curio package
        "dns.query", "dns.asyncquery", "dns.resolver", "dns.asyncresolver", "dns.versioned", "dns.zonefile")


def preload(packages: tuple[str, ...] = PACKAGES, modules: tuple[str, ...] = MODULES) -> list[str]:
    """Import ``packages`` recursively and ``modules``; returns what could not be imported."""
    missing = []
    for name in modules:
        if not _import(name):
            missing.append(name)
    for package_name in packages:
        if not _import(package_name):
            missing.append(package_name)
            continue
        package = importlib.import_module(package_name)
        for info in pkgutil.walk_packages(package.__path__, package_name + "."):
            if info.name.startswith(SKIP) or info.name.endswith(".__main__"):
                continue
            if not _import(info.name):
                missing.append(info.name)
    if missing:
        log.debug("preload skipped: %s", ", ".join(missing))
    return missing


def _import(name: str) -> bool:
    try:
        importlib.import_module(name)
    except Exception:  # ImportError, or an optional extra failing at import time
        return False
    return True
