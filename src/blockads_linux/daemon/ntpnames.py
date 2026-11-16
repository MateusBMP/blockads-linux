"""Names of NTP servers: the only names allowed plain DNS under "encrypted only".

With "encrypted only", plain
DNS is never used, except that while the encrypted upstreams fail TLS
certificate *time* checks (a wrong clock), A/AAAA queries for NTP server names
may use the plain servers, so the time daemon can fix the clock. Plain NTP is
itself unauthenticated, so this adds no spoofing exposure that NTP does not
already have; NTS clients verify the server's TLS certificate themselves.

The names are a curated built-in set (public pools and the distributions'
defaults) plus the servers configured on this machine for systemd-timesyncd,
chrony, ntpd/NTPsec and OpenNTPD. Built-in zones match every name below them;
names read from configuration match exactly.
"""

from __future__ import annotations

import glob
import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

#: The zone itself and every name under it (vendor pools: arch., debian., ...).
BUILTIN_ZONES = frozenset({"pool.ntp.org", "ntp.ubuntu.com"})
#: Exact names (distribution defaults and large public services).
BUILTIN_NAMES = frozenset({
    "ntp-bootstrap.ubuntu.com",
    "time.google.com", "time1.google.com", "time2.google.com", "time3.google.com", "time4.google.com",
    "time.cloudflare.com",
    "time.apple.com",
    "time.windows.com",
    "time.nist.gov",
    "time.facebook.com",
})

MAX_NAMES = 256
MAX_FILES = 64
MAX_FILE_SIZE = 64 * 1024

_HOST_RE = re.compile(r"(?=.{1,253}$)[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)*")

_TIMESYNCD_DIRS = ("etc/systemd/timesyncd.conf.d", "run/systemd/timesyncd.conf.d",
                   "usr/local/lib/systemd/timesyncd.conf.d", "usr/lib/systemd/timesyncd.conf.d")
_CHRONY_FILES = ("etc/chrony.conf", "etc/chrony/chrony.conf")
_NTPD_FILES = ("etc/ntp.conf", "etc/ntpsec/ntp.conf")
_OPENNTPD_FILES = ("etc/ntpd.conf", "etc/openntpd/ntpd.conf")


@dataclass(frozen=True, slots=True)
class NtpNames:
    names: frozenset[str] = BUILTIN_NAMES
    zones: frozenset[str] = BUILTIN_ZONES
    configured: frozenset[str] = field(default_factory=frozenset)  # from this machine's configs

    @classmethod
    def load(cls, root: Path = Path("/")) -> "NtpNames":
        configured = frozenset(read_system_ntp_names(root))
        return cls(BUILTIN_NAMES | configured, BUILTIN_ZONES, configured)

    def matches(self, name: str) -> bool:
        """``name`` is normalized (lowercase, no final dot)."""
        if name in self.names:
            return True
        labels = name.split(".")
        return any(".".join(labels[i:]) in self.zones for i in range(len(labels)))


def normalize_host(text: str) -> str | None:
    """A valid host name in lowercase without the final dot; None for IPs and junk."""
    host = text.strip().strip('"').lower().rstrip(".")
    if host.startswith("[") or not _HOST_RE.fullmatch(host):
        return None
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return host
    return None


def _read(path: Path) -> str:
    try:
        with path.open("rb") as handle:
            return handle.read(MAX_FILE_SIZE).decode("utf-8", errors="replace")
    except OSError:
        return ""


def _lines(text: str) -> Iterable[list[str]]:
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if line and not line.startswith(("!", ";", "%")):
            yield line.split()


def _under(root: Path, path: str) -> Path:
    return root / path.lstrip("/")


def _glob(root: Path, pattern: str) -> list[Path]:
    return sorted(Path(p) for p in glob.glob(str(_under(root, pattern))))


def timesyncd_names(root: Path) -> list[str]:
    """``NTP=`` and ``FallbackNTP=`` of timesyncd.conf and its drop-ins."""
    files = [_under(root, "etc/systemd/timesyncd.conf")]
    for directory in _TIMESYNCD_DIRS:
        files += _glob(root, f"{directory}/*.conf")
    names = []
    for path in files[:MAX_FILES]:
        for line in _read(path).splitlines():
            key, _, value = line.partition("=")
            if key.strip() in ("NTP", "FallbackNTP"):
                names += value.split()
    return names


def chrony_names(root: Path) -> list[str]:
    """``server``/``pool``/``peer`` of chrony.conf and of its confdir, sourcedir and include files."""
    names: list[str] = []
    queue = [_under(root, path) for path in _CHRONY_FILES]
    seen: set[Path] = set()
    nested = False
    while queue and len(seen) < MAX_FILES:
        batch, queue = queue, []
        for path in batch:
            if path in seen:
                continue
            seen.add(path)
            for fields in _lines(_read(path)):
                directive, args = fields[0].lower(), fields[1:]
                if directive in ("server", "pool", "peer") and args:
                    names.append(args[0])
                elif not nested and directive in ("confdir", "sourcedir", "include"):
                    suffix = {"confdir": "/*.conf", "sourcedir": "/*.sources", "include": ""}[directive]
                    for arg in args if directive != "include" else args[:1]:
                        queue += _glob(root, arg.rstrip("/") + suffix if suffix else arg)
        nested = True  # included files are read, but their own includes are not followed
    return names


def ntpd_names(root: Path) -> list[str]:
    """``server``/``pool``/``peer`` of ntpd's (or NTPsec's) ntp.conf."""
    names = []
    for path in _NTPD_FILES:
        for fields in _lines(_read(_under(root, path))):
            if fields[0].lower() in ("server", "pool", "peer") and len(fields) > 1:
                names.append(fields[1])
    return names


def openntpd_names(root: Path) -> list[str]:
    """``server``/``servers`` of OpenNTPD's ntpd.conf."""
    names = []
    for path in _OPENNTPD_FILES:
        for fields in _lines(_read(_under(root, path))):
            if fields[0].lower() in ("server", "servers") and len(fields) > 1:
                names.append(fields[1])
    return names


def read_system_ntp_names(root: Path = Path("/")) -> set[str]:
    """Host names of the NTP servers configured on this machine (IPs skipped)."""
    found: set[str] = set()
    for reader in (timesyncd_names, chrony_names, ntpd_names, openntpd_names):
        for text in reader(root):
            host = normalize_host(text)
            if host is not None and len(found) < MAX_NAMES:
                found.add(host)
    return found
