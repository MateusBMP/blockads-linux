"""Network speed from ``/proc/net/dev`` (local only)."""

from __future__ import annotations

import time
from pathlib import Path

SKIP_PREFIXES = ("lo", "docker", "br-", "veth", "virbr", "cni", "podman", "blockads")


def read_counters(path: Path = Path("/proc/net/dev")) -> tuple[int, int]:
    """Total (rx, tx) bytes over physical-ish interfaces; (0, 0) when unreadable."""
    rx = tx = 0
    try:
        lines = path.read_text().splitlines()[2:]
    except OSError:
        return 0, 0
    for line in lines:
        name, _, rest = line.partition(":")
        name = name.strip()
        if not rest or name.startswith(SKIP_PREFIXES):
            continue
        fields = rest.split()
        if len(fields) >= 9:
            try:
                rx += int(fields[0])
                tx += int(fields[8])
            except ValueError:
                continue
    return rx, tx


class SpeedMeter:
    def __init__(self, path: Path = Path("/proc/net/dev"), clock=time.monotonic) -> None:
        self.path = path
        self.clock = clock
        self._last: tuple[float, int, int] | None = None

    def sample(self) -> tuple[float, float]:
        """Bytes per second (down, up) since the previous sample; (0, 0) the first time."""
        now = self.clock()
        rx, tx = read_counters(self.path)
        last, self._last = self._last, (now, rx, tx)
        if last is None or now <= last[0]:
            return 0.0, 0.0
        elapsed = now - last[0]
        return max(0, rx - last[1]) / elapsed, max(0, tx - last[2]) / elapsed
