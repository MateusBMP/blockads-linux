"""Minimal ``sd_notify`` and ``sd_listen_fds`` (no python-systemd dependency).

See sd_notify(3) and sd_listen_fds(3). Both are no-ops outside systemd.
"""

from __future__ import annotations

import os
import socket

SD_LISTEN_FDS_START = 3
_MAX_FDS = 64


def listen_fds(environ: dict[str, str] | None = None, *, unset: bool = True) -> list[tuple[socket.socket, str]]:
    """Adopt the sockets passed by systemd socket activation.

    Returns ``(socket, name)`` pairs; names come from ``FileDescriptorName=``
    (``LISTEN_FDNAMES``) and default to ``"unknown"``. Like
    ``sd_listen_fds(1)``, the variables are removed from the environment so
    they are not inherited by children.
    """
    env = os.environ if environ is None else environ
    try:
        pid = int(env.get("LISTEN_PID", ""))
        count = int(env.get("LISTEN_FDS", ""))
    except ValueError:
        return []
    names = env.get("LISTEN_FDNAMES", "").split(":")
    if unset:
        for key in ("LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"):
            env.pop(key, None)
    if pid != os.getpid() or not 0 < count <= _MAX_FDS:
        return []
    adopted = []
    for index in range(count):
        fd = SD_LISTEN_FDS_START + index
        os.set_inheritable(fd, False)
        name = names[index] if index < len(names) and names[index] else "unknown"
        adopted.append((socket.socket(fileno=fd), name))
    return adopted


def notify(state: str, environ: dict[str, str] | None = None) -> bool:
    """Send ``state`` (e.g. ``"READY=1"``, ``"WATCHDOG=1"``) to systemd.

    Returns False when not running under systemd or the send fails.
    """
    env = os.environ if environ is None else environ
    address = env.get("NOTIFY_SOCKET", "")
    if not address or address[0] not in "/@":
        return False
    if address[0] == "@":
        address = "\0" + address[1:]  # abstract namespace
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM | socket.SOCK_CLOEXEC) as sock:
            sock.sendto(state.encode("utf-8"), address)
    except OSError:
        return False
    return True
