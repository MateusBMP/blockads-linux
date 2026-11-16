"""Crash-safe file replacement and JSON documents with a backup copy.

:func:`write_atomic` writes a temporary file in the same directory, fsyncs
it, optionally keeps the previous version as ``<name>.bak``, renames it into
place and fsyncs the directory. A crash leaves either the old or the new
file, never a torn one. On failure (ENOSPC included) the temporary file is
removed and the old file is untouched.

:func:`load_json` reads a document, falling back to the ``.bak`` copy when
the main file is missing, unreadable or invalid; a corrupt main file is
moved aside (``<name>.corrupt-<time>``) so it can be inspected and is not
read again.
"""

from __future__ import annotations

import json
import os
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

MAX_JSON_BYTES = 16 * 1024 * 1024
KEEP_CORRUPT = 3  # quarantined copies kept per file


def backup_path(path: Path) -> Path:
    return path.with_name(path.name + ".bak")


def fsync_dir(directory: Path) -> None:
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_atomic(path: Path, data: bytes, *, mode: int = 0o600, backup: bool = False) -> None:
    directory = path.parent
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "wb") as out:
            os.fchmod(out.fileno(), mode)
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        if backup and path.exists():
            bak = backup_path(path)
            bak_tmp = bak.with_name(bak.name + ".tmp")
            bak_tmp.unlink(missing_ok=True)
            os.link(path, bak_tmp)  # the old inode becomes the backup: no copy, no extra space
            os.replace(bak_tmp, bak)
        os.replace(tmp_name, path)
        fsync_dir(directory)
    except BaseException:
        Path(tmp_name).unlink(missing_ok=True)
        raise


def dump_json(document: Any) -> bytes:
    return (json.dumps(document, indent=1, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def write_json(path: Path, document: Any, *, backup: bool = False) -> None:
    write_atomic(path, dump_json(document), backup=backup)


@dataclass(frozen=True, slots=True)
class Loaded:
    document: Any | None  # None: neither the file nor its backup was usable
    source: str  # "main" | "backup" | "missing" | "invalid"
    problem: str = ""  # why the main file was not used


def _read(path: Path, validate: Callable[[Any], Any] | None) -> Any:
    with path.open("rb") as stream:
        data = stream.read(MAX_JSON_BYTES + 1)
    if len(data) > MAX_JSON_BYTES:
        raise ValueError("file too large")
    document = json.loads(data.decode("utf-8"))
    return validate(document) if validate is not None else document


def quarantine(path: Path, clock: Callable[[], float] = time.time) -> Path | None:
    """Move a corrupt file aside, keeping the last few copies."""
    target = path.with_name(f"{path.name}.corrupt-{int(clock())}")
    try:
        os.replace(path, target)
    except OSError:
        return None
    old = sorted(path.parent.glob(f"{path.name}.corrupt-*"))
    for extra in old[:-KEEP_CORRUPT]:
        extra.unlink(missing_ok=True)
    return target


def load_json(path: Path, validate: Callable[[Any], Any] | None = None, *,
              clock: Callable[[], float] = time.time) -> Loaded:
    """Read ``path`` (or its backup); ``validate`` may raise ValueError/TypeError/KeyError."""
    problem = ""
    try:
        return Loaded(_read(path, validate), "main")
    except FileNotFoundError:
        problem = "missing"
    except (OSError, ValueError, TypeError, KeyError) as exc:
        problem = f"{type(exc).__name__}: {exc}"[:200]
        if not isinstance(exc, PermissionError):
            quarantine(path, clock)
    try:
        return Loaded(_read(backup_path(path), validate), "backup", problem)
    except FileNotFoundError:
        pass
    except (OSError, ValueError, TypeError, KeyError) as exc:
        if problem == "missing":
            problem = f"backup: {type(exc).__name__}: {exc}"[:200]
    return Loaded(None, "missing" if problem == "missing" else "invalid", problem)
