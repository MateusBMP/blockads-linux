"""The filter manifest: which compiled artifact serves each list.

``filters/manifest.json`` is replaced atomically by the updater; the daemon
watches it and swaps its matcher. The previous generation is kept as
``manifest.prev.json`` for one-click rollback. Artifacts referenced by
neither are deleted (:func:`collect_garbage`).

The daemon trusts the manifest only as far as it must: names must look like
``<sha256>.bkf`` and the artifact header is verified when it is opened.
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterable
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from ..common.atomic import load_json, write_json
from ..filters.artifact import SUFFIX

MANIFEST_SCHEMA = 1
_ARTIFACT_RE = re.compile(r"[0-9a-f]{64}\.bkf")
_ID_RE = re.compile(r"[a-z0-9_]{1,80}")


class ManifestError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class Source:
    url: str
    sha256: str = ""
    size: int = 0
    etag: str = ""
    last_modified: str = ""


@dataclass(frozen=True, slots=True)
class ListEntry:
    artifact: str = ""  # "" until the first successful compile
    rules: int = 0
    compiled_at: int = 0
    checked_at: int = 0  # last attempt (Unix time)
    changed_at: int = 0  # last time the content changed
    sources: tuple[Source, ...] = ()
    error: str = ""  # last attempt's error; the artifact (if any) is the last good one


@dataclass(frozen=True, slots=True)
class Manifest:
    generation: int = 0
    updated_at: int = 0
    lists: dict[str, ListEntry] = field(default_factory=dict)

    def artifacts(self) -> set[str]:
        return {entry.artifact for entry in self.lists.values() if entry.artifact}

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": MANIFEST_SCHEMA,
            "generation": self.generation,
            "updated_at": self.updated_at,
            "lists": {list_id: {
                "artifact": e.artifact, "rules": e.rules, "compiled_at": e.compiled_at,
                "checked_at": e.checked_at, "changed_at": e.changed_at, "error": e.error,
                "sources": [{"url": s.url, "sha256": s.sha256, "size": s.size, "etag": s.etag,
                             "last_modified": s.last_modified} for s in e.sources],
            } for list_id, e in sorted(self.lists.items())},
        }

    @classmethod
    def from_dict(cls, document: Any) -> Manifest:
        if not isinstance(document, dict) or document.get("schema") != MANIFEST_SCHEMA:
            raise ManifestError("unsupported manifest")
        lists = {}
        raw_lists = document.get("lists")
        if not isinstance(raw_lists, dict):
            raise ManifestError("lists must be an object")
        for list_id, raw in raw_lists.items():
            if not _ID_RE.fullmatch(list_id) or not isinstance(raw, dict):
                raise ManifestError(f"bad entry {list_id!r}")
            artifact = _text(raw.get("artifact", ""))
            if artifact and not _ARTIFACT_RE.fullmatch(artifact):
                raise ManifestError(f"{list_id}: bad artifact name")
            sources = tuple(Source(_text(s.get("url")), _text(s.get("sha256", "")), _int(s.get("size", 0)),
                                   _text(s.get("etag", "")), _text(s.get("last_modified", "")))
                            for s in raw.get("sources", []) if isinstance(s, dict))
            lists[list_id] = ListEntry(artifact, _int(raw.get("rules", 0)), _int(raw.get("compiled_at", 0)),
                                       _int(raw.get("checked_at", 0)), _int(raw.get("changed_at", 0)),
                                       sources, _text(raw.get("error", "")))
        return cls(_int(document.get("generation", 0)), _int(document.get("updated_at", 0)), lists)


def _text(value: Any) -> str:
    if not isinstance(value, str):
        raise ManifestError("expected a string")
    return value[:4096]


def _int(value: Any) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ManifestError("expected a non-negative integer")
    return value


def load_manifest(path: Path) -> Manifest | None:
    """The manifest, or None if missing or invalid (the backup is not used: see rollback)."""
    loaded = load_json(path, Manifest.from_dict)
    return loaded.document if loaded.source in ("main", "backup") else None


def publish(paths_manifest: Path, previous: Path, manifest: Manifest) -> Manifest:
    """Make ``manifest`` current; the current one becomes the previous generation."""
    current = load_manifest(paths_manifest)
    manifest = replace(manifest, generation=(current.generation if current else 0) + 1)
    if current is not None:
        write_json(previous, current.to_dict())
    write_json(paths_manifest, manifest.to_dict())
    return manifest


def rollback(paths_manifest: Path, previous: Path) -> Manifest:
    """Swap the current and previous generations (a second rollback undoes the first)."""
    old = load_manifest(previous)
    if old is None:
        raise ManifestError("there is no previous generation")
    current = load_manifest(paths_manifest)
    generation = max(old.generation, current.generation if current else 0) + 1
    restored = replace(old, generation=generation)
    if current is not None:
        write_json(previous, current.to_dict())
    write_json(paths_manifest, restored.to_dict())
    return restored


def collect_garbage(directory: Path, keep: Iterable[str]) -> int:
    """Delete artifacts (and stale temporaries) that no manifest references."""
    keep = set(keep)
    removed = 0
    for path in directory.glob(f"*{SUFFIX}"):
        if path.name not in keep:
            try:
                path.unlink()
                removed += 1
            except OSError:
                pass
    for path in directory.glob(".tmp-*"):
        try:
            path.unlink()
        except OSError:
            pass
    return removed


def referenced(*manifests: Manifest | None) -> set[str]:
    names: set[str] = set()
    for manifest in manifests:
        if manifest is not None:
            names |= manifest.artifacts()
    return names


def exists(directory: Path, name: str) -> bool:
    return bool(name) and os.path.exists(directory / name)
