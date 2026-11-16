"""One updater run.

1. Read the settings: the enabled catalog lists (retired ones skipped) and
   the enabled custom lists (several URLs merged into one artifact).
2. Unless forced ("Update now", ``--force``), skip the run on a metered
   connection when "unmetered only" is set, and update only the lists that
   are due: new or never compiled, past the update interval, failed more than
   an hour ago, or with changed URLs. A ``checked_at`` in the future (the
   clock went back) counts as due.
3. Download (conditional requests), compile as a stream into a
   content-addressed artifact, and reject a result with no rules or a shrink
   of more than 90%: the last good artifact stays.
4. Publish the manifest atomically. The previous generation is rotated only
   when an artifact changed, so hourly "nothing new" runs never overwrite
   the rollback copy. Unreferenced artifacts are deleted.
5. Write ``update-status.json`` for the GUI (no list contents, no addresses).
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import hashlib
import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..common.atomic import write_json
from ..common.paths import Paths
from ..common.settings import Settings, load_settings
from ..filters.artifact import DEFAULT_MAX_ENTRIES, ArtifactBuilder, ArtifactError, TooManyRules
from ..filters.catalog import Catalog, load_bundled_catalog
from ..filters.parser import iter_binary_lines, iter_list_rules
from . import manifest as mf
from .fetch import FetchError, Fetcher, FetchResult
from .manifest import ListEntry, Manifest, Source

log = logging.getLogger("blockads-update")

STATUS_SCHEMA = 1
RETRY_FAILED_AFTER = 3600
MAX_SHRINK = 0.9  # reject a list that lost more than 90% of its rules
CLOCK_SLACK = 86400


@dataclass(frozen=True, slots=True)
class Target:
    id: str
    urls: tuple[str, ...]


def targets(settings: Settings, catalog: Catalog) -> list[Target]:
    result = []
    for list_id in settings.filters.enabled:
        entry = catalog.get(list_id)
        if entry is not None and not entry.retired:
            result.append(Target(list_id, (entry.url,)))
    for custom in settings.filters.custom:
        if custom.enabled and custom.urls:
            result.append(Target(custom.id, custom.urls))
    return result


def is_due(target: Target, entry: ListEntry | None, interval_hours: int, now: float) -> bool:
    if entry is None or not entry.artifact:
        return True
    if tuple(s.url for s in entry.sources) != target.urls:
        return True
    if entry.checked_at > now + CLOCK_SLACK:
        return True
    age = now - entry.checked_at
    if entry.error and age >= RETRY_FAILED_AFTER:
        return True
    return interval_hours > 0 and age >= interval_hours * 3600


class Updater:
    def __init__(self, paths: Paths, fetcher: Fetcher, *, catalog: Catalog | None = None,
                 metered: Callable[[], Awaitable[bool]] | None = None, clock: Callable[[], float] = time.time,
                 concurrency: int = 3, max_entries: int = DEFAULT_MAX_ENTRIES) -> None:
        self.paths = paths
        self.fetcher = fetcher
        self.catalog = catalog or load_bundled_catalog()
        self.metered = metered
        self.clock = clock
        self.concurrency = concurrency
        self.max_entries = max_entries

    async def run(self, *, force: bool = False, only: set[str] | None = None) -> dict[str, Any]:
        paths = self.paths
        paths.ensure()
        started = int(self.clock())
        if paths.update_request.exists():
            force = True
            with contextlib.suppress(OSError):
                paths.update_request.unlink()
        settings = load_settings(paths.settings).value
        current = mf.load_manifest(paths.manifest) or Manifest()
        status: dict[str, Any] = {"schema": STATUS_SCHEMA, "started_at": started, "forced": force, "skipped": "",
                                  "lists": {}, "generation": current.generation}
        if not force and settings.filters.unmetered_only and self.metered is not None and await self.metered():
            status["skipped"] = "metered"
            return self._finish(status)
        wanted = targets(settings, self.catalog)
        due = [t for t in wanted
               if (only is None or t.id in only)
               and (force or is_due(t, current.lists.get(t.id), settings.filters.update_interval_hours, started))]
        semaphore = asyncio.Semaphore(self.concurrency)

        async def one(target: Target) -> tuple[str, ListEntry, str]:
            async with semaphore:
                entry, result = await self._update(target, current.lists.get(target.id))
                return target.id, entry, result

        results = await asyncio.gather(*(one(t) for t in due))
        lists = {t.id: current.lists[t.id] for t in wanted if t.id in current.lists}
        for list_id, entry, result in results:
            lists[list_id] = entry
            status["lists"][list_id] = {"result": result, "error": entry.error, "rules": entry.rules}
        new = Manifest(current.generation, started, lists)
        if new.lists != current.lists or not paths.manifest.exists():
            artifacts_changed = ({k: e.artifact for k, e in new.lists.items()}
                                 != {k: e.artifact for k, e in current.lists.items()})
            if artifacts_changed or not paths.manifest.exists():
                new = mf.publish(paths.manifest, paths.previous_manifest, new)
            else:  # bookkeeping only (checked_at, ETags): keep the rollback copy
                write_json(paths.manifest, new.to_dict())
            status["generation"] = new.generation
        previous = mf.load_manifest(paths.previous_manifest)
        mf.collect_garbage(paths.artifacts, mf.referenced(new, previous))
        return self._finish(status)

    def _finish(self, status: dict[str, Any]) -> dict[str, Any]:
        status["finished_at"] = int(self.clock())
        results = [v["result"] for v in status["lists"].values()]
        status["summary"] = {r: results.count(r) for r in ("updated", "unchanged", "failed")}
        try:
            write_json(self.paths.update_status, status)
        except OSError as exc:
            log.warning("cannot write the status file: %s", exc.strerror)
        return status

    async def _update(self, target: Target, old: ListEntry | None) -> tuple[ListEntry, str]:
        now = int(self.clock())
        same_urls = old is not None and old.artifact and tuple(s.url for s in old.sources) == target.urls
        previous_sources = {s.url: s for s in old.sources} if same_urls and old else {}
        files = [self.paths.download_dir / f"{target.id}.{index}" for index in range(len(target.urls))]
        try:
            fetched: list[FetchResult] = []
            for url, path in zip(target.urls, files):
                known = previous_sources.get(url)
                fetched.append(await self.fetcher.fetch(url, path, etag=known.etag if known else "",
                                                        last_modified=known.last_modified if known else ""))
            if all(r.status == "not_modified" for r in fetched) and old is not None:
                return dataclasses.replace(old, checked_at=now, error="", sources=_merge(old.sources, fetched)), \
                    "unchanged"
            for index, result in enumerate(fetched):  # a merged list needs every part
                if result.status == "not_modified":
                    fetched[index] = await self.fetcher.fetch(target.urls[index], files[index])
            sources = tuple(Source(target.urls[i], r.sha256, r.size, r.etag, r.last_modified)
                            for i, r in enumerate(fetched))
            if old is not None and old.artifact and [s.sha256 for s in old.sources] == [s.sha256 for s in sources]:
                return dataclasses.replace(old, checked_at=now, error="", sources=sources), "unchanged"
            info = await asyncio.to_thread(self._compile, files, sources, now)
            if old is not None and old.rules and info.block_count < old.rules * (1 - MAX_SHRINK):
                raise FetchError(f"the list shrank from {old.rules} to {info.block_count} rules; kept the old one")
            entry = ListEntry(info.name, info.block_count, now, now, now, sources, "")
            return entry, "updated"
        except (FetchError, ArtifactError, OSError) as exc:
            message = _message(exc)
            log.warning("%s: %s", target.id, message)
            base = old if old is not None else ListEntry(sources=tuple(Source(u) for u in target.urls))
            return dataclasses.replace(base, checked_at=now, error=message), "failed"
        finally:
            for path in files:
                with contextlib.suppress(OSError):
                    path.unlink()

    def _compile(self, files: list[Path], sources: tuple[Source, ...], now: int) -> Any:
        builder = ArtifactBuilder(self.max_entries)
        for path in files:
            with path.open("rb") as stream:
                builder.add_rules(iter_list_rules(iter_binary_lines(stream)))
        digest = hashlib.sha256("".join(s.sha256 for s in sources).encode()).digest()
        return builder.write(self.paths.artifacts, source_sha256=digest, compiled_at=now)


def _merge(old: tuple[Source, ...], fetched: list[FetchResult]) -> tuple[Source, ...]:
    """Keep the old hashes; take refreshed validators from 304 replies when sent."""
    merged = []
    for source, result in zip(old, fetched):
        merged.append(dataclasses.replace(source, etag=result.etag or source.etag,
                                          last_modified=result.last_modified or source.last_modified))
    return tuple(merged)


def _message(exc: BaseException) -> str:
    if isinstance(exc, TooManyRules):
        return "the list has too many rules"
    if isinstance(exc, ArtifactError):
        return "no valid rules in the list"
    if isinstance(exc, OSError):
        return f"local error: {exc.strerror or type(exc).__name__}"
    return str(exc)[:300]


def read_status(path: Path) -> dict[str, Any] | None:
    from ..common.atomic import load_json

    loaded = load_json(path)
    return loaded.document if isinstance(loaded.document, dict) else None
