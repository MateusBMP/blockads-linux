"""The bundled filter-list catalog and DoH blocklist.

Both files are generated at development time by ``tools/gen_catalog.py`` from
blockads-android (GPL-3.0) and shipped as package data. They are never fetched
at runtime: the catalog only changes with an application update.
"""

from __future__ import annotations

import functools
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from importlib import resources
from urllib.parse import urlsplit

#: Category order; it is also the matching order ("security lists first").
CATEGORIES: tuple[str, ...] = ("security", "ads", "privacy", "social", "annoyances", "regional", "other")
SCHEMA_VERSION = 1

_ID_RE = re.compile(r"[a-z0-9_]{1,80}")
_DOMAIN_RE = re.compile(r"(?=.{1,253}$)([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]*[a-z0-9])?")
_MAX_URL = 2048


class CatalogError(ValueError):
    """The catalog data is malformed."""


@dataclass(frozen=True, slots=True)
class CatalogEntry:
    id: str
    name: str
    description: str
    category: str
    url: str
    enabled_by_default: bool
    android_default: bool
    approx_rules: int
    retired: str | None = None

    @property
    def category_rank(self) -> int:
        return CATEGORIES.index(self.category)


@dataclass(frozen=True, slots=True)
class Catalog:
    revision: str
    entries: tuple[CatalogEntry, ...]

    def get(self, list_id: str) -> CatalogEntry | None:
        return self._index().get(list_id)

    def default_enabled_ids(self) -> frozenset[str]:
        return frozenset(e.id for e in self.entries if e.enabled_by_default)

    def by_category(self) -> dict[str, list[CatalogEntry]]:
        groups: dict[str, list[CatalogEntry]] = {c: [] for c in CATEGORIES}
        for entry in self.entries:
            groups[entry.category].append(entry)
        return groups

    def _index(self) -> Mapping[str, CatalogEntry]:
        return _index_entries(self.entries)


@functools.lru_cache(maxsize=4)
def _index_entries(entries: tuple[CatalogEntry, ...]) -> dict[str, CatalogEntry]:
    return {e.id: e for e in entries}


def validate_list_url(url: object) -> str:
    """Accept only plain https URLs with a host and no credentials or whitespace."""
    if not isinstance(url, str) or not url or len(url) > _MAX_URL:
        raise CatalogError(f"invalid URL: {url!r}")
    if any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in url):
        raise CatalogError(f"URL contains whitespace or control characters: {url!r}")
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        raise CatalogError(f"only https URLs with a host are allowed: {url!r}")
    if parts.username is not None or parts.password is not None:
        raise CatalogError(f"URLs with credentials are not allowed: {url!r}")
    return url


def _require(value: object, kind: type, field: str, list_id: str) -> object:
    if not isinstance(value, kind) or (kind is int and isinstance(value, bool)):
        raise CatalogError(f"{list_id}: field {field!r} must be {kind.__name__}")
    return value


def parse_catalog(data: str | bytes) -> Catalog:
    """Parse and strictly validate catalog JSON."""
    try:
        doc = json.loads(data)
    except (ValueError, UnicodeDecodeError) as exc:
        raise CatalogError(f"catalog is not valid JSON: {exc}") from exc
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA_VERSION:
        raise CatalogError(f"unsupported catalog schema: {doc.get('schema') if isinstance(doc, dict) else doc!r}")
    raw_lists = doc.get("lists")
    if not isinstance(raw_lists, list) or not raw_lists:
        raise CatalogError("catalog has no lists")
    entries = []
    seen: set[str] = set()
    for item in raw_lists:
        if not isinstance(item, dict):
            raise CatalogError("catalog entries must be objects")
        list_id = item.get("id")
        if not isinstance(list_id, str) or not _ID_RE.fullmatch(list_id):
            raise CatalogError(f"invalid list id: {list_id!r}")
        if list_id in seen:
            raise CatalogError(f"duplicate list id: {list_id}")
        seen.add(list_id)
        name = _require(item.get("name"), str, "name", list_id)
        description = _require(item.get("description", ""), str, "description", list_id)
        category = item.get("category")
        if category not in CATEGORIES:
            raise CatalogError(f"{list_id}: unknown category {category!r}")
        retired = item.get("retired")
        if retired is not None:
            _require(retired, str, "retired", list_id)
        entry = CatalogEntry(
            id=list_id,
            name=str(name)[:200],
            description=str(description)[:1000],
            category=category,
            url=validate_list_url(item.get("url")),
            enabled_by_default=bool(_require(item.get("enabled_by_default"), bool, "enabled_by_default", list_id)),
            android_default=bool(_require(item.get("android_default"), bool, "android_default", list_id)),
            approx_rules=max(0, int(_require(item.get("approx_rules", 0), int, "approx_rules", list_id))),
            retired=retired,
        )
        if entry.retired and entry.enabled_by_default:
            raise CatalogError(f"{list_id}: a retired list cannot be enabled by default")
        entries.append(entry)
    source = doc.get("source") if isinstance(doc.get("source"), dict) else {}
    return Catalog(revision=str(source.get("revision", "")), entries=tuple(entries))


def parse_doh_blocklist(text: str) -> frozenset[str]:
    """Parse the DoH blocklist: one lowercase domain per line, ``#`` comments."""
    domains = set()
    for line in text.splitlines():
        entry = line.split("#", 1)[0].strip()
        if not entry:
            continue
        if not _DOMAIN_RE.fullmatch(entry):
            raise CatalogError(f"invalid DoH blocklist entry: {entry!r}")
        domains.add(entry)
    return frozenset(domains)


def _read_data(name: str) -> str:
    return resources.files("blockads_linux.filters").joinpath("data", name).read_text("utf-8")


@functools.cache
def load_bundled_catalog() -> Catalog:
    return parse_catalog(_read_data("catalog.json"))


@functools.cache
def load_doh_blocklist() -> frozenset[str]:
    return parse_doh_blocklist(_read_data("doh_blocklist.txt"))
