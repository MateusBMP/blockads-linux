"""Daemon settings and domain rules: schema, validation and storage
(``config/settings.json`` and ``config/rules.json``,
schema-versioned, written atomically with a ``.bak``).

Documents are parsed field by field against frozen dataclasses:

* ``lenient`` (loading from disk): a bad or unknown field falls back to its
  default and is reported in ``problems``; one bad value never resets the rest;
* ``strict`` (D-Bus setters, backup import): any problem raises
  :class:`SettingsError` and nothing changes.

A document written by a newer version (higher ``schema``) is read leniently
but never overwritten, so a downgrade cannot destroy newer settings.

Upstream specs are only checked for shape here; the daemon validates them
when it builds its upstream policy (that needs the transport modules).
"""

from __future__ import annotations

import dataclasses
import re
import types
import typing
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Union

from ..filters.catalog import load_bundled_catalog, validate_list_url
from ..filters.custom_rules import CustomRuleType, is_valid_domain, parse_rule
from .atomic import load_json, write_json

SETTINGS_SCHEMA = 1
RULES_SCHEMA = 1
MAX_RULES = 100_000
MAX_RULE_LENGTH = 1024
MAX_CUSTOM_LISTS = 50
MAX_URLS_PER_LIST = 10
UPDATE_INTERVALS = (0, 6, 12, 24, 48)  # hours; 0 = manual only
_SPEC_RE = re.compile(r"[A-Za-z0-9:/._\-\[\]#%@+=?&~]{1,2048}")
_ID_RE = re.compile(r"[a-z0-9_]{1,80}")
_UUID_RE = re.compile(r"[0-9a-fA-F-]{8,64}")


class SettingsError(ValueError):
    pass


def _spec(value: str) -> None:
    if not _SPEC_RE.fullmatch(value):
        raise ValueError("not an upstream spec")


def _list_id(value: str) -> None:
    if not _ID_RE.fullmatch(value):
        raise ValueError("bad list id")


def _custom_list_id(value: str) -> None:
    if not value.startswith("custom_") or not _ID_RE.fullmatch(value):
        raise ValueError("custom list ids start with custom_")


def _https_url(value: str) -> None:
    validate_list_url(value)


def _uuid(value: str) -> None:
    if not _UUID_RE.fullmatch(value):
        raise ValueError("bad connection UUID")


def opt(default: Any = dataclasses.MISSING, *, factory: Any = dataclasses.MISSING, choices: tuple = (),
        minimum: int | None = None, maximum: int | None = None, max_len: int = 200, max_items: int = 1000,
        check: Any = None) -> Any:
    meta = {"choices": choices, "min": minimum, "max": maximum, "max_len": max_len,
            "max_items": max_items, "check": check}
    if factory is not dataclasses.MISSING:
        return field(default_factory=factory, metadata=meta)
    return field(default=default, metadata=meta)


def _default_enabled() -> tuple[str, ...]:
    return tuple(sorted(load_bundled_catalog().default_enabled_ids()))


@dataclass(frozen=True, slots=True)
class CustomList:
    id: str = opt("custom_list", check=_custom_list_id)  # the default marks a missing id
    name: str = opt("Custom list", max_len=200)
    urls: tuple[str, ...] = opt((), max_items=MAX_URLS_PER_LIST, max_len=2048, check=_https_url)
    enabled: bool = opt(True)


@dataclass(frozen=True, slots=True)
class FilterSettings:
    enabled: tuple[str, ...] = opt(factory=_default_enabled, max_items=1000, check=_list_id)
    custom: tuple[CustomList, ...] = opt((), max_items=MAX_CUSTOM_LISTS)
    update_interval_hours: int = opt(24, choices=UPDATE_INTERVALS)
    unmetered_only: bool = opt(False)


@dataclass(frozen=True, slots=True)
class DnsSettings:
    upstream: tuple[str, ...] = opt(("quad9",), max_items=8, max_len=2048, check=_spec)
    fallback: tuple[str, ...] | None = opt(None, max_items=8, max_len=2048, check=_spec)  # None: the preset's
    encrypted_only: bool = opt(False)
    vpn_dns: bool = opt(True)
    block_mode: str = opt("null_ip", choices=("null_ip", "nxdomain", "refused"))
    block_ttl: int = opt(10, minimum=0, maximum=86400)
    preferred_ip: str = opt("auto", choices=("auto", "ipv4", "ipv6"))
    safesearch: bool = opt(False)
    youtube_restricted: bool = opt(False)
    doh_blocklist: bool = opt(False)
    cname_check: bool = opt(True)


@dataclass(frozen=True, slots=True)
class LogSettings:
    enabled: bool = opt(True)
    retention_days: int = opt(7, minimum=1, maximum=365)


@dataclass(frozen=True, slots=True)
class ProtectionSettings:
    paused: bool = opt(False)
    pause_until: int = opt(0, minimum=0, maximum=2**40)  # Unix time; 0 = until resumed


@dataclass(frozen=True, slots=True)
class TrustedNetwork:
    uuid: str = opt("", check=_uuid)
    name: str = opt("", max_len=200)
    mode: str = opt("pause", choices=("pause", "network_dns"))


@dataclass(frozen=True, slots=True)
class Settings:
    filters: FilterSettings = opt(factory=FilterSettings)
    dns: DnsSettings = opt(factory=DnsSettings)
    logging: LogSettings = opt(factory=LogSettings)
    protection: ProtectionSettings = opt(factory=ProtectionSettings)
    trusted_networks: tuple[TrustedNetwork, ...] = opt((), max_items=100)

    def to_dict(self) -> dict[str, Any]:
        return {"schema": SETTINGS_SCHEMA, **_to_plain(self)}

    @classmethod
    def from_dict(cls, document: Any, *, strict: bool = False) -> tuple[Settings, list[str]]:
        problems: list[str] = []
        if not isinstance(document, dict):
            raise SettingsError("settings must be a JSON object")
        schema = document.get("schema")
        if not isinstance(schema, int) or isinstance(schema, bool) or schema < 1:
            problems.append("schema: missing or invalid")
        elif schema > SETTINGS_SCHEMA:
            problems.append(f"schema: {schema} is newer than {SETTINGS_SCHEMA}")
        settings = _parse(cls, {k: v for k, v in document.items() if k != "schema"}, "", problems)
        settings = _check_consistency(settings, problems)
        if strict and problems:
            raise SettingsError("; ".join(problems[:10]))
        return settings, problems


def _check_consistency(settings: Settings, problems: list[str]) -> Settings:
    if not settings.dns.upstream:
        problems.append("dns.upstream: empty; the default is used")
        settings = dataclasses.replace(settings, dns=dataclasses.replace(settings.dns, upstream=("quad9",)))
    custom: dict[str, CustomList] = {}
    for item in settings.filters.custom:
        if not item.urls or item.id == "custom_list" or item.id in custom:
            problems.append(f"filters.custom: {item.id!r} dropped (no valid URL, bad or duplicate id)")
        else:
            custom[item.id] = item
    trusted: dict[str, TrustedNetwork] = {}
    for network in settings.trusted_networks:
        if not network.uuid or network.uuid in trusted:
            problems.append("trusted_networks: entry without a UUID or a duplicate UUID dropped")
        else:
            trusted[network.uuid] = network
    settings = dataclasses.replace(
        settings, filters=dataclasses.replace(settings.filters, custom=tuple(custom.values())),
        trusted_networks=tuple(trusted.values()))
    return settings


# --- generic dataclass <-> JSON -------------------------------------------------


def _to_plain(value: Any) -> Any:
    if dataclasses.is_dataclass(value):
        return {f.name: _to_plain(getattr(value, f.name)) for f in dataclasses.fields(value)}
    if isinstance(value, tuple):
        return [_to_plain(v) for v in value]
    return value


def _parse(cls: type, raw: Any, prefix: str, problems: list[str]) -> Any:
    if not isinstance(raw, dict):
        problems.append(f"{prefix or 'document'}: must be an object")
        return cls()
    hints = typing.get_type_hints(cls)
    values = {}
    names = {f.name for f in dataclasses.fields(cls)}
    for key in raw:
        if key not in names:
            problems.append(f"{prefix}{key}: unknown field")
    for f in dataclasses.fields(cls):
        if f.name not in raw:
            continue
        where = f"{prefix}{f.name}"
        try:
            values[f.name] = _convert(hints[f.name], raw[f.name], f.metadata, where, problems)
        except (ValueError, TypeError) as exc:
            problems.append(f"{where}: {exc}")
    return cls(**values)


def _convert(kind: Any, value: Any, meta: Any, where: str, problems: list[str]) -> Any:
    origin = typing.get_origin(kind)
    if origin in (Union, types.UnionType):
        args = [a for a in typing.get_args(kind) if a is not type(None)]
        if value is None:
            return None
        return _convert(args[0], value, meta, where, problems)
    if origin is tuple:
        item_kind = typing.get_args(kind)[0]
        if not isinstance(value, list):
            raise TypeError("must be a list")
        if len(value) > meta["max_items"]:
            raise ValueError(f"more than {meta['max_items']} items")
        items = []
        for index, item in enumerate(value):
            try:
                items.append(_convert(item_kind, item, meta, f"{where}[{index}]", problems))
            except (ValueError, TypeError) as exc:
                problems.append(f"{where}[{index}]: {exc}")  # drop the bad item, keep the rest
        return tuple(dict.fromkeys(items)) if item_kind is str else tuple(items)
    if dataclasses.is_dataclass(kind):
        if not isinstance(value, dict):
            raise TypeError("must be an object")
        return _parse(kind, value, f"{where}.", problems)
    if kind is bool:
        if not isinstance(value, bool):
            raise TypeError("must be true or false")
        return value
    if kind is int:
        if not isinstance(value, int) or isinstance(value, bool):
            raise TypeError("must be an integer")
        if meta["min"] is not None and value < meta["min"] or meta["max"] is not None and value > meta["max"]:
            raise ValueError(f"must be within {meta['min']}..{meta['max']}")
    elif kind is str:
        if not isinstance(value, str):
            raise TypeError("must be a string")
        if len(value) > meta["max_len"] or any(ord(ch) < 0x20 for ch in value):
            raise ValueError("too long or has control characters")
    else:  # pragma: no cover - schema error
        raise TypeError(f"unsupported type {kind}")
    if meta["choices"] and value not in meta["choices"]:
        raise ValueError(f"must be one of {', '.join(map(str, meta['choices']))}")
    if meta["check"] is not None:
        meta["check"](value)
    return value


# --- domain rules ----------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Rules:
    rules: tuple[str, ...] = ()  # CustomRuleParser syntax: ||x^, @@||x^, *.x, ! comment
    whitelist: tuple[str, ...] = ()  # domains

    def to_dict(self) -> dict[str, Any]:
        return {"schema": RULES_SCHEMA, "rules": list(self.rules), "whitelist": list(self.whitelist)}

    @classmethod
    def from_dict(cls, document: Any, *, strict: bool = False) -> tuple[Rules, list[str]]:
        problems: list[str] = []
        if not isinstance(document, dict):
            raise SettingsError("rules must be a JSON object")
        schema = document.get("schema")
        if isinstance(schema, int) and not isinstance(schema, bool) and schema > RULES_SCHEMA:
            problems.append(f"schema: {schema} is newer than {RULES_SCHEMA}")
        rules = _rule_lines(document.get("rules", []), "rules", problems, valid_rule)
        whitelist = _rule_lines(document.get("whitelist", []), "whitelist", problems, valid_whitelist_entry)
        if strict and problems:
            raise SettingsError("; ".join(problems[:10]))
        return cls(rules, tuple(d.lower() for d in whitelist)), problems


def valid_rule(text: str) -> bool:
    return parse_rule(text) is not None


def valid_whitelist_entry(text: str) -> bool:
    return is_valid_domain(text)


def _rule_lines(raw: Any, name: str, problems: list[str], valid: Any) -> tuple[str, ...]:
    if not isinstance(raw, list):
        problems.append(f"{name}: must be a list")
        return ()
    if len(raw) > MAX_RULES:
        problems.append(f"{name}: more than {MAX_RULES} entries; the rest were dropped")
        raw = raw[:MAX_RULES]
    kept: dict[str, None] = {}
    bad = 0
    for item in raw:
        if isinstance(item, str) and len(item) <= MAX_RULE_LENGTH and valid(item.strip()):
            kept[item.strip()] = None
        else:
            bad += 1
    if bad:
        problems.append(f"{name}: {bad} invalid entries dropped")
    return tuple(kept)


def rule_counts(rules: Rules) -> dict[str, int]:
    parsed = [parse_rule(r) for r in rules.rules]
    return {
        "block": sum(1 for r in parsed if r and r.rule_type is CustomRuleType.BLOCK),
        "allow": sum(1 for r in parsed if r and r.rule_type is CustomRuleType.ALLOW),
        "whitelist": len(rules.whitelist),
    }


# --- storage ----------------------------------------------------------------------


@dataclass(slots=True)
class Stored:
    value: Any
    problems: list[str]
    source: str  # load_json source: main | backup | missing | invalid
    read_only: bool = False  # written by a newer version: never overwrite


def _load(path: Path, cls: Any) -> Stored:
    def validate(document: Any) -> Any:
        if not isinstance(document, dict):
            raise ValueError("not a JSON object")
        return document

    loaded = load_json(path, validate)
    if loaded.document is None:
        problems = [] if loaded.source == "missing" else [f"{path.name}: {loaded.problem}; defaults used"]
        return Stored(cls(), problems, loaded.source)
    value, problems = cls.from_dict(loaded.document)
    if loaded.source == "backup":
        problems.insert(0, f"{path.name}: {loaded.problem}; restored from the backup")
    read_only = any("is newer than" in p for p in problems)
    return Stored(value, problems, loaded.source, read_only)


def load_settings(path: Path) -> Stored:
    return _load(path, Settings)


def load_rules(path: Path) -> Stored:
    return _load(path, Rules)


def save(path: Path, value: Settings | Rules, stored: Stored | None = None) -> None:
    if stored is not None and stored.read_only:
        raise SettingsError(f"{path.name} was written by a newer version; not overwriting it")
    write_json(path, value.to_dict(), backup=True)
