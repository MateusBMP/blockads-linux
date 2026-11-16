"""What each D-Bus method does, independent of the bus.

:class:`DaemonApi` methods take arguments already checked against the
method's D-Bus signature and size limits (``dbus_service``), and return the
reply's Python value. They raise :class:`ApiError` for anything the caller
got wrong or the daemon cannot do; ``dbus_service`` turns it into a D-Bus
error. Results are versioned JSON (``"api": API_VERSION``).

Setters follow one pattern, serialized by a lock: reload from disk (a hand
edit is not lost), derive the new document, validate it in strict mode
(``common.settings``), write it atomically, reload and run the callbacks.
Nothing here logs a domain name.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import logging
import re
import sqlite3
import time
from collections.abc import Callable
from typing import Any

from .. import __version__
from ..common.dbus_api import API_VERSION, FEATURES, MAX_LOG_PAGE, MAX_PAUSE_SECONDS
from ..common.settings import (
    MAX_CUSTOM_LISTS,
    MAX_RULES,
    Rules,
    Settings,
    SettingsError,
    rule_counts,
)
from ..filters.catalog import CATEGORIES
from ..filters.custom_rules import CustomRuleType, CustomVerdict, entries_match, is_valid_domain, parse_rule
from .health import Health
from .logstore import LogStore
from .pipeline import FIREFOX_CANARY
from .resolver import Forwarder
from .responses import is_invalid_tld
from .state import StateManager, upstream_config
from .upstream.policy import UpstreamPolicy

log = logging.getLogger("blockadsd.api")

PERIOD_DAYS = {"24h": 1, "7d": 7, "4w": 28, "12m": 365}
LOG_FILTER_KEYS = {"verdict", "search", "before_id", "since_ms", "until_ms"}


class ApiError(Exception):
    """``kind``: InvalidArgs | ReadOnly | Unavailable | Failed."""

    def __init__(self, kind: str, message: str) -> None:
        super().__init__(message)
        self.kind = kind
        self.message = message


def invalid(message: str) -> ApiError:
    return ApiError("InvalidArgs", message)


def dumps(document: dict[str, Any]) -> str:
    return json.dumps({"api": API_VERSION, **document}, separators=(",", ":"), ensure_ascii=False)


def loads_object(text: str, what: str) -> dict[str, Any]:
    try:
        value = json.loads(text)
    except ValueError:
        raise invalid(f"{what}: not valid JSON") from None
    if not isinstance(value, dict):
        raise invalid(f"{what}: must be a JSON object")
    return value


def normalize_domain(text: str) -> str:
    """A bare domain (``*.`` prefix allowed), lower case, without the trailing dot."""
    domain = text.strip().rstrip(".").lower()
    if not is_valid_domain(domain) or len(domain) > 253:
        raise invalid("not a valid domain")
    return domain


class DaemonApi:
    def __init__(self, state: StateManager, *, store: LogStore | None, health: Health | None,
                 forwarder: Forwarder | None, upstreams: Callable[[], UpstreamPolicy | None] = lambda: None,
                 bridge: Callable[[], dict[str, Any] | None] = lambda: None,
                 bypass: Callable[[], dict[str, Any]] = lambda: {},
                 clock: Callable[[], float] = time.time) -> None:
        self.state = state
        self.store = store
        self.health = health
        self.forwarder = forwarder
        self.upstreams = upstreams
        self.bridge = bridge
        self.bypass = bypass
        self.clock = clock
        self.started = time.monotonic()
        self._write = asyncio.Lock()

    # --- view ----------------------------------------------------------------

    async def GetStatus(self) -> str:
        state = self.state
        settings = state.settings
        policy = state.policy
        paused = state.paused
        trusted = state.trusted
        status: dict[str, Any] = {
            "version": __version__,
            "uptime_s": int(time.monotonic() - self.started),
            "protection": {
                "state": state.protection_state,
                "paused_until": settings.protection.pause_until if paused else 0,
                "trusted_network": {"uuid": trusted.uuid, "name": trusted.name, "mode": trusted.mode}
                if trusted is not None else None,
            },
            "filters": {
                "lists": len(policy.matcher.list_ids),
                "rules": policy.matcher.rule_count,
                "missing": list(state.missing),
                "generation": state.generation,
                "updated_at": state.manifest.updated_at if state.manifest else 0,
            },
            "custom_rules": rule_counts(state.rules),
            "problems": list(state.problems),
            "read_only": state.settings_read_only or state.rules_read_only,
        }
        upstreams = self.upstreams()
        if upstreams is not None:
            status["upstream"] = upstreams.summary()
            network = upstreams.state
            status["network"] = {
                "source": network.source,
                "uuid": network.primary_uuid,
                "name": network.primary_name,
                "type": network.primary_type,
                "vpn": network.vpn_active,
                "captive": network.captive,
                "metered": network.metered.metered,
                "split_dns": [{"domain": r.domain, "interface": r.interface, "vpn": r.vpn,
                               "servers": [s.address for s in r.servers]}
                              for r in upstreams.router.routes.values()
                              if r.interface][:100],
            }
        if self.forwarder is not None:
            active = self.forwarder.active
            status.setdefault("upstream", {})["active"] = (
                {"label": active.label, "encrypted": active.encrypted, "tier": active.tier} if active else None)
            status["upstream"]["clock_suspect"] = self.forwarder.clock_suspect
        bridge = self.bridge()
        if bridge is not None:
            status["bridge"] = bridge
        bypass = dict(self.bypass())
        if upstreams is not None:
            bypass["resolved_dot"] = upstreams.state.resolved_dot
        bypass["doh_blocklist"] = settings.dns.doh_blocklist
        status["bypass"] = bypass
        alerts: list[dict[str, Any]] = []
        if self.health is not None:
            status["health"] = self.health.summary()
            alerts += [{"kind": a.kind, "message": a.message, "at": int(a.at)} for a in self.health.alerts]
        if self.store is not None:
            status["log"] = {"recording": self.store.recording, "dropped": self.store.dropped}
            alerts += [{"kind": kind, "message": detail, "at": 0} for kind, detail in self.store.alerts.items()]
            status["today"] = await self._read(lambda store: store.totals(_local_midnight(self.clock())), {})
        status["alerts"] = alerts
        return dumps(status)

    async def GetStatistics(self, period: str) -> str:
        if period not in PERIOD_DAYS:
            raise invalid(f"period must be one of {', '.join(PERIOD_DAYS)}")
        days = PERIOD_DAYS[period]
        now = self.clock()

        def read(store: LogStore) -> dict[str, Any]:
            return {"series": store.series(period, now),
                    "totals": store.totals(_local_midnight(now) - (days - 1) * 86400),
                    "reasons": store.reasons(days, now=now)}

        return dumps({"period": period, **await self._read(read, {"series": [], "totals": {}, "reasons": {}})})

    async def GetFilterCatalog(self) -> str:
        state = self.state
        enabled = set(state.settings.filters.enabled)
        lists = state.manifest.lists if state.manifest else {}

        def info(list_id: str) -> dict[str, Any]:
            entry = lists.get(list_id)
            if entry is None:
                return {"downloaded": False, "rules": 0, "changed_at": 0, "checked_at": 0, "error": ""}
            return {"downloaded": bool(entry.artifact), "rules": entry.rules, "changed_at": entry.changed_at,
                    "checked_at": entry.checked_at, "error": entry.error}

        catalog = [{
            "id": e.id, "name": e.name, "description": e.description, "category": e.category, "url": e.url,
            "enabled": e.id in enabled, "default": e.enabled_by_default, "retired": e.retired or "",
            "approx_rules": e.approx_rules, **info(e.id),
        } for e in state.catalog.entries]
        custom = [{"id": c.id, "name": c.name, "urls": list(c.urls), "enabled": c.enabled, **info(c.id)}
                  for c in state.settings.filters.custom]
        filters = state.settings.filters
        return dumps({"revision": state.catalog.revision, "categories": list(CATEGORIES), "lists": catalog,
                      "custom": custom, "update_interval_hours": filters.update_interval_hours,
                      "unmetered_only": filters.unmetered_only})

    async def GetSettings(self) -> str:
        return dumps({"settings": self.state.settings.to_dict(), "read_only": self.state.settings_read_only})

    async def GetRules(self) -> str:
        rules = self.state.rules
        return dumps({"rules": rules.to_dict(), "counts": rule_counts(rules), "read_only": self.state.rules_read_only})

    async def TestDomain(self, domain: str) -> str:
        name = domain.strip().rstrip(".").lower()
        if not name or len(name) > 253 or not is_valid_domain(name):
            raise invalid("not a valid domain")
        policy = self.state.policy

        def result(verdict: str, reason: str, lists: tuple[str, ...] = (), matched: str = "") -> str:
            return dumps({"domain": name, "verdict": verdict, "reason": reason, "lists": list(lists),
                          "matched": matched, "paused": policy.paused})

        if is_invalid_tld(name) or name == FIREFOX_CANARY:
            return result("local", "invalid_tld" if is_invalid_tld(name) else "doh_canary")
        if policy.paused:
            return result("allowed", "trusted_network" if self.state.protection_state == "trusted" else "paused")
        if name in policy.internal_allow:
            return result("allowed", "internal_allow")
        if policy.doh_blocklist and entries_match(name, policy.doh_blocklist):
            return result("blocked", "doh_bypass_protection")
        custom = policy.custom.verdict(name)
        if custom is CustomVerdict.ALLOW:
            return result("allowed", "custom_allow")
        if custom is CustomVerdict.WHITELIST:
            return result("allowed", "whitelist")
        if custom is CustomVerdict.BLOCK:
            return result("blocked", "custom")
        match = policy.matcher.match(name)
        if match.blocked:
            return result("blocked", "filter_list", match.lists, match.matched or "")
        return result("allowed", "")

    # --- view-logs -------------------------------------------------------------

    async def GetQueryLog(self, filter_json: str, after_id: int, limit: int) -> str:
        options = loads_object(filter_json or "{}", "filter")
        unknown = set(options) - LOG_FILTER_KEYS
        if unknown:
            raise invalid(f"filter: unknown keys {', '.join(sorted(unknown))}")
        kwargs: dict[str, Any] = {"after_id": after_id, "limit": max(1, min(limit or 100, MAX_LOG_PAGE))}
        for key in ("before_id", "since_ms", "until_ms"):
            if key in options:
                value = options[key]
                if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                    raise invalid(f"filter: {key} must be a non-negative integer")
                kwargs[key] = value
        for key in ("verdict", "search"):
            if key in options and options[key] is not None:
                if not isinstance(options[key], str) or len(options[key]) > 255:
                    raise invalid(f"filter: {key} must be a short string")
                kwargs[key] = options[key]

        def read(store: LogStore) -> list[dict[str, Any]]:
            try:
                return store.query_log(**kwargs)
            except ValueError as exc:  # unknown verdict
                raise invalid(f"filter: {exc}") from None

        entries = await self._read(read, [])
        return dumps({"entries": entries, "recording": self.store.recording if self.store else False})

    async def GetTopDomains(self, days: int, blocked: bool, limit: int) -> str:
        if not 1 <= days <= 365:
            raise invalid("days must be within 1..365")
        limit = max(1, min(limit or 10, MAX_LOG_PAGE))
        domains = await self._read(lambda store: store.top_domains(days, blocked=blocked, limit=limit), [])
        return dumps({"days": days, "blocked": blocked, "domains": domains})

    # --- tighten -----------------------------------------------------------------

    async def AddBlockRule(self, domain: str) -> None:
        name = normalize_domain(domain)
        await self._edit_rules(lambda rules: _add_rule(rules, f"||{name}^", CustomRuleType.BLOCK, name))

    async def RemoveAllowRule(self, domain: str) -> None:
        name = normalize_domain(domain)

        def edit(rules: Rules) -> Rules:
            rules = _remove_rules(rules, CustomRuleType.ALLOW, name)
            return dataclasses.replace(rules, whitelist=tuple(d for d in rules.whitelist if d != name))

        await self._edit_rules(edit)

    async def EnableFilters(self, ids: list[str]) -> None:
        await self._edit_settings(lambda s: self._set_filters(s, ids, True))

    async def UpdateFiltersNow(self) -> None:
        await asyncio.to_thread(self.state.request_update)

    async def Resume(self) -> None:
        await self._edit_settings(lambda s: _replace(s, "protection", paused=False, pause_until=0))

    async def EnableFeature(self, feature: str) -> None:
        await self._edit_settings(lambda s: _feature(s, feature, True))

    # --- weaken --------------------------------------------------------------------

    async def Pause(self, seconds: int) -> None:
        if seconds > MAX_PAUSE_SECONDS:
            raise invalid(f"pause at most {MAX_PAUSE_SECONDS} seconds (0 = until resumed)")
        until = int(self.clock()) + seconds if seconds else 0
        await self._edit_settings(lambda s: _replace(s, "protection", paused=True, pause_until=until))

    async def DisableFilters(self, ids: list[str]) -> None:
        await self._edit_settings(lambda s: self._set_filters(s, ids, False))

    async def AddAllowRule(self, domain: str) -> None:
        name = normalize_domain(domain)
        await self._edit_rules(lambda rules: _add_rule(rules, f"@@||{name}^", CustomRuleType.ALLOW, name))

    async def RemoveBlockRule(self, domain: str) -> None:
        name = normalize_domain(domain)
        await self._edit_rules(lambda rules: _remove_rules(rules, CustomRuleType.BLOCK, name))

    async def DisableFeature(self, feature: str) -> None:
        await self._edit_settings(lambda s: _feature(s, feature, False))

    async def SetUpstream(self, upstream_json: str) -> None:
        options = loads_object(upstream_json, "upstream")
        known = {"upstream", "fallback", "encrypted_only", "vpn_dns"}
        if set(options) - known:
            raise invalid(f"upstream: unknown keys {', '.join(sorted(set(options) - known))}")

        def edit(settings: Settings) -> Settings:
            dns = {**settings.to_dict()["dns"], **options}
            try:  # what the daemon will build: transport, stamp and preset errors surface here
                upstream_config(dns["upstream"] or [], dns["fallback"], encrypted_only=bool(dns["encrypted_only"]),
                                vpn_dns=bool(dns["vpn_dns"]))
            except (ValueError, TypeError) as exc:
                raise invalid(f"upstream: {exc}") from None
            return _from_dict({**settings.to_dict(), "dns": dns})

        await self._edit_settings(edit)

    async def SetTrustedNetworks(self, networks_json: str) -> None:
        options = loads_object(networks_json, "networks")
        if set(options) != {"networks"}:
            raise invalid('networks: expected {"networks": [...]}')
        await self._edit_settings(lambda s: _from_dict({**s.to_dict(), "trusted_networks": options["networks"]}))

    async def AddCustomFilter(self, filter_json: str) -> str:
        options = loads_object(filter_json, "filter")
        if set(options) - {"name", "urls", "enabled"} or "urls" not in options:
            raise invalid('filter: expected {"name": ..., "urls": [...]}')
        created: list[str] = []

        def edit(settings: Settings) -> Settings:
            custom = settings.filters.custom
            if len(custom) >= MAX_CUSTOM_LISTS:
                raise invalid(f"at most {MAX_CUSTOM_LISTS} custom lists")
            name = options.get("name") or "Custom list"
            slug = re.sub(r"[^a-z0-9]+", "_", str(name).lower()).strip("_")[:40] or "list"
            used = {c.id for c in custom}
            list_id = next(f"custom_{slug}" + (f"_{n}" if n else "") for n in range(len(used) + 1)
                           if f"custom_{slug}" + (f"_{n}" if n else "") not in used)
            item = {"id": list_id, "name": name, "urls": options["urls"], "enabled": options.get("enabled", True)}
            document = settings.to_dict()
            document["filters"]["custom"].append(item)
            new = _from_dict(document)
            created.append(list_id)
            return new

        await self._edit_settings(edit)
        return created[0]

    async def RemoveCustomFilter(self, list_id: str) -> None:
        def edit(settings: Settings) -> Settings:
            custom = settings.filters.custom
            kept = tuple(c for c in custom if c.id != list_id)
            if len(kept) == len(custom):
                raise invalid("no custom list with that id")
            return _replace(settings, "filters", custom=kept)

        await self._edit_settings(edit)

    async def SetLogging(self, enabled: bool, retention_days: int) -> None:
        await self._edit_settings(lambda s: _from_dict(
            {**s.to_dict(), "logging": {"enabled": enabled, "retention_days": retention_days}}))

    async def ClearQueryLog(self) -> None:
        if self.store is None:
            raise ApiError("Unavailable", "the query log is not open")
        await asyncio.wrap_future(self.store.clear_log())

    async def SetBlockedResponse(self, mode: str, ttl: int) -> None:
        def edit(settings: Settings) -> Settings:
            document = settings.to_dict()
            document["dns"].update(block_mode=mode, block_ttl=ttl)
            return _from_dict(document)

        await self._edit_settings(edit)

    async def SetFilterSchedule(self, interval_hours: int, unmetered_only: bool) -> None:
        def edit(settings: Settings) -> Settings:
            document = settings.to_dict()
            document["filters"].update(update_interval_hours=interval_hours, unmetered_only=unmetered_only)
            return _from_dict(document)

        await self._edit_settings(edit)

    async def ImportBackup(self, backup_json: str) -> None:
        backup = loads_object(backup_json, "backup")
        if set(backup) - {"api", "settings", "rules"} or not set(backup) & {"settings", "rules"}:
            raise invalid('backup: expected {"settings": {...}, "rules": {...}}')
        try:  # validate both before writing either
            settings = Settings.from_dict(backup["settings"], strict=True)[0] if "settings" in backup else None
            rules = Rules.from_dict(backup["rules"], strict=True)[0] if "rules" in backup else None
        except SettingsError as exc:
            raise invalid(f"backup: {exc}") from None
        if settings is not None:
            await self._edit_settings(lambda _old: settings)
        if rules is not None:
            await self._edit_rules(lambda _old: rules)

    async def ResetSettings(self) -> None:
        await self._edit_settings(lambda _old: Settings())

    # --- helpers ----------------------------------------------------------------------

    async def _read(self, function: Callable[[LogStore], Any], empty: Any) -> Any:
        if self.store is None:
            return empty
        try:
            return await asyncio.to_thread(function, self.store)
        except sqlite3.OperationalError:  # no database yet (nothing logged), or it is being recreated
            return empty
        except sqlite3.Error as exc:
            raise ApiError("Unavailable", f"query log: {type(exc).__name__}") from None

    async def _edit_settings(self, edit: Callable[[Settings], Settings]) -> None:
        async with self._write:
            await asyncio.to_thread(self.state.check)
            self.state.notify()
            new = edit(self.state.settings)
            new = _from_dict(new.to_dict())  # strict validation of the whole document
            if new == self.state.settings:
                return
            await self._save(self.state.save_settings, new)

    async def _edit_rules(self, edit: Callable[[Rules], Rules]) -> None:
        async with self._write:
            await asyncio.to_thread(self.state.check)
            self.state.notify()
            new = edit(self.state.rules)
            if len(new.rules) > MAX_RULES:
                raise invalid(f"at most {MAX_RULES} rules")
            try:
                new = Rules.from_dict(new.to_dict(), strict=True)[0]
            except SettingsError as exc:
                raise invalid(str(exc)) from None
            if new == self.state.rules:
                return
            await self._save(self.state.save_rules, new)

    async def _save(self, write: Callable[[Any], None], value: Any) -> None:
        try:
            await asyncio.to_thread(write, value)
        except SettingsError as exc:
            raise ApiError("ReadOnly", str(exc)) from None
        except OSError as exc:
            raise ApiError("Failed", f"cannot write: {exc.strerror or type(exc).__name__}") from None
        self.state.notify()

    def _set_filters(self, settings: Settings, ids: list[str], enable: bool) -> Settings:
        catalog = self.state.catalog
        custom_ids = {c.id for c in settings.filters.custom}
        for list_id in ids:
            entry = catalog.get(list_id)
            if entry is None and list_id not in custom_ids:
                raise invalid("unknown list id")
            if enable and entry is not None and entry.retired:
                raise invalid(f"{list_id} is retired: {entry.retired}")
        wanted = set(ids)
        enabled = [i for i in settings.filters.enabled if i not in wanted or enable]
        if enable:
            enabled += [i for i in ids if catalog.get(i) is not None and i not in enabled]
        custom = tuple(dataclasses.replace(c, enabled=enable) if c.id in wanted else c
                       for c in settings.filters.custom)
        return _replace(settings, "filters", enabled=tuple(dict.fromkeys(enabled)), custom=custom)


def _from_dict(document: dict[str, Any]) -> Settings:
    try:
        return Settings.from_dict(document, strict=True)[0]
    except SettingsError as exc:
        raise invalid(str(exc)) from None


def _replace(settings: Settings, section: str, **values: Any) -> Settings:
    return dataclasses.replace(settings, **{section: dataclasses.replace(getattr(settings, section), **values)})


def _feature(settings: Settings, feature: str, value: bool) -> Settings:
    if feature not in FEATURES:
        raise invalid(f"feature must be one of {', '.join(FEATURES)}")
    section, field_name = FEATURES[feature]
    return _replace(settings, section, **{field_name: value})


def _add_rule(rules: Rules, text: str, kind: CustomRuleType, domain: str) -> Rules:
    for existing in rules.rules:
        parsed = parse_rule(existing)
        if parsed is not None and parsed.rule_type is kind and parsed.domain == domain:
            return rules
    return dataclasses.replace(rules, rules=rules.rules + (text,))


def _remove_rules(rules: Rules, kind: CustomRuleType, domain: str) -> Rules:
    def keep(text: str) -> bool:
        parsed = parse_rule(text)
        return parsed is None or parsed.rule_type is not kind or parsed.domain != domain

    return dataclasses.replace(rules, rules=tuple(r for r in rules.rules if keep(r)))


def _local_midnight(now: float) -> float:
    t = time.localtime(now)
    return time.mktime((t.tm_year, t.tm_mon, t.tm_mday, 0, 0, 0, 0, 0, -1))

