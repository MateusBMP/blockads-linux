"""Import a blockads-android settings backup (``blockads_settings.json``).

Port of what upstream's ``utils/SettingsBackupManager.kt`` restores
(revision fc95d66a), mapped onto this port's settings and rules:

* **version 2** (current Android): the settings live in ``configProfiles``,
  as the "unified configuration profile" text of
  ``ProfileUnifiedConfigHelper.generateFullProfile``. The active profile (or
  the first) is read: ``[general]`` (SafeSearch, YouTube Restricted, daily
  summary, milestones, theme, language), ``[dns]`` (``server = ...``; the
  first is the upstream, the second the fallback), ``[filter_local]``
  (``host-suffix, d, direct`` = whitelist; ``host-suffix``/``host-wildcard,
  d, reject`` = block) and ``[filter_remote]`` (list URLs);
* **version 1** (legacy): flat fields ``upstreamDns``, ``fallbackDns``,
  ``dnsResponseType``, ``filterLists``, ``whitelistDomains``,
  ``blocklistDomains``, ``customRules``, ...

Like Android's import it *adds* rules, whitelist entries and lists to what
is there, and replaces the DNS server and the switches it carries.

Filter lists are matched to this catalog by URL, then by name (Android
ships the same catalog). Other https URLs become custom lists. Android's
own servers are never contacted: a URL that is not the list's original one
is matched by name or dropped.

Not ported, so reported and skipped: per-app whitelist and firewall rules,
auto-reconnect, the DNS exclusion list, and inactive profiles.

The result is a backup document for ``ImportBackup`` plus the GUI
preferences it carries, and a report of what was done (no names).
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from typing import Any

from ..filters.catalog import Catalog, load_bundled_catalog, validate_list_url
from .settings import Rules, Settings, valid_rule, valid_whitelist_entry

#: Android ``DnsProviders`` by primary IP -> this port's preset (``data/entities/DnsProvider.kt``).
PROVIDERS_BY_IP = {
    "0.0.0.0": "system",
    "9.9.9.9": "quad9",
    "94.140.14.14": "adguard",
    "1.1.1.1": "cloudflare",
    "1.1.1.3": "cloudflare_family",
    "8.8.8.8": "google",
    "208.67.222.222": "opendns",
    "208.67.222.123": "opendns_family",
    "185.250.250.61": "dnsbunker",
}
BLOCK_MODES = {"custom_ip": "null_ip", "nxdomain": "nxdomain", "refused": "refused"}
THEMES = {"system": "system", "light": "light", "dark": "dark", "oled": "black"}
LANGUAGES = {"system": "system", "en": "en", "pt-BR": "pt_BR", "pt_BR": "pt_BR"}
_COMMENT = ("#", ";", "//")
MAX_INPUT = 4 * 1024 * 1024


class AndroidImportError(ValueError):
    pass


@dataclass
class ImportResult:
    backup: dict[str, Any]  # {"settings": ..., "rules": ...} for ImportBackup
    prefs: dict[str, Any] = field(default_factory=dict)  # GUI preferences (theme, language, notifications)
    report: dict[str, int] = field(default_factory=dict)  # counts: what was imported and skipped
    problems: list[str] = field(default_factory=list)


def is_android_backup(document: Any) -> bool:
    """An Android backup, not one of ours (``{"settings": ..., "rules": ...}``)."""
    if not isinstance(document, dict) or {"settings", "rules"} & set(document):
        return False
    return bool({"configProfiles", "upstreamDns", "filterLists", "whitelistDomains", "blocklistDomains",
                 "customRules"} & set(document))


def load(text: str | bytes) -> dict[str, Any]:
    if len(text) > MAX_INPUT:
        raise AndroidImportError("the backup is too large")
    try:
        document = json.loads(text)
    except ValueError:
        raise AndroidImportError("not a JSON file") from None
    if not is_android_backup(document):
        raise AndroidImportError("not a BlockAds for Android backup")
    return document


# --- profile text (version 2) ---------------------------------------------------


def _sections(content: str) -> dict[str, list[str]]:
    """Section name (lower case) -> its stripped, non-empty lines (comments kept)."""
    sections: dict[str, list[str]] = {}
    current = None
    for raw in content.splitlines():
        line = raw.strip()
        if line.startswith("[") and line.endswith("]"):
            current = sections.setdefault(line[1:-1].strip().lower(), [])
        elif current is not None and line:
            current.append(line)
    return sections


def _is_comment(line: str) -> bool:
    return line.startswith(_COMMENT)


def _key_values(lines: list[str]) -> dict[str, str]:
    result = {}
    for line in lines:
        if not _is_comment(line) and "=" in line:
            key, value = line.split("=", 1)
            result[key.strip().lower()] = value.strip()
    return result


def _bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in ("true", "false"):
        return value.strip().lower() == "true"
    return None


@dataclass
class _Parsed:
    general: dict[str, Any] = field(default_factory=dict)
    servers: list[str] = field(default_factory=list)
    block_mode: str | None = None
    whitelist: list[str] = field(default_factory=list)
    rules: list[str] = field(default_factory=list)
    lists: list[tuple[str, str]] = field(default_factory=list)  # (name or tag, url)
    disabled: int = 0
    apps: int = 0
    firewall: int = 0


def _parse_profile(content: str, parsed: _Parsed) -> None:
    sections = _sections(content)
    general = _key_values(sections.get("general", []))
    for key in ("safe_search", "youtube_restricted", "daily_summary", "milestone_notifications"):
        value = _bool(general.get(key))
        if value is not None:
            parsed.general[key] = value
    for key in ("theme", "language"):
        if general.get(key):
            parsed.general[key] = general[key]
    for line in sections.get("dns", []):
        if _is_comment(line):
            continue
        if "=" in line:
            key, value = line.split("=", 1)
            if key.strip().lower() == "server" and value.strip():
                parsed.servers.append(value.strip())
        else:
            parsed.servers.append(line)
    for line in sections.get("filter_local", []):
        if _is_comment(line):
            parts = [p.strip() for p in line.lstrip("#;/").split(",")]
            if len(parts) >= 3:
                parsed.disabled += 1
            continue
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 3:
            continue
        kind, domain, policy = parts[0].upper(), parts[1].lower(), parts[2].upper()
        if kind not in ("HOST-SUFFIX", "HOST", "HOST-WILDCARD", "DOMAIN-SUFFIX", "DOMAIN") or not domain:
            continue  # ip-cidr and the like: not DNS rules
        if policy == "DIRECT":
            parsed.whitelist.append(domain)
        elif policy == "REJECT":
            parsed.rules.append(f"||{domain}^")
    for line in sections.get("filter_remote", []):
        if _is_comment(line):
            continue
        parts = [p.strip() for p in line.split(",")]
        url, tag = parts[0], ""
        for part in parts[1:]:
            if "=" in part:
                key, value = part.split("=", 1)
                if key.strip().lower() == "tag":
                    tag = value.strip()
        if url.startswith(("http://", "https://")):
            parsed.lists.append((tag, url))
    parsed.apps += sum(1 for line in sections.get("app_whitelist", []) if not _is_comment(line))
    parsed.firewall += sum(1 for line in sections.get("firewall", []) if not _is_comment(line))


def _parse_legacy(document: dict[str, Any], parsed: _Parsed) -> None:
    for source, key in (("safeSearchEnabled", "safe_search"), ("youtubeRestrictedMode", "youtube_restricted"),
                        ("dailySummaryEnabled", "daily_summary"),
                        ("milestoneNotificationsEnabled", "milestone_notifications")):
        value = _bool(document.get(source))
        if value is not None:
            parsed.general.setdefault(key, value)
    for source, key in (("themeMode", "theme"), ("appLanguage", "language")):
        if isinstance(document.get(source), str) and document[source]:
            parsed.general.setdefault(key, document[source])
    if not parsed.servers:
        parsed.servers = [s.strip() for s in (document.get("upstreamDns"), document.get("fallbackDns"))
                          if isinstance(s, str) and s.strip()]
    mode = document.get("dnsResponseType")
    if isinstance(mode, str) and mode in BLOCK_MODES:
        parsed.block_mode = BLOCK_MODES[mode]
    for item in _list(document.get("filterLists")):
        if isinstance(item, dict) and isinstance(item.get("url"), str):
            if item.get("isEnabled", True) is False:
                continue
            parsed.lists.append((str(item.get("name", "")), item["url"].strip()))
    parsed.whitelist += [d.strip().lower() for d in _list(document.get("whitelistDomains")) if isinstance(d, str)]
    parsed.rules += [f"||{d.strip().lower()}^" for d in _list(document.get("blocklistDomains"))
                     if isinstance(d, str) and d.strip()]
    parsed.rules += [r.strip() for r in _list(document.get("customRules")) if isinstance(r, str) and r.strip()]
    parsed.apps += len(_list(document.get("whitelistedApps")))
    parsed.firewall += len(_list(document.get("firewallRules")))


def _list(value: Any) -> list[Any]:
    return value[:100_000] if isinstance(value, list) else []


def _active_profile(document: dict[str, Any]) -> tuple[str | None, int]:
    profiles = [p for p in _list(document.get("configProfiles")) if isinstance(p, dict)
                and isinstance(p.get("content"), str)]
    if not profiles:
        return None, 0
    active = next((p for p in profiles if p.get("isActive") is True), profiles[0])
    return active["content"], len(profiles) - 1


# --- mapping ---------------------------------------------------------------------


def _upstream_spec(server: str) -> str | None:
    """An Android server string -> one of our upstream texts (preset, URL or udp://IP)."""
    if server.startswith(("https://", "tls://", "sdns://")):
        return server  # DoQ/DoH3 (quic://, h3://) are not supported: skipped
    try:
        address = ipaddress.ip_address(server)
    except ValueError:
        return None
    return f"udp://[{address}]" if address.version == 6 else f"udp://{address}"


def _tag(name: str) -> str:
    """Android's profile tag for a list name (``[^a-zA-Z0-9_-]`` -> ``_``, trimmed)."""
    return re.sub(r"[^a-zA-Z0-9_-]", "_", name).strip("_").lower()


def _dedupe(items: list[str]) -> list[str]:
    return list(dict.fromkeys(items))


def convert(document: dict[str, Any], settings: dict[str, Any], rules: dict[str, Any],
            catalog: Catalog | None = None) -> ImportResult:
    """Merge an Android backup into the current settings and rules (both as the daemon returns them)."""
    catalog = catalog or load_bundled_catalog()
    parsed = _Parsed()
    report: dict[str, int] = {}
    content, inactive = _active_profile(document)
    if content is not None:
        _parse_profile(content, parsed)
    if document.get("version", 1) == 1 or content is None:
        _parse_legacy(document, parsed)
    if inactive:
        report["profiles_skipped"] = inactive

    current, problems = Settings.from_dict(settings)
    out = current.to_dict()
    dns = out["dns"]
    if parsed.servers:
        first = parsed.servers[0]
        preset = PROVIDERS_BY_IP.get(first)
        if preset is not None:
            dns["upstream"], dns["fallback"] = [preset], None
            if preset == "system":
                dns["encrypted_only"] = False
            report["dns"] = 1
        elif (spec := _upstream_spec(first)) is not None:
            dns["upstream"] = [spec]
            if spec.startswith("udp://"):
                dns["encrypted_only"] = False  # plain DNS cannot be "encrypted only"
            second = _upstream_spec(parsed.servers[1]) if len(parsed.servers) > 1 else None
            dns["fallback"] = [second] if second and not dns["encrypted_only"] else None
            report["dns"] = 1
        else:
            report["dns_skipped"] = 1
    if parsed.block_mode:
        dns["block_mode"] = parsed.block_mode
    for source, key in (("safe_search", "safesearch"), ("youtube_restricted", "youtube_restricted")):
        if source in parsed.general:
            dns[key] = parsed.general[source]

    by_url = {e.url: e.id for e in catalog.entries if not e.retired}
    by_name = {e.name.strip().lower(): e.id for e in catalog.entries if not e.retired}
    by_tag = {_tag(e.name): e.id for e in catalog.entries if not e.retired}
    enabled = list(out["filters"]["enabled"])
    custom = list(out["filters"]["custom"])
    known_urls = {u for c in custom for u in c["urls"]}
    for name, url in parsed.lists:
        list_id = by_url.get(url) or by_name.get(name.strip().lower()) or by_tag.get(_tag(name) if name else "")
        if list_id:
            if list_id not in enabled:
                enabled.append(list_id)
                report["lists"] = report.get("lists", 0) + 1
            continue
        try:
            validate_list_url(url)
        except ValueError:
            report["lists_skipped"] = report.get("lists_skipped", 0) + 1
            continue
        if url in known_urls or len(custom) >= 50:
            continue
        known_urls.add(url)
        slug = re.sub(r"[^a-z0-9]+", "_", (name or "list").lower()).strip("_")[:40] or "list"
        used = {c["id"] for c in custom}
        list_id = next(f"custom_{slug}" + (f"_{n}" if n else "") for n in range(len(used) + 1)
                       if f"custom_{slug}" + (f"_{n}" if n else "") not in used)
        custom.append({"id": list_id, "name": (name or "Imported list")[:200], "urls": [url], "enabled": True})
        report["custom_lists"] = report.get("custom_lists", 0) + 1
    out["filters"]["enabled"], out["filters"]["custom"] = enabled, custom

    new_settings, settings_problems = Settings.from_dict(out)
    problems += settings_problems

    old_rules, rule_problems = Rules.from_dict(rules)
    problems += rule_problems
    candidates, whites = _dedupe(parsed.rules), _dedupe(parsed.whitelist)
    added_rules = [r for r in candidates if valid_rule(r) and r not in old_rules.rules]
    added_white = [d for d in whites if valid_whitelist_entry(d) and d not in old_rules.whitelist]
    skipped = (sum(not valid_rule(r) for r in candidates)
               + sum(not valid_whitelist_entry(d) for d in whites))
    new_rules = Rules(old_rules.rules + tuple(added_rules), old_rules.whitelist + tuple(added_white))
    if added_rules:
        report["rules"] = len(added_rules)
    if added_white:
        report["whitelist"] = len(added_white)
    if skipped > 0:
        report["rules_skipped"] = skipped
    for key, count in (("disabled_rules_skipped", parsed.disabled), ("apps_skipped", parsed.apps),
                       ("firewall_skipped", parsed.firewall)):
        if count:
            report[key] = count

    prefs: dict[str, Any] = {}
    general = parsed.general
    if "daily_summary" in general:
        prefs["notify_daily_summary"] = general["daily_summary"]
    if "milestone_notifications" in general:
        prefs["notify_milestones"] = general["milestone_notifications"]
    if general.get("theme") in THEMES:
        prefs["theme"] = THEMES[general["theme"]]
    if general.get("language") in LANGUAGES:
        prefs["language"] = LANGUAGES[general["language"]]

    backup = {"settings": new_settings.to_dict(), "rules": new_rules.to_dict()}
    return ImportResult(backup, prefs, report, problems)
