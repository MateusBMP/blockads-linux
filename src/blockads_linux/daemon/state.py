"""The daemon's view of its state directory.

:class:`StateManager` turns ``settings.json``, ``rules.json`` and the
filter manifest into the pipeline's :class:`~.pipeline.Policy` and the
upstream configuration, and keeps them current: every ``interval`` seconds
it stats the three files and reloads what changed (the manifest watcher is
"stat every 5 s, then an atomic matcher swap"). The D-Bus setters write
through :meth:`StateManager.save_settings` / :meth:`save_rules`, which reload
at once; hand edits are picked up by the poll.

* Artifacts are opened once and shared between matcher generations. An old
  matcher is never closed: queries in flight may still hold it, and its
  mappings go away with the last reference.
* The internal allowlist holds the hosts of the enabled lists' URLs (so the
  updater can always reach them) and NetworkManager's connectivity-check host.
* When an enabled list has no artifact yet, ``update.request`` is touched so
  ``blockads-update.path`` starts an update (once per set of missing lists).
* Pause: ``protection.paused`` with an optional ``pause_until`` (Unix time);
  the pause ends by itself when that time passes.
* Trusted networks: when the primary NetworkManager connection
  (:meth:`StateManager.set_network`) is a trusted network in "pause" mode,
  the policy forwards unfiltered like a pause. "network_dns" mode is the
  upstream policy's (``PolicyConfig.network_dns_uuids``).
"""

from __future__ import annotations

import asyncio
import logging
import os
import threading
import time
from collections.abc import Callable
from pathlib import Path
from urllib.parse import urlsplit

from ..common.paths import Paths
from ..common.settings import Rules, Settings, SettingsError, TrustedNetwork, load_rules, load_settings, save
from ..filters.artifact import ArtifactError, LoadedArtifact
from ..filters.catalog import CATEGORIES, Catalog, load_bundled_catalog, load_doh_blocklist
from ..filters.custom_rules import CustomRuleSet, parse_rules
from ..filters.matcher import FilterList, FilterMatcher
from ..updater.manifest import Manifest, load_manifest
from .pipeline import Policy, PreferredIP
from .responses import BlockMode
from .upstream.policy import PolicyConfig
from .upstream.presets import DEFAULT_PRESET, PRESETS, UpstreamSpec, parse_upstream

log = logging.getLogger("blockadsd.state")


def upstream_config(texts: list[str] | tuple[str, ...], fallback: list[str] | tuple[str, ...] | None, *,
                    encrypted_only: bool = False, vpn_dns: bool = True,
                    network_dns_uuids: frozenset[str] = frozenset()) -> PolicyConfig:
    """PolicyConfig from upstream texts (presets, stamps, URLs); raises ValueError.

    ``fallback`` None means the presets' plain DNS plus the network tier;
    ``["none"]`` or ``()`` means no fallback; a list replaces the fallback and
    turns the network tier off.
    """
    texts = list(texts) or [DEFAULT_PRESET]
    if "system" in texts and len(texts) > 1:
        raise ValueError("'system' cannot be combined with other upstreams")
    system = texts == ["system"]
    configured = [] if system else [spec for text in texts for spec in parse_upstream(text)]
    preset_plain = tuple(spec for text in texts if text in PRESETS for spec in PRESETS[text].specs("udp"))
    if fallback is None:
        fallback_specs: tuple[UpstreamSpec, ...] = preset_plain
    elif list(fallback) in ([], ["none"]):
        fallback_specs = ()
    else:
        fallback_specs = tuple(spec for text in fallback for spec in parse_upstream(text))
    return PolicyConfig(
        configured=tuple(configured),
        fallback=() if encrypted_only else fallback_specs,
        rescue=preset_plain if encrypted_only else (),
        system=system,
        encrypted_only=encrypted_only,
        vpn_dns=vpn_dns,
        network_tier=fallback is None,
        network_dns_uuids=network_dns_uuids,
    )


def settings_upstream_config(settings: Settings) -> tuple[PolicyConfig, str]:
    """The settings' upstream config, or the default one and the reason it was refused."""
    dns = settings.dns
    trusted = frozenset(n.uuid for n in settings.trusted_networks if n.mode == "network_dns")
    try:
        return upstream_config(dns.upstream, dns.fallback, encrypted_only=dns.encrypted_only,
                               vpn_dns=dns.vpn_dns, network_dns_uuids=trusted), ""
    except ValueError as exc:
        return (upstream_config([DEFAULT_PRESET], None, vpn_dns=dns.vpn_dns, network_dns_uuids=trusted),
                f"dns: {exc}; using {DEFAULT_PRESET}")


def list_hosts(settings: Settings, catalog: Catalog) -> frozenset[str]:
    urls = [e.url for e in (catalog.get(i) for i in settings.filters.enabled) if e is not None]
    urls += [url for custom in settings.filters.custom if custom.enabled for url in custom.urls]
    return frozenset(h.lower() for h in (urlsplit(u).hostname for u in urls) if h)


def enabled_ids(settings: Settings, catalog: Catalog) -> list[str]:
    ids = [i for i in settings.filters.enabled if (e := catalog.get(i)) is not None and not e.retired]
    return ids + [c.id for c in settings.filters.custom if c.enabled]


def _signature(path: Path) -> tuple[int, int, int] | None:
    try:
        st = os.stat(path)
    except OSError:
        return None
    return st.st_ino, st.st_mtime_ns, st.st_size


class StateManager:
    def __init__(self, paths: Paths, *, catalog: Catalog | None = None, clock: Callable[[], float] = time.time,
                 on_policy: Callable[[Policy], None] | None = None,
                 on_upstreams: Callable[[PolicyConfig], None] | None = None,
                 on_settings: Callable[[Settings], None] | None = None) -> None:
        self.paths = paths
        self.catalog = catalog or load_bundled_catalog()
        self.clock = clock
        self.on_policy = on_policy
        self.on_upstreams = on_upstreams
        self.on_settings = on_settings
        self.settings = Settings()
        self.rules = Rules()
        self.manifest: Manifest | None = None
        self.policy = Policy()
        self.upstream_config, _ = settings_upstream_config(self.settings)
        self.problems: list[str] = []  # for the status API (no names)
        self.missing: tuple[str, ...] = ()  # enabled lists without an artifact
        self.extra_allow: frozenset[str] = frozenset()  # e.g. NetworkManager's check host
        self._artifacts: dict[str, LoadedArtifact] = {}
        self._signatures: dict[str, tuple[int, int, int] | None] = {}
        self._matcher = FilterMatcher()
        self._custom = CustomRuleSet()
        self._requested: tuple[str, ...] = ()
        self._paused_now = False
        self.network_uuid = ""  # the primary NetworkManager connection
        self._dirty: set[str] = set()  # callbacks owed: "policy", "upstreams", "settings", "filters"
        self.settings_read_only = False  # written by a newer version
        self.rules_read_only = False
        self.generation = 0  # manifest generation (FiltersUpdated)
        self.on_filters: Callable[[int], None] | None = None
        self._lock = threading.Lock()  # check() runs in worker threads

    # --- loading ----------------------------------------------------------------

    def load(self) -> Policy:
        """Read everything (startup)."""
        self._signatures = {name: _signature(path) for name, path in self._files().items()}
        self._load_settings()
        self._load_rules()
        self._load_manifest()
        self._rebuild()
        self.notify()
        return self.policy

    def check(self) -> bool:
        """Reload whatever changed on disk; True if the policy was rebuilt.

        File I/O only: it may run in a worker thread. :meth:`notify` (on the
        event loop) then runs the callbacks.
        """
        with self._lock:
            return self._check()

    def _check(self) -> bool:
        changed = set()
        for name, path in self._files().items():
            signature = _signature(path)
            if signature != self._signatures.get(name):
                self._signatures[name] = signature
                changed.add(name)
        if "settings" in changed:
            self._load_settings()
        if "rules" in changed:
            self._load_rules()
        if changed & {"settings", "manifest"}:
            self._load_manifest()
        paused = self._paused()
        if changed or paused != self._paused_now:
            self._rebuild()
            return True
        return False

    def save_settings(self, settings: Settings) -> None:
        """Write settings (already validated) and reload; file I/O, may run in a thread."""
        with self._lock:
            if self.settings_read_only:
                raise SettingsError("settings.json was written by a newer version; not overwriting it")
            save(self.paths.settings, settings)
            self._check()

    def save_rules(self, rules: Rules) -> None:
        with self._lock:
            if self.rules_read_only:
                raise SettingsError("rules.json was written by a newer version; not overwriting it")
            save(self.paths.rules, rules)
            self._check()

    def request_update(self) -> None:
        """Touch ``update.request`` ("Update now"; blockads-update.path starts the updater)."""
        self._request_update()

    @property
    def paused(self) -> bool:
        """The user's pause (not a trusted network's)."""
        return self._paused_now

    @property
    def trusted(self) -> TrustedNetwork | None:
        """The trusted-network entry of the current primary connection, if any."""
        if not self.network_uuid:
            return None
        return next((n for n in self.settings.trusted_networks if n.uuid == self.network_uuid), None)

    @property
    def protection_state(self) -> str:
        """"paused" (the user's pause), "trusted" (a trusted network in pause mode) or "active"."""
        if self._paused_now:
            return "paused"
        trusted = self.trusted
        return "trusted" if trusted is not None and trusted.mode == "pause" else "active"

    def set_network(self, uuid: str) -> None:
        """The primary connection changed (event loop only)."""
        if uuid != self.network_uuid:
            with self._lock:
                self.network_uuid = uuid
                self._rebuild()
            self.notify()

    def set_extra_allow(self, names: frozenset[str]) -> None:
        if names != self.extra_allow:
            with self._lock:
                self.extra_allow = names
                self._rebuild()
            self.notify()

    def notify(self) -> None:
        """Run the callbacks for what changed since the last call (event loop only)."""
        dirty, self._dirty = self._dirty, set()
        if "settings" in dirty and self.on_settings is not None:
            self.on_settings(self.settings)
        if "upstreams" in dirty and self.on_upstreams is not None:
            self.on_upstreams(self.upstream_config)
        if "policy" in dirty and self.on_policy is not None:
            self.on_policy(self.policy)
        if "filters" in dirty and self.on_filters is not None:
            self.on_filters(self.generation)

    async def watch(self, interval: float = 5.0) -> None:
        while True:
            await asyncio.sleep(interval)
            try:
                await asyncio.to_thread(self.check)
                self.notify()
            except Exception:
                log.exception("state reload failed")

    def _files(self) -> dict[str, Path]:
        return {"settings": self.paths.settings, "rules": self.paths.rules, "manifest": self.paths.manifest}

    def _load_settings(self) -> None:
        stored = load_settings(self.paths.settings)
        self.settings = stored.value
        self.settings_read_only = stored.read_only
        self.problems = [p for p in stored.problems if "unknown field" not in p]
        config, problem = settings_upstream_config(self.settings)
        if problem:
            self.problems.append(problem)
        if config != self.upstream_config:
            self.upstream_config = config
            self._dirty.add("upstreams")
        self._dirty.add("settings")
        for problem in self.problems:
            log.warning("settings: %s", problem)

    def _load_rules(self) -> None:
        stored = load_rules(self.paths.rules)
        self.rules = stored.value
        self.rules_read_only = stored.read_only
        for problem in stored.problems:
            log.warning("rules: %s", problem)
        self._custom = CustomRuleSet.build(parse_rules("\n".join(self.rules.rules)), self.rules.whitelist)

    def _load_manifest(self) -> None:
        self.manifest = load_manifest(self.paths.manifest)
        generation = self.manifest.generation if self.manifest else 0
        if generation != self.generation:
            self.generation = generation
            self._dirty.add("filters")
        lists = []
        used: dict[str, LoadedArtifact] = {}
        missing = []
        for list_id in enabled_ids(self.settings, self.catalog):
            entry = self.manifest.lists.get(list_id) if self.manifest else None
            if entry is None or not entry.artifact:
                missing.append(list_id)
                continue
            artifact = self._artifacts.get(entry.artifact) or used.get(entry.artifact)
            if artifact is None:
                try:
                    artifact = LoadedArtifact.open(self.paths.artifacts / entry.artifact)
                except (OSError, ArtifactError) as exc:
                    log.warning("%s: cannot open its artifact (%s)", list_id, type(exc).__name__)
                    missing.append(list_id)
                    continue
            used[entry.artifact] = artifact
            catalog_entry = self.catalog.get(list_id)
            rank = catalog_entry.category_rank if catalog_entry else CATEGORIES.index("other")
            lists.append(FilterList(list_id, rank, artifact))
        self._artifacts = used  # dropped ones close when the last matcher using them goes away
        self._matcher = FilterMatcher(lists)
        self.missing = tuple(missing)
        log.info("filters: %d lists, %d rules%s", len(lists), self._matcher.rule_count,
                 f"; {len(missing)} not downloaded yet" if missing else "")
        if missing and self.missing != self._requested:
            self._request_update()
        self._requested = self.missing

    def _request_update(self) -> None:
        try:
            self.paths.update_request.touch()
        except OSError as exc:
            log.warning("cannot request a filter update: %s", exc.strerror)

    def _paused(self) -> bool:
        protection = self.settings.protection
        return protection.paused and (not protection.pause_until or self.clock() < protection.pause_until)

    def _trusted_pause(self) -> bool:
        trusted = self.trusted
        return trusted is not None and trusted.mode == "pause"

    def _rebuild(self) -> None:
        dns = self.settings.dns
        self._paused_now = self._paused()
        self.policy = Policy(
            matcher=self._matcher,
            custom=self._custom,
            doh_blocklist=load_doh_blocklist() if dns.doh_blocklist else frozenset(),
            doh_watch=frozenset() if dns.doh_blocklist else load_doh_blocklist(),
            internal_allow=list_hosts(self.settings, self.catalog) | self.extra_allow,
            block_mode=BlockMode(dns.block_mode),
            block_ttl=dns.block_ttl,
            preferred_ip=PreferredIP(dns.preferred_ip),
            safesearch=dns.safesearch,
            youtube_restricted=dns.youtube_restricted,
            cname_check=dns.cname_check,
            paused=self._paused_now or self._trusted_pause(),
            pause_reason="paused" if self._paused_now else "trusted_network",
        )
        self._dirty.add("policy")

