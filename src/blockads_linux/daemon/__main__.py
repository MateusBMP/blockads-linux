"""``blockadsd``: the DNS filter daemon.

Development mode needs no root and touches no firewall::

    python -m blockads_linux.daemon --dev --listen 127.0.0.1:5300 \\
        --list path/to/hosts-or-adblock-list.txt

Without ``--dev`` the daemon adopts the sockets passed by systemd
(``LISTEN_FDS``) and reports ``READY=1``, reads its state directory and
serves the D-Bus API on the system bus (development: ``--dbus session``).
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import hashlib
import logging
import os
import re
import signal
import socket
import sys
import tempfile
import time
from pathlib import Path

from ..common.legal import add_version_option
from ..common.paths import Paths
from ..filters.artifact import ArtifactBuilder, LoadedArtifact
from ..filters.catalog import load_doh_blocklist
from ..filters.custom_rules import CustomRuleSet, parse_rules
from ..filters.matcher import FilterList, FilterMatcher
from ..filters.parser import iter_binary_lines, iter_list_rules
from . import sdnotify
from .api import DaemonApi
from .bridgeacl import BridgeAcl, file_signature, read_bridge_patterns
from .cache import DnsCache
from .dbus_service import DBusService
from .health import FW_STATE_PATH, Health, self_targets, watchdog_interval
from .logstore import LogStore
from .netmon import NetworkMonitor, NetworkState
from .ntpnames import NtpNames
from .preload import preload
from .pipeline import Pipeline, Policy, PreferredIP, QueryEvent
from .resolver import Forwarder
from .responses import BlockMode
from .server import DnsServer, bind_sockets
from .state import StateManager, upstream_config
from .upstream.policy import PolicyConfig, UpstreamPolicy
from .upstream.presets import DEFAULT_PRESET, PRESETS

log = logging.getLogger("blockadsd")

#: systemd FileDescriptorName= values served as loopback DNS.
LOOPBACK_FD_NAMES = frozenset({"dns-v4", "dns-v6"})
#: blockadsd-bridge.socket: served only behind the source ACL.
BRIDGE_FD_NAME = "dns-bridge"


def select_sockets(fds: list[tuple[socket.socket, str]]) -> tuple[list[socket.socket], list[socket.socket]]:
    """``(loopback, bridge)`` sockets; any other one is closed."""
    loopback, bridge = [], []
    for sock, name in fds:
        if name in LOOPBACK_FD_NAMES:
            loopback.append(sock)
        elif name == BRIDGE_FD_NAME:
            bridge.append(sock)
        else:
            log.warning("ignoring unknown systemd socket %r", name)
            sock.close()
    return loopback, bridge


def _listen_address(text: str) -> tuple[str, int]:
    match = re.fullmatch(r"\[([0-9A-Fa-f:.]+)\]:(\d+)|([0-9.]+):(\d+)", text)
    if not match:
        raise argparse.ArgumentTypeError(f"expected ADDR:PORT or [ADDR6]:PORT, got {text!r}")
    host = match.group(1) or match.group(3)
    port = int(match.group(2) or match.group(4))
    if port > 65535:  # 0 picks a free port (tests)
        raise argparse.ArgumentTypeError(f"bad port in {text!r}")
    return host, port


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="blockadsd", description="blockads-linux DNS filter daemon")
    add_version_option(parser, "blockadsd")
    dev = parser.add_argument_group("development mode")
    dev.add_argument("--dev", action="store_true", help="bind our own sockets (needs --listen); for tests only")
    dev.add_argument("--listen", action="append", type=_listen_address, default=[], metavar="ADDR:PORT",
                     help="address to serve DNS on, e.g. 127.0.0.1:5300 (repeatable)")
    dev.add_argument("--list", action="append", default=[], metavar="FILE",
                     help="compile a local filter list file at startup (repeatable)")
    dev.add_argument("--security-list", action="append", default=[], metavar="FILE",
                     help="like --list, but checked and reported first")
    dev.add_argument("--rules", metavar="FILE", help="custom rules file (one rule per line)")
    dev.add_argument("--state-dir", metavar="DIR",
                     help="use this state directory (settings, rules, filters, log) instead of --list/--rules; "
                          "without --dev the daemon always uses $BLOCKADS_STATE_DIR or /var/lib/blockads-linux")
    dev.add_argument("--state-poll", type=float, default=5.0, help=argparse.SUPPRESS)  # tests
    dev.add_argument("--fw-state", help=argparse.SUPPRESS)  # tests: blockads-fw state.json to follow
    dev.add_argument("--bridge-listen", action="append", type=_listen_address, default=[],
                     help=argparse.SUPPRESS)  # tests: a bridge listener behind the source ACL
    dev.add_argument("--health-interval", type=float, default=15.0, help=argparse.SUPPRESS)  # tests
    dev.add_argument("--dbus", metavar="BUS",
                     help="serve the D-Bus API (needs --state-dir) on 'session', 'system' or a bus address; "
                          "without --dev the daemon always uses the system bus")
    dev.add_argument("--dbus-allow-all", action="store_true",
                     help="skip polkit: every caller may do everything (development only)")
    dev.add_argument("--log-queries", action="store_true",
                     help="print every query to stderr (development only: names never go to the journal)")
    dns = parser.add_argument_group("DNS")
    dns.add_argument("--upstream", action="append", default=[], metavar="SPEC",
                     help=f"system, a preset ({', '.join(PRESETS)}), sdns:// stamp, udp://IP[:port], tcp://IP[:port], "
                          f"tls://IP[:port]#name or https://IP[:port]/path#name (default: {DEFAULT_PRESET})")
    dns.add_argument("--fallback", action="append", default=None, metavar="SPEC",
                     help="fallback upstream (default: the preset's plain DNS; 'none' to disable)")
    dns.add_argument("--encrypted-only", action="store_true", help="never use an unencrypted fallback")
    dns.add_argument("--no-vpn-dns", action="store_true",
                     help="do not prefer the DNS of a VPN that owns the default route")
    dns.add_argument("--no-netmon", action="store_true",
                     help="do not read NetworkManager/resolved over D-Bus (use /etc/resolv.conf)")
    dns.add_argument("--block-mode", choices=[m.value for m in BlockMode], default=BlockMode.NULL_IP.value)
    dns.add_argument("--block-ttl", type=int, default=10)
    dns.add_argument("--preferred-ip", choices=[p.value for p in PreferredIP], default=PreferredIP.AUTO.value)
    dns.add_argument("--safesearch", action="store_true")
    dns.add_argument("--youtube-restricted", action="store_true")
    dns.add_argument("--doh-blocklist", action="store_true", help="block the bundled DoH bootstrap names")
    dns.add_argument("--no-cname-check", action="store_true")
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser


def build_policy_config(args: argparse.Namespace) -> PolicyConfig:
    """Upstream choices from the command line (upstream tiers 3 to 6)."""
    try:
        return upstream_config(args.upstream or [DEFAULT_PRESET], args.fallback,
                               encrypted_only=args.encrypted_only, vpn_dns=not args.no_vpn_dns)
    except ValueError as exc:
        raise SystemExit(f"--encrypted-only: {exc}" if args.encrypted_only else str(exc)) from None


def compile_lists(files: list[str], rank: int, directory: Path) -> list[FilterList]:
    lists = []
    for name in files:
        path = Path(name)
        builder = ArtifactBuilder()
        with path.open("rb") as stream:
            builder.add_rules(iter_list_rules(iter_binary_lines(stream)))
        digest = hashlib.sha256(path.read_bytes()).digest()
        info = builder.write(directory, source_sha256=digest, compiled_at=int(time.time()))
        list_id = re.sub(r"[^a-z0-9_]", "_", path.stem.lower())[:80] or "list"
        lists.append(FilterList(list_id, rank, LoadedArtifact.open(directory / info.name)))
        log.info("compiled %s: %d rules", path.name, info.block_count)
    return lists


def build_policy(args: argparse.Namespace, artifacts: Path) -> Policy:
    lists = compile_lists(args.security_list, 0, artifacts) + compile_lists(args.list, 1, artifacts)
    custom = CustomRuleSet()
    if args.rules:
        custom = CustomRuleSet.build(parse_rules(Path(args.rules).read_text("utf-8")))
    return Policy(
        matcher=FilterMatcher(lists),
        custom=custom,
        doh_blocklist=load_doh_blocklist() if args.doh_blocklist else frozenset(),
        block_mode=BlockMode(args.block_mode),
        block_ttl=args.block_ttl,
        preferred_ip=PreferredIP(args.preferred_ip),
        safesearch=args.safesearch,
        youtube_restricted=args.youtube_restricted,
        cname_check=not args.no_cname_check,
    )


def _print_event(event: QueryEvent) -> None:
    import dns.rdatatype

    detail = f" ({event.reason})" if event.reason else ""
    tier = f" [{event.tier}]" if event.tier and event.tier != "configured" else ""
    source = f" via {event.upstream}{tier}" + (" [cache]" if event.cached else "") if event.upstream else ""
    answers = f" -> {','.join(event.answers)}" if event.answers else ""
    print(f"{event.verdict.value:<9} {dns.rdatatype.to_text(event.qtype):<5} {event.name}{detail}{source}{answers}"
          f" {event.elapsed_ms:.1f}ms", file=sys.stderr, flush=True)


def _log_upstreams(upstreams: UpstreamPolicy) -> None:
    summary = upstreams.summary()
    log.info("network: %s%s%s, %d routed domains", summary["source"], ", captive portal" if summary["captive"] else "",
             ", VPN DNS" if summary["vpn"] else "", summary["routes"])
    for tier in upstreams.captive_tiers or upstreams.tiers:
        log.info("%s upstreams: %s", tier.name, ", ".join(u.label for u in tier.upstreams))
    for tier in upstreams.rescue:
        log.info("%s upstreams: %s", tier.name, ", ".join(u.label for u in tier.upstreams))


async def serve(args: argparse.Namespace, sockets: list, policy: Policy, state: StateManager | None = None,
                bridge_sockets: list | None = None) -> int:
    """Serve until SIGTERM. With ``state``, settings, rules, filters and the log come from the state directory.

    ``bridge_sockets`` (``dns-bridge``) answer only the sources ``BridgeAcl`` allows.
    """
    config = state.upstream_config if state is not None else build_policy_config(args)
    current = {"upstreams": UpstreamPolicy(config, NetworkState("none"))}
    forwarder = Forwarder(policy=current["upstreams"], ntp_names=_ntp_matcher(config), cache=DnsCache())
    pipeline = Pipeline(forwarder, policy)
    store: LogStore | None = None
    if state is not None:
        logging_settings = state.settings.logging
        store = LogStore(state.paths.db, retention_days=logging_settings.retention_days,
                         recording=logging_settings.enabled)
        store.start()

    def on_event(event: QueryEvent) -> None:
        if store is not None:
            store.submit(event)
        if args.log_queries:
            _print_event(event)

    server = DnsServer(pipeline, on_event=on_event if store is not None or args.log_queries else None)
    background: set[asyncio.Task] = set()
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signum in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(signum, stop.set)
    # Development mode has no firewall rules and runs from a source tree:
    # no interception probe and no install check (the watchdog follows systemd).
    fw_state = Path(args.fw_state) if args.fw_state else (None if args.dev else FW_STATE_PATH)
    service: DBusService | None = None

    def on_alert(alert) -> None:
        if service is not None:
            service.alert(alert.kind, alert.message)

    health = Health(lambda: self_targets(server.probe_addresses), fw_state_path=fw_state,
                    fw_interval=args.health_interval, watchdog=watchdog_interval(), install_check=not args.dev,
                    on_alert=on_alert)
    acl: BridgeAcl | None = None
    if bridge_sockets:
        bridge_state = fw_state or FW_STATE_PATH
        acl = BridgeAcl(patterns=lambda: read_bridge_patterns(bridge_state),
                        state_signature=lambda: file_signature(bridge_state))

    def bridge_summary() -> dict | None:
        if acl is None:
            return None
        return {**acl.summary(), "dropped": server.stats.acl_dropped}

    bus = dbus_bus(args)
    if state is not None and bus is not None:
        api = DaemonApi(state, store=store, health=health, forwarder=forwarder,
                        upstreams=lambda: current["upstreams"], bridge=bridge_summary,
                        bypass=lambda: {"doh_lookups": pipeline.doh_lookups, "doh_last": int(pipeline.doh_last)})
        service = DBusService(api, bus=bus, allow_all=args.dbus_allow_all, on_firewall_reload=health.poke,
                              status_summary=lambda: {"protection": state.protection_state})

    async def swap_upstreams(new_config: PolicyConfig) -> None:
        old = current["upstreams"]
        new = current["upstreams"] = UpstreamPolicy(new_config, old.state)
        forwarder.policy = new
        forwarder.ntp_names = _ntp_matcher(new_config)
        forwarder.forget(old.upstreams())
        for upstream in old.upstreams():
            await upstream.close()
        await forwarder.reset()
        log.info("upstream settings changed")
        _log_upstreams(new)
        if service is not None:
            service.status_changed()

    async def network_changed(network: NetworkState, reason: str) -> None:
        # On resume or a network change, reload the routes,
        # drop connection pools, reset breakers and flush the cache.
        upstreams = current["upstreams"]
        stale = upstreams.apply(network)
        forwarder.forget(stale)
        for upstream in stale:
            await upstream.close()
        await forwarder.reset()
        if state is not None:
            state.set_extra_allow(frozenset({network.connectivity_check_host} - {""}))
            state.set_network(network.primary_uuid, network.primary_bssid)
        log.info("%s: upstream policy reloaded", "resume" if reason == "resume" else "network change")
        _log_upstreams(upstreams)
        health.poke()

    def spawn(coroutine) -> None:
        task = asyncio.get_running_loop().create_task(coroutine)
        background.add(task)
        task.add_done_callback(background.discard)

    if state is not None:
        def apply_logging(settings) -> None:
            store.recording = settings.logging.enabled
            store.retention_days = settings.logging.retention_days

        def apply_policy(new_policy: Policy) -> None:
            pipeline.policy = new_policy
            if service is not None:
                service.status_changed()

        state.on_policy = apply_policy
        if service is not None:
            state.on_filters = service.filters_updated
        state.on_upstreams = lambda new_config: spawn(swap_upstreams(new_config))
        state.on_settings = apply_logging
        spawn(state.watch(args.state_poll))

    monitor = None if args.no_netmon else NetworkMonitor(network_changed)
    if monitor is not None:
        spawn(monitor.run())
        # Start with the real network state when the bus answers quickly; never block startup on it.
        with contextlib.suppress(TimeoutError):
            async with asyncio.timeout(2):
                await monitor.ready.wait()
    if service is not None:
        spawn(service.run())
    await server.start(sockets)
    if acl is not None:
        await server.start(bridge_sockets, acl=acl.allows)
        acl.refresh()
        log.info("bridge listener: %s", ", ".join(acl.interfaces) or "no matching interface yet")
    for kind, address in server.addresses:
        log.info("serving DNS on %s %s", kind, address)
    if monitor is None or current["upstreams"].state.source == "none":
        _log_upstreams(current["upstreams"])
    if forwarder.ntp_names is not None:
        log.info("clock rescue: plain DNS for NTP names only")
    sdnotify.notify("READY=1")
    health_task = asyncio.create_task(health.run())
    stop_task = asyncio.create_task(stop.wait())
    await asyncio.wait({health_task, stop_task}, return_when=asyncio.FIRST_COMPLETED)
    code = health.exit_code or 0
    for task in (health_task, stop_task):
        task.cancel()
    await asyncio.gather(health_task, stop_task, return_exceptions=True)
    sdnotify.notify("STOPPING=1")
    log.info("stopping" if not code else f"stopping (exit {code}: {health.exit_reason})")
    for task in list(background):
        task.cancel()
    await asyncio.gather(*background, return_exceptions=True)
    await server.close()
    await forwarder.close()
    if store is not None:
        await asyncio.to_thread(store.stop)
    return code


def dbus_bus(args: argparse.Namespace) -> str | None:
    """The bus for the D-Bus API: the system bus in production, ``--dbus`` in development."""
    if not args.dev:
        return "SYSTEM"
    if args.dbus is None:
        return None
    return {"session": "SESSION", "system": "SYSTEM"}.get(args.dbus, args.dbus)


def _ntp_matcher(config: PolicyConfig):
    return NtpNames.load().matches if config.encrypted_only else None


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(levelname)s %(name)s: %(message)s")
    # httpx logs every request at INFO, and its HTTP/2 stack logs headers at
    # DEBUG: keep them out of the journal.
    for noisy in ("httpx", "httpcore", "hpack", "h2"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    if args.dev:
        if not args.listen:
            print("blockadsd: --dev needs at least one --listen ADDR:PORT", file=sys.stderr)
            return 2
        sockets = [sock for host, port in args.listen for sock in bind_sockets(host, port)]
        bridge_sockets = [sock for host, port in args.bridge_listen for sock in bind_sockets(host, port)]
    else:
        preload()  # before anything can be upgraded under us (health's install check)
        if (args.listen or args.list or args.security_list or args.rules or args.log_queries or args.state_dir
                or args.dbus or args.dbus_allow_all or args.bridge_listen):
            print("blockadsd: --listen, --list, --rules, --state-dir, --dbus, --dbus-allow-all and --log-queries"
                  " need --dev", file=sys.stderr)
            return 2
        sockets, bridge_sockets = select_sockets(sdnotify.listen_fds())
        if not sockets:
            print("blockadsd: no sockets from systemd; for development use --dev --listen ADDR:PORT",
                  file=sys.stderr)
            return 2
    if args.dev and args.dbus and args.state_dir is None:
        print("blockadsd: --dbus needs --state-dir", file=sys.stderr)
        return 2
    if args.state_dir is not None or not args.dev:
        if args.list or args.security_list or args.rules:
            print("blockadsd: --list, --security-list and --rules are for --dev without --state-dir",
                  file=sys.stderr)
            return 2
        os.umask(0o077)
        paths = Paths(Path(args.state_dir)) if args.state_dir else Paths.default()
        paths.ensure()
        state = StateManager(paths)
        policy = state.load()
        with contextlib.suppress(KeyboardInterrupt):
            return asyncio.run(serve(args, sockets, policy, state, bridge_sockets))
        return 0
    with tempfile.TemporaryDirectory(prefix="blockadsd-dev-") as artifacts:
        policy = build_policy(args, Path(artifacts))
        with contextlib.suppress(KeyboardInterrupt):
            return asyncio.run(serve(args, sockets, policy, bridge_sockets=bridge_sockets))
    return 0


if __name__ == "__main__":
    sys.exit(main())
