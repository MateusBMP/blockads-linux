"""``blockadsctl``: command-line client for the daemon's D-Bus API.

Every command is one or more D-Bus calls; the daemon checks polkit. When
stdin is a terminal the calls allow interactive authorization and, like
``systemctl``, a ``pkttyagent`` is started for this process so the password
prompt appears in the terminal when no desktop agent answers.

Exit status: 0 success, 1 the daemon refused or failed, 2 usage error,
3 the daemon is not running (or not reachable on the bus), 4 not authorized.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from typing import Any

from jeepney import DBusAddress, MessageType, new_method_call
from jeepney.io.blocking import open_dbus_connection
from jeepney.low_level import HeaderFields, MessageFlag

from ..common import android_import, dbus_api, diagnostics

NOT_RUNNING = {"org.freedesktop.DBus.Error.ServiceUnknown", "org.freedesktop.DBus.Error.NameHasNoOwner",
               "org.freedesktop.DBus.Error.NoReply"}
DENIED = {"org.freedesktop.DBus.Error.AccessDenied", "org.freedesktop.DBus.Error.InteractiveAuthorizationRequired"}


class CtlError(Exception):
    def __init__(self, message: str, code: int = 1) -> None:
        super().__init__(message)
        self.code = code


class Client:
    def __init__(self, bus: str = "SYSTEM", *, interactive: bool | None = None) -> None:
        try:
            self.conn = open_dbus_connection(bus=bus)
        except (OSError, KeyError) as exc:
            raise CtlError(f"cannot connect to the D-Bus {bus.lower()} bus: {exc}", 3) from None
        self.interactive = sys.stdin.isatty() if interactive is None else interactive
        self.address = DBusAddress(dbus_api.OBJECT_PATH, dbus_api.BUS_NAME, dbus_api.INTERFACE)
        self._agent: subprocess.Popen | None = None

    def close(self) -> None:
        if self._agent is not None:
            self._agent.terminate()
            with contextlib.suppress(subprocess.TimeoutExpired):
                self._agent.wait(timeout=2)
        self.conn.close()

    def call(self, method: str, *args: Any) -> Any:
        spec = dbus_api.METHODS[method]
        message = new_method_call(self.address, method, spec.in_sig, args)
        interactive = self.interactive and spec.action != dbus_api.VIEW
        if interactive:
            message.header.flags |= MessageFlag.allow_interactive_authorization
            self._start_agent()
        timeout = dbus_api.AUTH_TIMEOUT + 10 if interactive else 30
        reply = self.conn.send_and_get_reply(message, timeout=timeout)
        if reply.header.message_type == MessageType.error:
            name = reply.header.fields.get(HeaderFields.error_name, "")
            text = reply.body[0] if reply.body else name
            if name in NOT_RUNNING:
                raise CtlError("the blockadsd daemon is not running (systemctl start blockadsd.service)", 3)
            if name in DENIED:
                raise CtlError(f"not authorized: {text}", 4)
            raise CtlError(text, 1)
        return reply.body[0] if spec.out_sig else None

    def json(self, method: str, *args: Any) -> dict[str, Any]:
        return json.loads(self.call(method, *args))

    def _start_agent(self) -> None:
        """A terminal polkit agent for this process (as systemctl does); best effort."""
        if self._agent is not None or not sys.stdin.isatty() or os.environ.get("BLOCKADS_NO_AGENT"):
            return
        agent = shutil.which("pkttyagent")
        if agent is None:
            return
        read_fd, write_fd = os.pipe()
        try:
            self._agent = subprocess.Popen([agent, "--notify-fd", str(write_fd), "--fallback",
                                            "--process", str(os.getpid())], pass_fds=(write_fd,))
            os.close(write_fd)
            write_fd = -1
            with contextlib.suppress(OSError):
                os.read(read_fd, 1)  # EOF once the agent is registered (or gone)
        except OSError:
            self._agent = None
        finally:
            os.close(read_fd)
            if write_fd >= 0:
                os.close(write_fd)


# --- formatting -------------------------------------------------------------------


def _when(ts: int) -> str:
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts)) if ts else "never"


def _safe(text: Any) -> str:
    """Domain names and server text come from the network: no control characters on the terminal."""
    return re.sub(r"[\x00-\x1f\x7f-\x9f]", "?", str(text))


def bridge_line(bridge: dict[str, Any]) -> str:
    """Containers/VMs on bridges: what is filtered, answered and dropped."""
    if not bridge["patterns"]:
        line = "not filtered (bridge redirect off)"
    else:
        names = bridge["interfaces"]
        line = f"filtered ({len(names)} interface{'s' if len(names) != 1 else ''}"
        line += f": {', '.join(map(_safe, names))})" if names else ", none up yet)"
    counts = []
    if bridge.get("allowed"):
        counts.append(f"{bridge['allowed']:,} answered")
    if bridge.get("dropped"):
        counts.append(f"{bridge['dropped']:,} dropped from other sources")
    return line + ("; " + ", ".join(counts) if counts else "")


def print_status(status: dict[str, Any]) -> None:
    protection = status["protection"]
    state = protection["state"]
    if state == "paused":
        until = protection["paused_until"]
        state += f" until {_when(until)}" if until else " until resumed"
    elif state == "trusted":
        state = "paused on a trusted network"
    print(f"Protection:   {state}")
    trusted = protection.get("trusted_network")
    network = status.get("network") or {}
    if network.get("uuid"):
        line = _safe(network.get("name") or network["uuid"])
        if trusted:
            line += " (trusted: " + ("pause" if trusted["mode"] == "pause" else "its DNS, filtered") + ")"
        print(f"Network:      {line}")
    filters = status["filters"]
    line = f"{filters['lists']} lists, {filters['rules']:,} rules"
    if filters["missing"]:
        line += f" ({len(filters['missing'])} not downloaded yet)"
    print(f"Filters:      {line}; updated {_when(filters['updated_at'])}")
    counts = status["custom_rules"]
    print(f"Custom rules: {counts['block']} block, {counts['allow']} allow, {counts['whitelist']} whitelisted")
    upstream = status.get("upstream") or {}
    for tier in upstream.get("tiers", []):
        lock = "encrypted" if tier["encrypted"] else "plain"
        print(f"Upstream:     {tier['name']}: {', '.join(map(_safe, tier['upstreams']))} ({lock})")
    if upstream.get("active"):
        print(f"Last answer:  {_safe(upstream['active']['label'])} [{upstream['active']['tier']}]")
    if upstream.get("captive"):
        print("Network:      captive portal: using the network's DNS")
    if upstream.get("clock_suspect"):
        print("Warning:      certificates look expired or not yet valid: is the clock right?")
    bypass = status.get("bypass") or {}
    if bypass.get("resolved_dot") == "yes":
        print("Warning:      systemd-resolved uses DNS over TLS (DNSOverTLS=yes): its queries bypass the filter")
    if not bypass.get("doh_blocklist") and bypass.get("doh_last") and time.time() - bypass["doh_last"] < 86400:
        print("Warning:      a DNS-over-HTTPS server was looked up: a browser may bypass the filter"
              " (blockadsctl feature doh_blocklist on)")
    health = status.get("health")
    if health:
        families = ", ".join(health["interception"]) or "none"
        print(f"Interception: {families}" + (f" ({_safe(health['interception_error'])})"
                                             if health.get("interception_error") else ""))
    bridge = status.get("bridge")
    if bridge is not None:
        print(f"Containers:   {bridge_line(bridge)}")
    today = status.get("today") or {}
    if today.get("total"):
        rate = 100.0 * today["blocked"] / today["total"]
        print(f"Today:        {today['total']:,} queries, {today['blocked']:,} blocked ({rate:.1f}%)")
    log = status.get("log")
    if log and not log["recording"]:
        print("Query log:    not recording")
    for problem in status.get("problems", []):
        print(f"Problem:      {_safe(problem)}")
    for alert in status.get("alerts", []):
        print(f"Alert:        {_safe(alert['kind'])}: {_safe(alert['message'])}")


def print_entries(entries: list[dict[str, Any]]) -> None:
    for e in entries:
        stamp = time.strftime("%H:%M:%S", time.localtime(e["time_ms"] / 1000))
        reason = f" ({_safe(e['reason'])})" if e["reason"] else ""
        print(f"{stamp} {e['verdict']:<9} {_safe(e['name'])}{reason}", flush=True)


# --- commands ------------------------------------------------------------------------


def parse_duration(text: str) -> int:
    """'15m', '1h', '90s', '2d', '1h30m'; 'forever'/'0' = until resumed."""
    if text in ("0", "forever", "until-resumed"):
        return 0
    parts = re.fullmatch(r"(?:(\d+)d)?(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s?)?", text)
    if not parts or not any(parts.groups()):
        raise argparse.ArgumentTypeError(f"bad duration {text!r} (e.g. 15m, 1h, 2d, forever)")
    days, hours, minutes, seconds = (int(g or 0) for g in parts.groups())
    total = days * 86400 + hours * 3600 + minutes * 60 + seconds
    if not 0 < total <= dbus_api.MAX_PAUSE_SECONDS:
        raise argparse.ArgumentTypeError("a pause lasts between 1 second and 30 days")
    return total


def run(args: argparse.Namespace, client: Client) -> int:
    cmd = args.command
    if cmd == "status":
        status = client.json("GetStatus")
        if args.json:
            print(json.dumps(status, indent=2))
        else:
            print_status(status)
    elif cmd == "pause":
        client.call("Pause", args.duration)
    elif cmd == "resume":
        client.call("Resume")
    elif cmd == "test":
        result = client.json("TestDomain", args.domain)
        lists = f" by {', '.join(result['lists'])}" if result["lists"] else ""
        reason = f" ({result['reason']})" if result["reason"] and not lists else ""
        print(f"{_safe(result['domain'])}: {result['verdict']}{lists}{reason}")
        return 0 if result["verdict"] != "blocked" or not args.quiet_exit else 10
    elif cmd in ("block", "unblock", "allow", "unallow"):
        method = {"block": "AddBlockRule", "unblock": "RemoveBlockRule", "allow": "AddAllowRule",
                  "unallow": "RemoveAllowRule"}[cmd]
        for domain in args.domains:
            client.call(method, domain)
    elif cmd == "rules":
        rules = client.json("GetRules")
        if args.json:
            print(json.dumps(rules["rules"], indent=2))
        else:
            for rule in rules["rules"]["rules"]:
                print(_safe(rule))
            for domain in rules["rules"]["whitelist"]:
                print(f"@@{_safe(domain)}  (whitelist)")
    elif cmd == "filters":
        return run_filters(args, client)
    elif cmd == "log":
        return run_log(args, client)
    elif cmd == "stats":
        stats = client.json("GetStatistics", args.period)
        if args.json:
            print(json.dumps(stats, indent=2))
        else:
            totals = stats["totals"]
            print(f"{args.period}: {totals.get('total', 0):,} queries, {totals.get('blocked', 0):,} blocked,"
                  f" {totals.get('cached', 0):,} from cache, {totals.get('failed', 0):,} failed")
            for reason, count in stats["reasons"].items():
                print(f"  {count:>8,}  {_safe(reason) or '(none)'}")
    elif cmd == "top":
        top = client.json("GetTopDomains", args.days, not args.allowed, args.limit)
        for item in top["domains"]:
            print(f"{item['count']:>8,}  {_safe(item['name'])}")
    elif cmd == "feature":
        client.call("EnableFeature" if args.state == "on" else "DisableFeature", args.name)
    elif cmd == "upstream":
        options: dict[str, Any] = {"upstream": args.specs}
        if args.fallback is not None:
            options["fallback"] = None if args.fallback == ["default"] else args.fallback
        if args.encrypted_only is not None:
            options["encrypted_only"] = args.encrypted_only
        client.call("SetUpstream", json.dumps(options))
    elif cmd == "logging":
        current = client.json("GetSettings")["settings"]["logging"]
        client.call("SetLogging", args.state == "on", args.retention or current["retention_days"])
    elif cmd == "clear-log":
        client.call("ClearQueryLog")
    elif cmd == "settings":
        print(json.dumps(client.json("GetSettings")["settings"], indent=2))
    elif cmd == "backup":
        backup = {"api": dbus_api.API_VERSION, "settings": client.json("GetSettings")["settings"],
                  "rules": client.json("GetRules")["rules"]}
        write_output(args.file, json.dumps(backup, indent=2) + "\n")
    elif cmd == "restore":
        with open_input(args.file) as stream:
            text = stream.read(android_import.MAX_INPUT + 1)  # an Android backup shrinks when converted
        try:
            document = json.loads(text)
        except ValueError:
            document = None
        if android_import.is_android_backup(document):
            result = android_import.convert(document, client.json("GetSettings")["settings"],
                                            client.json("GetRules")["rules"])
            text = json.dumps(result.backup)
            print("BlockAds for Android backup: " + (", ".join(
                f"{key.replace('_', ' ')} {count}" for key, count in result.report.items()) or "nothing to import"))
            if result.prefs:
                print("GUI preferences (not applied here): " + ", ".join(
                    f"{key}={value}" for key, value in result.prefs.items()))
        if len(text.encode()) > dbus_api.MAX_JSON:
            raise CtlError(f"backup larger than {dbus_api.MAX_JSON} bytes")
        client.call("ImportBackup", text)
    elif cmd == "networks":
        return run_networks(args, client)
    elif cmd == "diagnostics":
        write_output(args.file, json.dumps(collect_diagnostics(client, args.helper), indent=2) + "\n")
        if args.file != "-":
            print(f"Diagnostics written to {args.file} (no query log, no rules, no network names).")
    elif cmd == "reset":
        if not args.yes:
            raise CtlError("this resets every setting (rules are kept); pass --yes to confirm", 2)
        client.call("ResetSettings")
    return 0


def run_filters(args: argparse.Namespace, client: Client) -> int:
    action = args.filters_command or "list"
    if action == "list":
        catalog = client.json("GetFilterCatalog")
        if args.json:
            print(json.dumps(catalog, indent=2))
            return 0
        rows = catalog["lists"] + [{**c, "category": "custom", "retired": ""} for c in catalog["custom"]]
        for row in rows:
            if not args.all and not row["enabled"]:
                continue
            mark = "x" if row["enabled"] else " "
            state = "retired" if row["retired"] else (f"{row['rules']:,} rules" if row["downloaded"]
                                                      else "not downloaded")
            error = f"  [{_safe(row['error'])}]" if row.get("error") else ""
            print(f"[{mark}] {row['id']:<40} {row['category']:<10} {state}{error}")
    elif action == "enable":
        client.call("EnableFilters", args.ids)
    elif action == "disable":
        client.call("DisableFilters", args.ids)
    elif action == "update":
        client.call("UpdateFiltersNow")
        print("Update requested.")
    elif action == "add":
        print(client.call("AddCustomFilter", json.dumps({"name": args.name, "urls": args.urls})))
    elif action == "remove":
        client.call("RemoveCustomFilter", args.id)
    return 0


def collect_diagnostics(client: Client, helper: str) -> dict[str, Any]:
    parts: dict[str, Any] = {}
    errors: dict[str, str] = {}
    for key, method in (("status", "GetStatus"), ("settings", "GetSettings"), ("catalog", "GetFilterCatalog")):
        try:
            result = client.json(method)
            parts[key] = result.get("settings") if key == "settings" else result
        except (CtlError, OSError, TimeoutError) as exc:
            errors[key] = str(exc)[:300]
    for key, command in (("firewall", "status"), ("doctor", "doctor")):
        try:
            run = subprocess.run([helper, command, "--json"], capture_output=True, text=True, timeout=30,
                                 check=False)
            parts[key] = json.loads(run.stdout)
        except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
            errors[key] = f"{type(exc).__name__}: {str(exc)[:200]}"
    return diagnostics.build(**parts, errors=errors)


def run_networks(args: argparse.Namespace, client: Client) -> int:
    """Trusted networks, keyed by NetworkManager connection UUID."""
    action = args.networks_command or "list"
    networks = client.json("GetSettings")["settings"]["trusted_networks"]
    if action == "list":
        if getattr(args, "json", False):
            print(json.dumps(networks, indent=2))
            return 0
        current = (client.json("GetStatus").get("network") or {}).get("uuid", "")
        for network in networks:
            mark = "*" if network["uuid"] == current else " "
            print(f"{mark} {network['uuid']:<36}  {network['mode']:<11}  {_safe(network['name'])}")
        if not networks:
            print("No trusted networks.")
        return 0
    if action == "add":
        uuid, name = args.uuid, args.name
        if uuid is None:
            network = client.json("GetStatus").get("network") or {}
            uuid = network.get("uuid", "")
            if not uuid:
                raise CtlError("no active NetworkManager connection; pass its UUID (nmcli -f NAME,UUID connection)")
            name = name or network.get("name", "")
        entry = {"uuid": uuid, "name": name or "", "mode": args.mode}
        networks = [n for n in networks if n["uuid"] != uuid] + [entry]
    elif action == "remove":
        kept = [n for n in networks if n["uuid"] != args.uuid]
        if len(kept) == len(networks):
            raise CtlError(f"{args.uuid} is not a trusted network")
        networks = kept
    client.call("SetTrustedNetworks", json.dumps({"networks": networks}))
    return 0


def run_log(args: argparse.Namespace, client: Client) -> int:
    query: dict[str, Any] = {}
    if args.verdict:
        query["verdict"] = args.verdict
    if args.search:
        query["search"] = args.search
    if args.csv is not None:
        return export_csv(args, client, query)
    if args.follow:
        after = 0
        latest = client.json("GetQueryLog", json.dumps({**query, "before_id": 2**62}), 0, args.limit)["entries"]
        print_entries(list(reversed(latest)))
        after = max((e["id"] for e in latest), default=0)
        while True:
            time.sleep(1.0)
            page = client.json("GetQueryLog", json.dumps(query), after, dbus_api.MAX_LOG_PAGE)["entries"]
            print_entries(page)
            if page:
                after = page[-1]["id"]
    entries = client.json("GetQueryLog", json.dumps({**query, "before_id": 2**62}), 0, args.limit)["entries"]
    entries.reverse()
    if args.json:
        print(json.dumps(entries, indent=2))
    else:
        print_entries(entries)
    return 0


def export_csv(args: argparse.Namespace, client: Client, query: dict[str, Any]) -> int:
    """The whole log, oldest first, in pages; written by this process (no fd passing)."""
    chunks = []
    after, header = 0, True
    while True:
        page = client.json("GetQueryLog", json.dumps(query), after, dbus_api.MAX_LOG_PAGE)["entries"]
        if not page:
            break
        chunks.append(dbus_api.csv_rows(page, header=header))
        header = False
        after = page[-1]["id"]
    if header:
        chunks.append(dbus_api.csv_rows([], header=True))
    write_output(args.csv, "".join(chunks))
    return 0


def write_output(path: str, text: str) -> None:
    if path == "-":
        sys.stdout.write(text)
        return
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(text)


def open_input(path: str):
    return contextlib.nullcontext(sys.stdin) if path == "-" else open(path, encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="blockadsctl", description="Control the blockads-linux DNS filter.")
    parser.add_argument("--bus", default="system", help="system (default), session, or a bus address")
    parser.add_argument("--no-ask-password", action="store_true", help="never prompt for authentication")
    sub = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    p = sub.add_parser("status", help="show the filter's state")
    p.add_argument("--json", action="store_true")
    p = sub.add_parser("pause", help="stop filtering for a while (asks for the admin password)")
    p.add_argument("duration", nargs="?", default=0, type=parse_duration, help="15m, 1h, 2d or forever (default)")
    sub.add_parser("resume", help="filter again")
    p = sub.add_parser("test", help="would this domain be blocked?")
    p.add_argument("domain")
    p.add_argument("--quiet-exit", action="store_true", help="exit 10 when blocked")
    for name, text in (("block", "always block"), ("unblock", "remove a block rule"),
                       ("allow", "never block"), ("unallow", "remove an allow rule")):
        p = sub.add_parser(name, help=f"{text} (with subdomains)")
        p.add_argument("domains", nargs="+", metavar="DOMAIN")
    p = sub.add_parser("rules", help="list the custom rules")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("filters", help="filter lists")
    p.add_argument("--json", action="store_true")
    p.add_argument("--all", action="store_true", help="also list disabled lists")
    fsub = p.add_subparsers(dest="filters_command", metavar="ACTION")
    fsub.add_parser("list")
    for name in ("enable", "disable"):
        fp = fsub.add_parser(name)
        fp.add_argument("ids", nargs="+", metavar="ID")
    fsub.add_parser("update", help="download updates now")
    fp = fsub.add_parser("add", help="add a custom list")
    fp.add_argument("name")
    fp.add_argument("urls", nargs="+", metavar="URL")
    fp = fsub.add_parser("remove", help="remove a custom list")
    fp.add_argument("id")

    p = sub.add_parser("log", help="recent queries")
    p.add_argument("-n", "--limit", type=int, default=50)
    p.add_argument("-f", "--follow", action="store_true")
    p.add_argument("--verdict", choices=("forwarded", "blocked", "local", "failed"))
    p.add_argument("--search")
    p.add_argument("--json", action="store_true")
    p.add_argument("--csv", metavar="FILE", help="export the whole log as CSV ('-' for stdout)")
    p = sub.add_parser("stats", help="statistics")
    p.add_argument("period", nargs="?", default="24h", choices=("24h", "7d", "4w", "12m"))
    p.add_argument("--json", action="store_true")
    p = sub.add_parser("top", help="top domains")
    p.add_argument("--days", type=int, default=1)
    p.add_argument("--allowed", action="store_true", help="most queried instead of most blocked")
    p.add_argument("-n", "--limit", type=int, default=20)
    p = sub.add_parser("feature", help=f"turn on/off: {', '.join(dbus_api.FEATURES)}")
    p.add_argument("name", choices=tuple(dbus_api.FEATURES))
    p.add_argument("state", choices=("on", "off"))
    p = sub.add_parser("upstream", help="set the DNS servers (presets, stamps or URLs)")
    p.add_argument("specs", nargs="+", metavar="SPEC")
    p.add_argument("--fallback", nargs="+", metavar="SPEC", help="'none', 'default', or servers")
    enc = p.add_mutually_exclusive_group()
    enc.add_argument("--encrypted-only", dest="encrypted_only", action="store_true", default=None)
    enc.add_argument("--allow-plain", dest="encrypted_only", action="store_false")
    p = sub.add_parser("logging", help="query log recording")
    p.add_argument("state", choices=("on", "off"))
    p.add_argument("--retention", type=int, metavar="DAYS")
    sub.add_parser("clear-log", help="delete the query log (statistics are kept)")
    sub.add_parser("settings", help="print the settings as JSON")
    p = sub.add_parser("backup", help="write settings and rules as JSON")
    p.add_argument("file", nargs="?", default="-")
    p = sub.add_parser("restore", help="replace settings and rules from a backup (or merge a BlockAds for Android backup)")
    p.add_argument("file", nargs="?", default="-")
    p = sub.add_parser("diagnostics", help="write a diagnostics report (JSON; nothing is sent anywhere)")
    p.add_argument("file", nargs="?", default="-")
    p.add_argument("--helper", default="/usr/lib/blockads-linux/blockads-fw", help=argparse.SUPPRESS)
    p = sub.add_parser("networks", help="trusted networks (NetworkManager connections)")
    nsub = p.add_subparsers(dest="networks_command", metavar="ACTION")
    np_ = nsub.add_parser("list")
    np_.add_argument("--json", action="store_true")
    np_ = nsub.add_parser("add", help="trust a connection (default: the current one; asks for the admin password)")
    np_.add_argument("uuid", nargs="?", help="NetworkManager connection UUID")
    np_.add_argument("--name", help="label (default: the connection's name)")
    np_.add_argument("--mode", choices=("pause", "network_dns"), default="pause",
                     help="pause: no filtering; network_dns: keep filtering, use the network's DNS")
    np_ = nsub.add_parser("remove")
    np_.add_argument("uuid")
    p = sub.add_parser("reset", help="reset every setting to its default")
    p.add_argument("--yes", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    bus = {"system": "SYSTEM", "session": "SESSION"}.get(args.bus, args.bus)
    try:
        client = Client(bus, interactive=False if args.no_ask_password else None)
    except CtlError as exc:
        print(f"blockadsctl: {exc}", file=sys.stderr)
        return exc.code
    try:
        return run(args, client)
    except CtlError as exc:
        print(f"blockadsctl: {exc}", file=sys.stderr)
        return exc.code
    except (TimeoutError, OSError) as exc:
        print(f"blockadsctl: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 3
    except KeyboardInterrupt:
        return 130
    finally:
        client.close()

