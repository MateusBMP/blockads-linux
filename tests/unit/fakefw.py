"""Test support for helper/blockads-fw: module loader and a fake iptables.

``FakeIptables`` simulates iptables/ip6tables and their ``-restore`` for both
backends in memory, with the semantics measured by tests/netns/interception.sh:
- ``:CHAIN - [0:0]`` in a restore creates or flushes the chain;
- each ``*table`` ... ``COMMIT`` block commits on its own (per-table commit);
- ``-S``/``-C``/``-D``/``-F``/``-X``/``-A``/``-I`` with iptables' error texts.

Rules are stored as the token text the helper renders, so ``-S`` output
matches the rendered rules exactly; normalisation by real iptables is covered
by the namespace test (tests/netns/fw_helper.sh).

Faults: ``fail_on`` maps a 1-based call number to "fail" or "timeout";
``fail_if`` is a predicate on (backend, argv) that fails every matching call.
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import shlex
import struct
import sys
from pathlib import Path

HELPER = Path(__file__).resolve().parents[2] / "helper" / "blockads-fw"

BUILTINS = {
    "nat": ("PREROUTING", "INPUT", "OUTPUT", "POSTROUTING"),
    "filter": ("INPUT", "FORWARD", "OUTPUT"),
}


def load_helper():
    """Import helper/blockads-fw (no .py suffix) as a fresh module."""
    loader = importlib.machinery.SourceFileLoader("blockads_fw", str(HELPER))
    spec = importlib.util.spec_from_loader("blockads_fw", loader)
    module = importlib.util.module_from_spec(spec)
    old = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = old
    return module


def quote(token: str) -> str:
    if token and not any(ch in token for ch in ' "\'\\\t'):
        return token
    return '"' + token.replace("\\", "\\\\").replace('"', '\\"') + '"'


def join(tokens: list[str]) -> str:
    return " ".join(quote(t) for t in tokens)


class Table:
    def __init__(self, name: str):
        self.chains: dict[str, list[str]] = {b: [] for b in BUILTINS[name]}
        self.builtins = set(BUILTINS[name])

    def copy(self) -> "Table":
        new = Table.__new__(Table)
        new.chains = {k: list(v) for k, v in self.chains.items()}
        new.builtins = set(self.builtins)
        return new


class FakeIptables:
    def __init__(self) -> None:
        # (backend, family) -> table name -> Table
        self.state: dict[tuple[str, str], dict[str, Table]] = {}
        self.calls: list[tuple[str, list[str], str | None]] = []
        self.fail_on: dict[int, str] = {}
        self.fail_if = None
        self.systemctl: list[list[str]] = []
        self.service_active = False  # `systemctl is-active blockadsd.service`
        self.unsupported: set[tuple[str, str]] = set()  # (backend, family) without nat

    # -- helpers for tests ------------------------------------------------
    def tables(self, backend: str, family: str) -> dict[str, Table]:
        return self.state.setdefault((backend, family), {t: Table(t) for t in BUILTINS})

    def rules(self, backend: str, family: str, table: str, chain: str) -> list[str] | None:
        return self.tables(backend, family)[table].chains.get(chain)

    def add(self, backend: str, family: str, table: str, chain: str, line: str, *, insert: bool = False) -> None:
        chains = self.tables(backend, family)[table].chains
        chains.setdefault(chain, [])
        if insert:
            chains[chain].insert(0, line)
        else:
            chains[chain].append(line)

    def leftovers(self) -> list[str]:
        found = []
        for (backend, family), tables in self.state.items():
            for tname, table in tables.items():
                for chain, rules in table.chains.items():
                    if chain.startswith("BLOCKADS_"):
                        found.append(f"{backend}/{family}/{tname}: chain {chain}")
                    found += [f"{backend}/{family}/{tname}/{chain}: {r}" for r in rules if "BLOCKADS_" in r]
        return found

    # -- the fake run_cmd -------------------------------------------------
    def run_cmd(self, exe: str, argv: list[str], input_text: str | None = None, timeout: float | None = None):
        timeout = 10 if timeout is None else timeout
        self.calls.append((exe, list(argv), input_text))
        number = len(self.calls)
        backend = "legacy" if "legacy" in exe else "nft"
        if argv[0] == "systemctl":
            self.systemctl.append(list(argv))
            if argv[1] == "is-active":
                return (0 if self.service_active else 3), "", ""
            return 0, "", ""
        fault = self.fail_on.get(number)
        if fault is None and self.fail_if is not None and self.fail_if(backend, argv):
            fault = "fail"
        if fault == "timeout":
            return -1, "", f"{argv[0]}: timed out after {timeout:g}s"
        if fault == "fail":
            return 4, "", "iptables: injected failure."
        family = "ipv6" if argv[0].startswith("ip6") else "ipv4"
        if argv[0].endswith("-restore"):
            return self._restore(backend, family, input_text or "")
        return self._ipt(backend, family, argv[1:])

    def _ipt(self, backend: str, family: str, args: list[str]):
        args = list(args)
        if args[:1] == ["-w"]:
            args = args[2:]
        table_name = "filter"
        if args[:1] == ["-t"]:
            table_name = args[1]
            args = args[2:]
        if (backend, family) in self.unsupported and table_name == "nat":
            return 3, "", "can't initialize ip6tables table `nat': Table does not exist"
        if args[:1] == ["-V"]:
            return 0, f"iptables v1.8.13 ({'nf_tables' if backend == 'nft' else 'legacy'})\n", ""
        table = self.tables(backend, family)[table_name]
        op, chain, spec = args[0], args[1] if len(args) > 1 else "", args[2:]
        missing = (1, "", "iptables: No chain/target/match by that name.\n")
        if op == "-S":
            if chain not in table.chains:
                return missing
            head = f"-P {chain} ACCEPT" if chain in table.builtins else f"-N {chain}"
            return 0, "\n".join([head] + [f"-A {chain} {r}" for r in table.chains[chain]]) + "\n", ""
        if op == "-C":
            if chain not in table.chains or join(spec) not in table.chains[chain]:
                return 1, "", "iptables: Bad rule (does a matching rule exist in that chain?).\n"
            return 0, "", ""
        if op == "-D":
            if chain not in table.chains:
                return missing
            target = join(spec)
            if target not in table.chains[chain]:
                return 1, "", "iptables: Bad rule (does a matching rule exist in that chain?).\n"
            table.chains[chain].remove(target)
            return 0, "", ""
        if op == "-F":
            if chain not in table.chains:
                return missing
            table.chains[chain] = []
            return 0, "", ""
        if op == "-X":
            if chain not in table.chains or chain in table.builtins:
                return missing
            if self._referenced(table, chain):
                return 1, "", "iptables v1.8.13: CHAIN_DEL failed (Device or resource busy)\n"
            del table.chains[chain]
            return 0, "", ""
        if op == "-N":
            table.chains.setdefault(chain, [])
            return 0, "", ""
        if op in ("-A", "-I"):
            if chain not in table.chains:
                return missing
            if op == "-I" and spec and spec[0].isdigit():
                table.chains[chain].insert(int(spec[0]) - 1, join(spec[1:]))
            else:
                (table.chains[chain].append if op == "-A" else lambda r: table.chains[chain].insert(0, r))(join(spec))
            return 0, "", ""
        return 2, "", f"unsupported fake op {op}"

    @staticmethod
    def _referenced(table: Table, chain: str) -> bool:
        for rules in table.chains.values():
            for rule in rules:
                tokens = rule.split()
                if any(t in ("-j", "-g") and i + 1 < len(tokens) and tokens[i + 1] == chain
                       for i, t in enumerate(tokens)):
                    return True
        return False

    def _restore(self, backend: str, family: str, text: str):
        tables = self.tables(backend, family)
        work: Table | None = None
        name = ""
        for number, line in enumerate(text.splitlines(), 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("*"):
                name = line[1:]
                if (backend, family) in self.unsupported and name == "nat":
                    return 1, "", f"line {number}: table nat not supported\n"
                work = tables[name].copy()
                continue
            if line == "COMMIT":
                tables[name] = work
                work = None
                continue
            if work is None:
                return 1, "", f"line {number}: outside a table\n"
            if line.startswith(":"):
                chain = line[1:].split()[0]
                work.chains[chain] = []
                continue
            tokens = shlex.split(line)
            op, chain, spec = tokens[0], tokens[1], tokens[2:]
            if chain not in work.chains:
                return 1, "", f"iptables-restore: line {number} failed\n"
            if op == "-A":
                work.chains[chain].append(join(spec))
            elif op == "-I":
                position = int(spec[0]) - 1 if spec and spec[0].isdigit() else 0
                rule = spec[1:] if spec and spec[0].isdigit() else spec
                work.chains[chain].insert(position, join(rule))
            elif op == "-D":
                target = join(spec)
                if target not in work.chains[chain]:
                    return 1, "", f"iptables-restore: line {number} failed\n"
                work.chains[chain].remove(target)
            else:
                return 1, "", f"iptables-restore: line {number}: unsupported\n"
        return 0, "", ""


def proc_line_v4(address: str, port: int, state: str = "07") -> str:
    """A /proc/net/{udp,tcp} line for a host-endian IPv4 address."""
    packed = bytes(int(x) for x in address.split("."))
    word = struct.unpack("=I", packed)[0]
    return f"   0: {word:08X}:{port:04X} 00000000:0000 {state} 00000000:00000000 00:00000000 00000000     0        0 1 1"


def proc_line_v6(address: str, port: int, state: str = "07") -> str:
    import ipaddress
    packed = ipaddress.ip_address(address).packed
    words = "".join(f"{struct.unpack('=I', packed[i:i + 4])[0]:08X}" for i in range(0, 16, 4))
    return f"   0: {words}:{port:04X} 00000000000000000000000000000000:0000 {state} 00000000:00000000 00:00000000 00000000     0        0 1 1"


HEADER = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode"


def write_proc(root: Path, *, v4_ports=(153,), v6_ports=(153,), any_ports=(), ipv6: str = "on",
               unprivileged_start: int = 1024, legacy_tables: str = "") -> None:
    """A fake /proc with listeners. ipv6: on | no-lo | off (kernel) | empty."""
    net = root / "net"
    net.mkdir(parents=True, exist_ok=True)
    (root / "sys/net/ipv4").mkdir(parents=True, exist_ok=True)
    (root / "sys/net/ipv4/ip_unprivileged_port_start").write_text(f"{unprivileged_start}\n")
    udp = [proc_line_v4("127.0.0.1", p) for p in v4_ports] + [proc_line_v4("0.0.0.0", p) for p in any_ports]
    tcp = [proc_line_v4("127.0.0.1", p, "0A") for p in v4_ports] + [proc_line_v4("0.0.0.0", p, "0A") for p in any_ports]
    udp6 = [proc_line_v6("::1", p) for p in v6_ports] + [proc_line_v6("::", p) for p in any_ports]
    tcp6 = [proc_line_v6("::1", p, "0A") for p in v6_ports] + [proc_line_v6("::", p, "0A") for p in any_ports]
    for name, lines in (("udp", udp), ("tcp", tcp), ("udp6", udp6), ("tcp6", tcp6)):
        (net / name).write_text("\n".join([HEADER, *lines]) + "\n")
    inet6 = net / "if_inet6"
    if ipv6 == "off":
        if inet6.exists():
            inet6.unlink()
    elif ipv6 == "empty":
        inet6.write_text("")
    else:
        rows = []
        if ipv6 == "on":
            rows.append("00000000000000000000000000000001 01 80 10 80       lo")
        rows.append("fe800000000000000000000000000001 02 40 20 80     eth0")
        inet6.write_text("\n".join(rows) + "\n")
    for name in ("ip_tables_names", "ip6_tables_names"):
        path = net / name
        if legacy_tables:
            path.write_text(legacy_tables + "\n")
        elif path.exists():
            path.unlink()
