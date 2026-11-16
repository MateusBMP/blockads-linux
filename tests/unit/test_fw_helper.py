"""helper/blockads-fw against a fake iptables (no root, no namespaces).

Real iptables (nft and legacy) is exercised by tests/netns/fw_helper.sh.
"""

from __future__ import annotations

import io
import json
import os
import socket
import struct
import threading
from pathlib import Path

import dns.message
import dns.rrset
import pytest

from tests.unit.fakefw import FakeIptables, load_helper, proc_line_v4, proc_line_v6, write_proc

GOLDEN = Path(__file__).resolve().parents[1] / "golden" / "fw"
UID = 977
RESOLVED_UID = 976


class Env:
    def __init__(self, mod, fake: FakeIptables, tmp: Path):
        self.mod = mod
        self.fake = fake
        self.tmp = tmp
        self.proc = tmp / "proc"
        self.conf = tmp / "etc" / "firewall.conf"
        self.run_dir = tmp / "run"
        self.current = "nft"
        self.missing: set[str] = set()
        self.probe_results: dict[str, list[str]] = {}

    def run(self, *argv: str, stdin: str | None = None) -> int:
        if stdin is not None:
            self.mod.sys.stdin = io.TextIOWrapper(io.BytesIO(stdin.encode()))
        return self.mod.main(list(argv))

    def state(self) -> dict:
        return json.loads((self.run_dir / "state.json").read_text())

    def write_conf(self, text: str, mode: int = 0o644) -> None:
        self.conf.parent.mkdir(parents=True, exist_ok=True)
        self.conf.write_text(text)
        os.chmod(self.conf, mode)

    def proc_setup(self, **kwargs) -> None:
        write_proc(self.proc, **kwargs)

    def rules(self, family: str, table: str, chain: str, backend: str = "nft"):
        return self.fake.rules(backend, family, table, chain)


@pytest.fixture
def fw(tmp_path, monkeypatch):
    mod = load_helper()
    fake = FakeIptables()
    env = Env(mod, fake, tmp_path)
    env.proc_setup()

    def find_tool(name: str):
        if name in env.missing:
            return None
        if name in ("busctl", "systemctl"):
            return f"/fake/{name}"
        backend = "legacy" if "legacy" in name else ("nft" if "nft" in name else env.current)
        if f"backend:{backend}" in env.missing:
            return None
        return f"/fake/xtables-{backend}-multi"

    def probe(family: str) -> str:
        queue = env.probe_results.get(family)
        return queue.pop(0) if queue else "ok"

    monkeypatch.setattr(mod, "run_cmd", fake.run_cmd)
    monkeypatch.setattr(mod, "find_tool", find_tool)
    monkeypatch.setattr(mod, "check_trusted", lambda path: None)
    monkeypatch.setattr(mod, "service_uid", lambda: UID)
    monkeypatch.setattr(mod, "resolved_dot_mode", lambda: "absent")
    monkeypatch.setattr(mod, "probe", probe)
    monkeypatch.setattr(mod, "require_root", lambda: None)
    monkeypatch.setattr(mod, "setup_process", lambda: None)
    monkeypatch.setattr(mod, "PROC", str(env.proc))
    monkeypatch.setattr(mod, "RUN_DIR", str(env.run_dir))
    monkeypatch.setattr(mod, "CONF_PATH", str(env.conf))
    monkeypatch.setattr(mod, "TRUSTED_UIDS", frozenset({0, os.getuid()}))
    # The helper only stashes an emergency script owned by a trusted uid. The source tree
    # may belong to someone else (CI mounts the checkout into a container as another
    # user), so use a copy owned by the test user.
    script = tmp_path / "lib" / "blockads-fw-emergency.sh"
    script.parent.mkdir(exist_ok=True)
    script.write_bytes(Path(mod.EMERGENCY_SCRIPT).read_bytes())
    os.chmod(script, 0o755)
    monkeypatch.setattr(mod, "EMERGENCY_SCRIPT", str(script))
    monkeypatch.setattr(mod, "LOCK_TIMEOUT", 0.3)
    monkeypatch.setattr(mod.time, "sleep", lambda s: None)
    return env


def chain_count(env: Env, family: str, table: str, builtin: str, chain: str, backend: str = "nft") -> int:
    rules = env.rules(family, table, builtin, backend) or []
    return sum(1 for r in rules if r == f"-j {chain}")


# --- configuration -----------------------------------------------------------

def test_defaults_when_config_missing(fw):
    cfg, warnings = fw.mod.read_config()
    assert cfg == fw.mod.validate_config({})
    assert cfg["port"] == 153 and cfg["bridge_port"] == 154 and cfg["block_dot"] is True
    assert cfg["bypass_cidrs"] == ["100.100.100.100/32", "fd7a:115c:a1e0::53/128"]
    assert warnings and "missing" in warnings[0]


def test_config_round_trip(fw):
    cfg = fw.mod.validate_config({
        "ipv6": "off", "block_webrtc": True, "bypass_cidrs": ["10.0.0.0/8", "10.0.0.0/8", "fd00::/8"],
        "bridge_interfaces": ["docker0", "br-+", "virbr+"],
    })
    assert cfg["bypass_cidrs"] == ["10.0.0.0/8", "fd00::/8"]
    text = fw.mod.render_config(cfg)
    assert fw.mod.parse_config_text(text) == cfg
    fw.write_conf(text)
    assert fw.mod.read_config() == (cfg, [])


@pytest.mark.parametrize("text, fragment", [
    ("color=blue\n", "unknown key"),
    ("port=153\nport=153\n", "duplicate"),
    ("justtext\n", "key=value"),
    ("port=1024\n", "privileged"),
    ("port=53\n", "privileged"),
    ("port=9\n", "privileged"),
    ("port=0153x\n", "port number"),
    ("bridge_port=153\n", "differ"),
    ("ipv6=on\n", "auto or off"),
    ("block_dot=yes\n", "true or false"),
    ("bypass_cidrs=10.0.0.1/8\n", "host bits"),
    ("bypass_cidrs=not-an-ip\n", "bypass_cidrs"),
    ("bridge_interfaces=+\n", "bridge_interfaces"),
    ("bridge_interfaces=lo\n", "not allowed"),
    ("bridge_interfaces=eth0;reboot\n", "invalid interface"),
    ("bridge_interfaces=-i\n", "invalid interface"),
    ("bridge_interfaces=abcdefghijklmnop\n", "invalid interface"),
])
def test_invalid_config_exits_2(fw, text, fragment):
    fw.write_conf(text)
    with pytest.raises(fw.mod.FwError) as info:
        fw.mod.read_config()
    assert info.value.code == 2
    assert fragment in str(info.value)


def test_config_permissions(fw):
    fw.write_conf("port=153\n", mode=0o666)
    with pytest.raises(fw.mod.FwError, match="not group/world-writable"):
        fw.mod.read_config()
    fw.conf.unlink()
    target = fw.tmp / "elsewhere.conf"
    target.write_text("port=153\n")
    fw.conf.symlink_to(target)
    with pytest.raises(fw.mod.FwError) as info:
        fw.mod.read_config()
    assert info.value.code == 2


def test_config_too_large(fw):
    fw.write_conf("# x\n" * 5000)
    with pytest.raises(fw.mod.FwError, match="larger"):
        fw.mod.read_config()


def test_apply_with_invalid_config_fails_open(fw):
    fw.write_conf("port=99999\n")
    assert fw.run("apply", "--verify") == 2
    assert fw.fake.leftovers() == []


def test_check_trusted():
    mod = load_helper()
    mod.check_trusted(os.path.realpath("/usr/bin"))
    with pytest.raises(mod.FwError, match="writable|not owned"):
        mod.check_trusted("/tmp")


def test_check_trusted_rejects_user_owned(tmp_path):
    mod = load_helper()
    with pytest.raises(mod.FwError):
        mod.check_trusted(str(tmp_path))


# --- rendering (golden) ------------------------------------------------------

def _golden_cases(mod):
    base = mod.validate_config({})
    full = mod.validate_config({"block_webrtc": True, "bridge_interfaces": ["docker0", "br-+"],
                                "bypass_cidrs": ["100.100.100.100/32", "10.64.0.0/10", "fd7a:115c:a1e0::53/128"]})
    nodot = mod.validate_config({"block_dot": False, "bypass_cidrs": []})
    cases = {}
    for family, tag in (("ipv4", "v4"), ("ipv6", "v6")):
        for name, cfg, resolved, hooks in (
            ("default", base, None, mod.MAIN_HOOKS),
            ("full", full, RESOLVED_UID, mod.MAIN_HOOKS + mod.BRIDGE_HOOKS),
            ("nodot", nodot, None, mod.MAIN_HOOKS),
        ):
            text = "".join(
                mod.render_transaction(table, builtin, chain,
                                       mod.render_rules(family, chain, cfg, UID, resolved), 0)
                for table, builtin, chain in hooks
            )
            cases[f"{name}_{tag}.txt"] = text
    return cases


def test_golden_transactions():
    mod = load_helper()
    cases = _golden_cases(mod)
    if os.environ.get("UPDATE_GOLDEN"):
        GOLDEN.mkdir(parents=True, exist_ok=True)
        for name, text in cases.items():
            (GOLDEN / name).write_text(text)
    for name, text in cases.items():
        assert (GOLDEN / name).read_text() == text, name


def test_golden_matches_plan_shape():
    text = (GOLDEN / "default_v4.txt").read_text()
    assert ('-A BLOCKADS_DNS -d 127.0.0.1/32 -p udp -m udp --dport 9 -m comment --comment '
            '"blockads-linux probe; runtime-only, do not persist" -j REDIRECT --to-ports 153') in text
    assert f"-A BLOCKADS_DNS -m owner --uid-owner {UID} -j RETURN" in text
    assert "-A BLOCKADS_DNS -d 100.100.100.100/32 -j RETURN" in text
    assert "fd7a" not in text
    v6 = (GOLDEN / "default_v6.txt").read_text()
    assert "-d fd7a:115c:a1e0::53/128 -j RETURN" in v6 and "100.100" not in v6
    assert "icmp6-port-unreachable" in v6
    full = (GOLDEN / "full_v4.txt").read_text()
    assert f"--uid-owner {RESOLVED_UID}" in full
    assert "-A BLOCKADS_BRIDGE -i br-+ -p tcp -m tcp --dport 53 -j REDIRECT --to-ports 154" in full
    assert "-A BLOCKADS_IN -p udp -m udp --dport 154 -m conntrack --ctstate DNAT -j RETURN" in full
    assert "-I PREROUTING 1 -j BLOCKADS_BRIDGE" in full and "-I INPUT 1 -j BLOCKADS_IN" in full
    nodot = (GOLDEN / "nodot_v4.txt").read_text()
    assert "853" not in nodot and "100.100" not in nodot


@pytest.mark.parametrize("jumps, inserts, deletes", [(0, 1, 0), (1, 0, 0), (3, 0, 2)])
def test_transaction_jump_dedup(jumps, inserts, deletes):
    mod = load_helper()
    text = mod.render_transaction("nat", "OUTPUT", "BLOCKADS_DNS", [["-j", "RETURN"]], jumps)
    assert text.count("-I OUTPUT 1 -j BLOCKADS_DNS") == inserts
    assert text.count("-D OUTPUT -j BLOCKADS_DNS") == deletes
    assert text.startswith("*nat\n:BLOCKADS_DNS - [0:0]\n") and text.endswith("COMMIT\n")


def test_jump_lines():
    mod = load_helper()
    lines = [
        "-P OUTPUT ACCEPT",
        "-A OUTPUT -j BLOCKADS_DNS",
        "-A OUTPUT -o lo -j BLOCKADS_DNS",
        "-A OUTPUT -g BLOCKADS_DNS",
        "-A OUTPUT -j BLOCKADS_DNS_OLD",
        "-A OUTPUT -m comment --comment BLOCKADS_DNS -j ACCEPT",
        "-A OTHER -j BLOCKADS_DNS",
    ]
    assert mod.jump_lines(lines, "OUTPUT", "BLOCKADS_DNS") == lines[1:4]
    assert mod.exact_jumps(lines, "OUTPUT", "BLOCKADS_DNS") == 1


# --- /proc -------------------------------------------------------------------

def test_proc_listeners(fw):
    fw.proc_setup(v4_ports=(153,), v6_ports=(), any_ports=(154,))
    assert ("127.0.0.1", 153) in fw.mod.listeners("udp", "ipv4")
    assert fw.mod.has_listener("ipv4", 153)
    assert not fw.mod.has_listener("ipv6", 153)
    assert fw.mod.has_listener("ipv4", 154)  # wildcard
    assert fw.mod.has_listener("ipv6", 154, any_address=True)


def test_tcp_listener_needs_listen_state(fw):
    (fw.proc / "net" / "tcp").write_text("hdr\n" + proc_line_v4("127.0.0.1", 153, "01") + "\n")
    assert not fw.mod.has_listener("ipv4", 153)
    (fw.proc / "net" / "tcp6").write_text("hdr\n" + proc_line_v6("::1", 153, "0A") + "\n")
    assert fw.mod.has_listener("ipv6", 153)


def test_ipv6_addresses(fw):
    assert ("::1", "lo") in fw.mod.ipv6_addresses()
    fw.proc_setup(ipv6="off")
    assert fw.mod.ipv6_addresses() is None


# --- probe wire format -------------------------------------------------------

def test_probe_query_is_valid_dns():
    mod = load_helper()
    nonce = "ab" * 16
    wire = mod.build_probe_query(4242, nonce)
    query = dns.message.from_wire(wire)
    assert query.id == 4242
    assert str(query.question[0].name) == f"{nonce}.probe.blockads-linux.invalid."
    assert query.question[0].rdtype == 16

    response = dns.message.make_response(query)
    response.answer.append(dns.rrset.from_text(query.question[0].name, 10, "IN", "TXT", f'"blockads-linux:{nonce}"'))
    assert mod.parse_txt_answers(response.to_wire(), 4242) == [f"blockads-linux:{nonce}"]
    with pytest.raises(ValueError):
        mod.parse_txt_answers(response.to_wire(), 4243)
    response.set_rcode(3)
    with pytest.raises(ValueError):
        mod.parse_txt_answers(response.to_wire(), 4242)
    for cut in range(0, len(wire)):
        try:
            mod.parse_txt_answers(response.to_wire()[:cut], 4242)
        except (ValueError, struct.error, IndexError):
            pass


def _responder(echo: bool):
    """UDP+TCP responder on 127.0.0.1:<random> answering like the daemon (or wrongly)."""
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("127.0.0.1", 0))
    port = udp.getsockname()[1]
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp.bind(("127.0.0.1", port))
    tcp.listen(4)

    def answer(wire: bytes) -> bytes:
        query = dns.message.from_wire(wire)
        response = dns.message.make_response(query)
        label = query.question[0].name.labels[0].decode()
        text = f"blockads-linux:{label}" if echo else "blockads-linux:other"
        response.answer.append(dns.rrset.from_text(query.question[0].name, 10, "IN", "TXT", f'"{text}"'))
        return response.to_wire()

    def serve_udp():
        while True:
            try:
                data, peer = udp.recvfrom(4096)
            except OSError:
                return
            udp.sendto(answer(data), peer)

    def serve_tcp():
        while True:
            try:
                conn, _ = tcp.accept()
            except OSError:
                return
            with conn:
                length = struct.unpack("!H", conn.recv(2))[0]
                data = b""
                while len(data) < length:
                    data += conn.recv(length - len(data))
                reply = answer(data)
                conn.sendall(struct.pack("!H", len(reply)) + reply)

    for target in (serve_udp, serve_tcp):
        threading.Thread(target=target, daemon=True).start()
    return port, (udp, tcp)


def test_probe_once_against_responder():
    mod = load_helper()
    port, socks = _responder(echo=True)
    try:
        assert mod.probe_once("ipv4", "udp", port=port) == "ok"
        assert mod.probe_once("ipv4", "tcp", port=port) == "ok"
    finally:
        for s in socks:
            s.close()
    port, socks = _responder(echo=False)
    try:
        assert mod.probe_once("ipv4", "udp", port=port) == "wrong answer"
    finally:
        for s in socks:
            s.close()


def test_probe_once_refused_is_fast():
    mod = load_helper()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    assert mod.probe_once("ipv4", "udp", port=port).startswith("refused")


# --- apply -------------------------------------------------------------------

def test_apply_fresh(fw):
    assert fw.run("apply", "--verify") == 0
    for family in ("ipv4", "ipv6"):
        assert chain_count(fw, family, "nat", "OUTPUT", "BLOCKADS_DNS") == 1
        assert chain_count(fw, family, "filter", "OUTPUT", "BLOCKADS_OUT") == 1
        assert fw.rules(family, "nat", "OUTPUT")[0] == "-j BLOCKADS_DNS"
        assert fw.rules(family, "nat", "BLOCKADS_BRIDGE") is None
    assert len(fw.rules("ipv4", "nat", "BLOCKADS_DNS")) == 7
    assert len(fw.rules("ipv6", "nat", "BLOCKADS_DNS")) == 7
    state = fw.state()
    assert state["applied"] is True and state["backend"] == "nft"
    assert state["families"] == {"ipv4": {"status": "active"}, "ipv6": {"status": "active"}}
    assert state["bridge"] == {"status": "off"}
    assert oct(os.stat(fw.run_dir / "state.json").st_mode & 0o777) == "0o644"
    restores = [c for c in fw.fake.calls if c[1][0].endswith("-restore")]
    assert len(restores) == 4  # one per (family, table)
    assert all(c[1][1:] == ["-w", "10", "--noflush"] for c in restores)


def test_apply_stashes_the_emergency_script(fw):
    fw.write_conf("port=153\n")
    assert fw.run("apply") == 0
    copy = fw.run_dir / "emergency.sh"
    assert copy.read_bytes() == Path(fw.mod.EMERGENCY_SCRIPT).read_bytes()
    assert oct(os.stat(copy).st_mode & 0o777) == "0o644"
    assert not any("emergency" in w for w in fw.state()["warnings"])
    assert fw.run("revert") == 0
    assert copy.exists()  # kept: a later stop may still need it


@pytest.mark.parametrize("problem", ["missing", "not-a-script", "writable"])
def test_apply_without_a_usable_emergency_script_still_applies(fw, tmp_path, monkeypatch, problem):
    script = tmp_path / "badlib" / "blockads-fw-emergency.sh"
    script.parent.mkdir()
    if problem != "missing":
        script.write_text("#!/bin/sh\nexit 0\n" if problem == "writable" else "echo hi\n")
        os.chmod(script, 0o666 if problem == "writable" else 0o755)
    monkeypatch.setattr(fw.mod, "EMERGENCY_SCRIPT", str(script))
    fw.write_conf("port=153\n")
    assert fw.run("apply") == 0
    assert fw.state()["applied"] is True
    assert any("emergency script not copied" in w for w in fw.state()["warnings"])
    assert not (fw.run_dir / "emergency.sh").exists()


def test_apply_is_idempotent(fw):
    assert fw.run("apply", "--verify") == 0
    snapshot = json.dumps({str(k): {t: v.chains for t, v in tabs.items()} for k, tabs in fw.fake.state.items()},
                          sort_keys=True, default=str)
    assert fw.run("apply", "--verify") == 0
    again = json.dumps({str(k): {t: v.chains for t, v in tabs.items()} for k, tabs in fw.fake.state.items()},
                       sort_keys=True, default=str)
    assert snapshot == again


def test_apply_removes_duplicate_jumps_and_keeps_admin_rules(fw):
    fw.fake.add("nft", "ipv4", "nat", "OUTPUT", "-d 203.0.113.7/32 -j RETURN")
    fw.fake.add("nft", "ipv4", "nat", "BLOCKADS_DNS", "-j RETURN")
    for _ in range(3):
        fw.fake.add("nft", "ipv4", "nat", "OUTPUT", "-j BLOCKADS_DNS")
    assert fw.run("apply") == 0
    assert chain_count(fw, "ipv4", "nat", "OUTPUT", "BLOCKADS_DNS") == 1
    assert "-d 203.0.113.7/32 -j RETURN" in fw.rules("ipv4", "nat", "OUTPUT")
    # The admin rule came first and stays first: warn, never fight for position.
    assert any("not first" in w for w in fw.state()["warnings"])


def test_apply_warns_about_other_dns_nat(fw):
    fw.fake.add("nft", "ipv4", "nat", "OUTPUT", "-p udp -m udp --dport 53 -j DNAT --to-destination 10.0.0.1")
    assert fw.run("apply") == 0
    assert any("another DNS NAT rule" in w for w in fw.state()["warnings"])


def test_apply_refuses_unprivileged_port(fw):
    fw.proc_setup(unprivileged_start=100)
    assert fw.run("apply", "--verify") == 1
    assert fw.fake.leftovers() == []


def test_apply_refuses_without_listener(fw):
    fw.proc_setup(v4_ports=())
    assert fw.run("apply", "--verify") == 1
    assert fw.fake.leftovers() == []


def test_apply_without_iptables(fw):
    fw.missing |= {"iptables", "iptables-restore"}
    assert fw.run("apply") == 1


def test_v4_probe_failure_reverts_everything(fw):
    fw.probe_results["ipv4"] = ["udp: refused (not redirected)"]
    assert fw.run("apply", "--verify") == 1
    assert fw.fake.leftovers() == []
    state = fw.state()
    assert state["applied"] is False and "probe" in state["error"]


def test_v6_probe_failure_degrades_v6_only(fw):
    fw.probe_results["ipv6"] = ["tcp: timeout"]
    assert fw.run("apply", "--verify") == 0
    assert chain_count(fw, "ipv4", "nat", "OUTPUT", "BLOCKADS_DNS") == 1
    assert chain_count(fw, "ipv6", "nat", "OUTPUT", "BLOCKADS_DNS") == 0
    assert fw.rules("ipv6", "nat", "BLOCKADS_DNS") is None
    assert fw.state()["families"]["ipv6"]["status"] == "degraded"


def test_probe_skipped_without_verify(fw):
    fw.probe_results["ipv4"] = ["udp: timeout"]
    assert fw.run("apply") == 0


@pytest.mark.parametrize("ipv6, conf, status", [
    ("on", "ipv6=off\n", "disabled"),
    ("off", "", "unavailable"),
    ("empty", "", "unavailable"),
    ("no-lo", "", "degraded"),
])
def test_ipv6_not_eligible(fw, ipv6, conf, status):
    fw.fake.add("nft", "ipv6", "nat", "BLOCKADS_DNS", "-j RETURN")
    fw.fake.add("nft", "ipv6", "nat", "OUTPUT", "-j BLOCKADS_DNS")
    if conf:
        fw.write_conf(conf)
    fw.proc_setup(ipv6=ipv6)
    assert fw.run("apply", "--verify") == 0
    assert fw.state()["families"]["ipv6"]["status"] == status
    assert chain_count(fw, "ipv4", "nat", "OUTPUT", "BLOCKADS_DNS") == 1
    if status != "unavailable":
        assert chain_count(fw, "ipv6", "nat", "OUTPUT", "BLOCKADS_DNS") == 0  # stale v6 rules removed


def test_ipv6_degraded_without_listener_or_nat(fw):
    fw.proc_setup(v6_ports=())
    assert fw.run("apply") == 0
    assert "[::1]:153" in fw.state()["families"]["ipv6"]["reason"]
    fw.proc_setup()
    fw.fake.unsupported.add(("nft", "ipv6"))
    assert fw.run("apply") == 0
    assert "nat is not usable" in fw.state()["families"]["ipv6"]["reason"]


def test_ipv6_degraded_without_ip6tables(fw):
    fw.missing |= {"ip6tables", "ip6tables-restore"}
    assert fw.run("apply") == 0
    assert fw.state()["families"]["ipv6"] == {"status": "degraded", "reason": "ip6tables is not installed"}


def test_resolved_strict_dot_is_exempt(fw, monkeypatch):
    monkeypatch.setattr(fw.mod, "resolved_dot_mode", lambda: "yes")
    monkeypatch.setattr(fw.mod.pwd, "getpwnam", lambda name: type("E", (), {"pw_uid": RESOLVED_UID})())
    assert fw.run("apply") == 0
    assert f"-m owner --uid-owner {RESOLVED_UID} -j RETURN" in fw.rules("ipv4", "filter", "BLOCKADS_OUT")
    assert fw.state()["partial"] is True


def test_apply_removes_other_backend_leftovers(fw):
    fw.proc_setup(legacy_tables="nat\nfilter")
    fw.fake.add("legacy", "ipv4", "nat", "BLOCKADS_DNS", "-j RETURN")
    fw.fake.add("legacy", "ipv4", "nat", "OUTPUT", "-j BLOCKADS_DNS")
    assert fw.run("apply") == 0
    assert [x for x in fw.fake.leftovers() if x.startswith("legacy")] == []


def test_legacy_untouched_when_kernel_has_no_legacy_tables(fw):
    assert fw.run("apply") == 0
    assert not any("legacy" in exe for exe, _, _ in fw.fake.calls)
    assert fw.run("revert", "--all-backends") == 0
    assert not any("legacy" in exe for exe, _, _ in fw.fake.calls)


def test_legacy_backend_as_current(fw):
    fw.current = "legacy"
    fw.proc_setup(legacy_tables="nat\nfilter")
    assert fw.run("apply") == 0
    assert fw.state()["backend"] == "legacy"
    assert chain_count(fw, "ipv4", "nat", "OUTPUT", "BLOCKADS_DNS", backend="legacy") == 1
    assert fw.run("revert") == 0
    assert fw.fake.leftovers() == []


# --- bridge ------------------------------------------------------------------

def test_bridge_on(fw):
    fw.write_conf("bridge_interfaces=docker0,br-+\n")
    fw.proc_setup(any_ports=(154,))
    assert fw.run("apply") == 0
    for family in ("ipv4", "ipv6"):
        assert chain_count(fw, family, "nat", "PREROUTING", "BLOCKADS_BRIDGE") == 1
        assert chain_count(fw, family, "filter", "INPUT", "BLOCKADS_IN") == 1
    bridge = fw.state()["bridge"]
    assert bridge["status"] == "on" and bridge["interfaces"] == ["docker0", "br-+"]
    assert bridge["families"]["ipv4"] == {"status": "active"}
    # Turning it off removes the chains on the next apply.
    fw.write_conf("bridge_interfaces=\n")
    assert fw.run("apply") == 0
    assert fw.rules("ipv4", "nat", "BLOCKADS_BRIDGE") is None
    assert chain_count(fw, "ipv4", "filter", "INPUT", "BLOCKADS_IN") == 0


def test_bridge_without_listener_is_inactive(fw):
    fw.write_conf("bridge_interfaces=docker0\n")
    assert fw.run("apply") == 0
    assert fw.rules("ipv4", "nat", "BLOCKADS_BRIDGE") is None
    assert fw.state()["bridge"]["families"]["ipv4"]["status"] == "inactive"
    assert chain_count(fw, "ipv4", "nat", "OUTPUT", "BLOCKADS_DNS") == 1


def test_bridge_failure_keeps_main_protection(fw):
    fw.write_conf("bridge_interfaces=docker0\n")
    fw.proc_setup(any_ports=(154,))
    original = fw.fake._restore

    def restore(backend, family, text):
        if "BLOCKADS_IN" in text:
            return 1, "", "injected\n"
        return original(backend, family, text)

    fw.fake._restore = restore
    assert fw.run("apply") == 0
    assert chain_count(fw, "ipv4", "nat", "OUTPUT", "BLOCKADS_DNS") == 1
    assert fw.rules("ipv4", "nat", "BLOCKADS_BRIDGE") is None
    assert fw.state()["bridge"]["families"]["ipv4"]["status"] == "inactive"


# --- revert ------------------------------------------------------------------

def test_revert_removes_everything(fw):
    fw.write_conf("bridge_interfaces=docker0\n")
    fw.proc_setup(any_ports=(154,))
    assert fw.run("apply") == 0
    fw.fake.add("nft", "ipv4", "nat", "OUTPUT", "-o lo -j BLOCKADS_DNS")  # a non-exact jump
    fw.fake.add("nft", "ipv4", "filter", "OUTPUT", "-j BLOCKADS_OUT")      # a duplicate
    fw.fake.add("nft", "ipv4", "filter", "OUTPUT", "-p tcp -j ACCEPT")     # someone else's
    assert fw.run("revert") == 0
    assert fw.fake.leftovers() == []
    assert fw.rules("ipv4", "filter", "OUTPUT") == ["-p tcp -j ACCEPT"]
    assert fw.state()["applied"] is False
    assert fw.run("revert") == 0  # idempotent on a clean state


def test_revert_all_backends(fw):
    fw.proc_setup(legacy_tables="nat")
    for backend in ("nft", "legacy"):
        for family in ("ipv4", "ipv6"):
            fw.fake.add(backend, family, "nat", "BLOCKADS_DNS", "-j RETURN")
            fw.fake.add(backend, family, "nat", "OUTPUT", "-j BLOCKADS_DNS")
    assert fw.run("revert") == 0
    assert all(x.startswith("legacy") for x in fw.fake.leftovers())
    assert fw.run("revert", "--all-backends") == 0
    assert fw.fake.leftovers() == []


def test_revert_follows_the_recorded_backend(fw):
    fw.proc_setup(legacy_tables="nat")
    fw.current = "legacy"
    assert fw.run("apply") == 0
    fw.current = "nft"  # e.g. update-alternatives switched since
    assert fw.run("revert") == 0
    assert fw.fake.leftovers() == []


def test_revert_historical_chains(fw, monkeypatch):
    monkeypatch.setattr(fw.mod, "HISTORICAL_HOOKS", (("nat", "OUTPUT", "BLOCKADS_OLD"),))
    fw.fake.add("nft", "ipv4", "nat", "BLOCKADS_OLD", "-j RETURN")
    fw.fake.add("nft", "ipv4", "nat", "OUTPUT", "-j BLOCKADS_OLD")
    assert fw.run("revert") == 0
    assert fw.fake.leftovers() == []


def test_revert_reports_what_is_left(fw):
    assert fw.run("apply") == 0
    fw.fake.fail_if = lambda backend, argv: "-X" in argv and "BLOCKADS_OUT" in argv
    assert fw.run("revert") == 1
    state = fw.state()
    assert any("BLOCKADS_OUT" in item for item in state["left"])
    # Everything else was still removed: revert never stops early.
    assert chain_count(fw, "ipv4", "nat", "OUTPUT", "BLOCKADS_DNS") == 0
    assert chain_count(fw, "ipv6", "nat", "OUTPUT", "BLOCKADS_DNS") == 0
    assert chain_count(fw, "ipv4", "filter", "OUTPUT", "BLOCKADS_OUT") == 0


def test_revert_timeout_is_not_clean(fw):
    assert fw.run("apply") == 0
    fw.fake.fail_on = {len(fw.fake.calls) + 1: "timeout"}
    rc = fw.run("revert")
    # The first -S timed out: revert retries the listing and still cleans.
    assert rc in (0, 1)
    if rc == 0:
        assert fw.fake.leftovers() == []


def test_revert_without_lock_holder_waits_then_proceeds(fw):
    fw.run_dir.mkdir(mode=0o755)
    import fcntl
    holder = os.open(fw.run_dir / "lock", os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(holder, fcntl.LOCK_EX)
    try:
        assert fw.run("apply") == 1  # apply needs the lock
        assert fw.run("revert") == 0  # revert proceeds anyway
    finally:
        os.close(holder)


# --- fault injection: fail or time out on the N-th call -------------------------

@pytest.mark.parametrize("fault", ["fail", "timeout"])
def test_fault_on_every_call(fw, fault):
    fw.write_conf("bridge_interfaces=docker0\n")
    fw.proc_setup(any_ports=(154,))
    assert fw.run("apply", "--verify") == 0
    total = len(fw.fake.calls)
    assert total > 20
    for n in range(1, total + 1):
        fw.fake.state.clear()
        fw.fake.calls.clear()
        fw.fake.fail_on = {n: fault}
        rc = fw.run("apply", "--verify")
        fw.fake.fail_on = {}
        state = fw.state()
        if rc == 0:
            # Whatever survived is complete and verified for IPv4.
            assert chain_count(fw, "ipv4", "nat", "OUTPUT", "BLOCKADS_DNS") == 1, n
            assert len(fw.rules("ipv4", "nat", "BLOCKADS_DNS")) == 7, n
            assert chain_count(fw, "ipv4", "filter", "OUTPUT", "BLOCKADS_OUT") == 1, n
            for family in ("ipv6",):
                if state["families"][family]["status"] == "active":
                    assert chain_count(fw, family, "nat", "OUTPUT", "BLOCKADS_DNS") == 1, n
                else:
                    assert chain_count(fw, family, "nat", "OUTPUT", "BLOCKADS_DNS") == 0, n
        else:
            assert rc == 1, n
            # Fail-open: nothing left, or honestly reported.
            assert fw.fake.leftovers() == [] or state.get("left"), (n, fw.fake.leftovers())
        # A clean revert afterwards always succeeds.
        assert fw.run("revert") == 0, n
        assert fw.fake.leftovers() == [], n


# --- set-config --------------------------------------------------------------

def test_set_config(fw):
    fw.write_conf(fw.mod.render_config(fw.mod.validate_config({"port": 253})))
    assert fw.run("set-config", stdin='{"block_webrtc": true, "bypass_cidrs": ["10.0.0.0/8"]}') == 0
    cfg, _ = fw.mod.read_config()
    assert cfg["block_webrtc"] is True and cfg["bypass_cidrs"] == ["10.0.0.0/8"]
    assert cfg["port"] == 253  # admin value kept
    assert oct(os.stat(fw.conf).st_mode & 0o777) == "0o644"
    assert fw.fake.systemctl == []


def test_set_config_toggles_bridge_socket(fw):
    assert fw.run("set-config", stdin='{"bridge_interfaces": ["docker0"]}') == 0
    assert fw.fake.systemctl[-1] == ["systemctl", "enable", "--now", "blockadsd-bridge.socket"]
    assert fw.run("set-config", stdin='{"bridge_interfaces": []}') == 0
    assert fw.fake.systemctl[-1] == ["systemctl", "disable", "--now", "blockadsd-bridge.socket"]


def test_set_config_bridge_restarts_a_running_daemon(fw):
    # systemd refuses to start a socket whose service is active: stop, toggle, start.
    fw.fake.service_active = True
    assert fw.run("set-config", stdin='{"bridge_interfaces": ["docker0"]}') == 0
    assert fw.fake.systemctl[1:] == [["systemctl", "stop", "blockadsd.service"],
                                     ["systemctl", "enable", "--now", "blockadsd-bridge.socket"],
                                     ["systemctl", "reset-failed", "blockadsd.service"],
                                     ["systemctl", "start", "blockadsd.service"]]
    fw.fake.systemctl.clear()
    assert fw.run("set-config", stdin='{"block_dot": false}') == 0
    assert fw.fake.systemctl == []  # other keys: no restart


def test_set_config_bridge_starts_the_daemon_even_if_the_socket_fails(fw, monkeypatch):
    fw.fake.service_active = True
    calls = []

    def run_cmd(exe, argv, input_text=None, timeout=None):
        calls.append(argv[1:])
        if argv[1] == "is-active":
            return 0, "", ""
        return (1, "", "boom") if argv[1] == "enable" else (0, "", "")
    monkeypatch.setattr(fw.mod, "run_cmd", run_cmd)
    assert fw.mod.set_bridge_socket(True) == 1
    assert calls[-1] == ["start", "blockadsd.service"]


@pytest.mark.parametrize("payload", [
    '{"port": 253}',
    '{"bridge_port": 200}',
    '{"color": 1}',
    '{"block_dot": "false"}',
    '{"bypass_cidrs": "10.0.0.0/8"}',
    '{"bridge_interfaces": ["+"]}',
    '[]',
    '{}',
    'not json',
    '{"ipv6": "on"}',
])
def test_set_config_rejects(fw, payload):
    fw.write_conf("block_dot=true\n")
    before = fw.conf.read_text()
    assert fw.run("set-config", stdin=payload) == 2
    assert fw.conf.read_text() == before


def test_set_config_rejects_huge_input(fw):
    assert fw.run("set-config", stdin='{"bypass_cidrs": [' + '"10.0.0.0/8",' * 3000 + '"10.0.0.0/8"]}') == 2


# --- status and doctor ---------------------------------------------------------

def test_status_and_doctor(fw, capsys, monkeypatch):
    assert fw.run("status") == 0
    assert "never applied" in capsys.readouterr().out
    assert fw.run("apply") == 0
    capsys.readouterr()
    assert fw.run("status", "--json") == 0
    report = json.loads(capsys.readouterr().out)
    assert report["state"]["applied"] is True
    monkeypatch.setattr(fw.mod.os, "geteuid", lambda: 0)
    assert fw.run("status") == 0
    out = capsys.readouterr().out
    assert "ipv4: active" in out and "live (nft)" in out
    assert fw.run("doctor", "--json") == 0
    checks = {c["check"]: c for c in json.loads(capsys.readouterr().out)}
    assert checks["iptables"]["level"] == "ok"
    assert checks["jumps ipv4"]["level"] == "ok"
    assert checks["listener ipv4"]["level"] == "ok"


def test_doctor_reports_failures(fw, capsys):
    fw.proc_setup(v4_ports=())
    fw.write_conf("port=99999\n")
    assert fw.run("doctor") == 1
    out = capsys.readouterr().out
    assert "FAIL  config" in out and "FAIL  listener ipv4" in out


def test_doctor_warns_about_saved_rulesets(fw, capsys, monkeypatch):
    saved = fw.tmp / "rules.v4"
    saved.write_text("*nat\n-A OUTPUT -j BLOCKADS_DNS\nCOMMIT\n")
    monkeypatch.setattr(fw.mod, "SAVED_RULESETS", (str(saved),))
    fw.run("doctor")
    assert "saved ruleset" in capsys.readouterr().out


def test_usage_errors(fw):
    assert fw.run() == 2
    assert fw.run("frobnicate") == 2


def test_internal_error_reverts(fw, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("boom")

    original = fw.mod.collect_warnings
    monkeypatch.setattr(fw.mod, "collect_warnings", boom)
    assert fw.run("apply") == 1
    assert fw.fake.leftovers() == []
    monkeypatch.setattr(fw.mod, "collect_warnings", original)


def test_emergency_script_shape():
    text = (Path(__file__).resolve().parents[2] / "helper" / "blockads-fw-emergency.sh").read_text()
    assert text.startswith("#!/bin/sh")
    for chain in ("BLOCKADS_DNS", "BLOCKADS_OUT", "BLOCKADS_BRIDGE", "BLOCKADS_IN"):
        assert chain in text
    assert "eval" not in text.replace("evaluates", "")
    # /proc files report size 0, so `[ -s /proc/net/ip_tables_names ]` is always false
    # (found in VM testing: the script silently skipped legacy).
    assert '[ -s "$names" ]' not in text
