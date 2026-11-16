"""Tests for daemon.state (settings, rules and manifest -> pipeline policy)."""

import asyncio
import os
import re
import signal
import sys

import dns.message
import dns.rcode
import dns.rdatatype
import pytest

from blockads_linux.common.atomic import write_json
from blockads_linux.common.paths import Paths
from blockads_linux.daemon.logstore import LogStore
from blockads_linux.daemon.state import StateManager, list_hosts, settings_upstream_config, upstream_config
from blockads_linux.filters.artifact import ArtifactBuilder
from blockads_linux.filters.catalog import Catalog, CatalogEntry
from blockads_linux.filters.parser import iter_list_rules
from blockads_linux.updater import manifest as mf
from blockads_linux.common.settings import Settings

from .upstreams import UdpServer

CATALOG = Catalog("t", (
    CatalogEntry("sec_list", "Sec", "", "security", "https://sec.example.org/list.txt", False, False, 0),
    CatalogEntry("ads_list", "Ads", "", "ads", "https://lists.example.net/ads.txt", False, False, 0),
    CatalogEntry("gone", "Gone", "", "ads", "https://old.example/x", False, False, 0, "retired"),
))


def compile_into(paths, lines):
    builder = ArtifactBuilder()
    builder.add_rules(iter_list_rules(lines))
    return builder.write(paths.artifacts, source_sha256=b"\0" * 32, compiled_at=1)


def setup_state(tmp_path, *, enabled=("sec_list", "ads_list"), dns=None, rules=None, protection=None):
    paths = Paths(tmp_path / "state")
    paths.ensure()
    write_json(paths.settings, {"schema": 1, "filters": {"enabled": list(enabled), "custom": [
        {"id": "custom_mine", "name": "Mine", "urls": ["https://mine.example.com/l.txt"]}]},
        "dns": dns or {}, "protection": protection or {}})
    if rules is not None:
        write_json(paths.rules, {"schema": 1, "rules": rules, "whitelist": []})
    sec = compile_into(paths, ["0.0.0.0 malware.example", "0.0.0.0 both.example"])
    ads = compile_into(paths, ["||ads.example^", "||both.example^"])
    mf.publish(paths.manifest, paths.previous_manifest, mf.Manifest(lists={
        "sec_list": mf.ListEntry(sec.name, sec.block_count), "ads_list": mf.ListEntry(ads.name, ads.block_count)}))
    return paths


def bump(path):
    """Make sure a rewrite is seen even on coarse mtime file systems."""
    st = os.stat(path)
    os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns + 10**9))


def test_policy_from_state(tmp_path):
    paths = setup_state(tmp_path, dns={"block_mode": "nxdomain", "block_ttl": 60, "safesearch": True},
                        rules=["||custom.example^", "@@||ads.example^"])
    state = StateManager(paths, catalog=CATALOG)
    policy = state.load()
    assert policy.matcher.match("x.malware.example").lists == ("sec_list",)
    assert policy.matcher.match("both.example").lists == ("sec_list", "ads_list")  # security first
    assert policy.block_mode.value == "nxdomain" and policy.block_ttl == 60 and policy.safesearch
    assert policy.custom.verdict("custom.example").value == "block"
    assert policy.custom.verdict("ads.example").value == "allow"
    assert policy.internal_allow == {"sec.example.org", "lists.example.net", "mine.example.com"}
    assert state.missing == ("custom_mine",)  # enabled, never downloaded
    assert paths.update_request.exists()


def test_reload_on_change_and_artifact_reuse(tmp_path):
    paths = setup_state(tmp_path)
    policies = []
    state = StateManager(paths, catalog=CATALOG, on_policy=policies.append)
    state.load()
    first = state.policy.matcher
    assert not state.check()  # nothing changed
    write_json(paths.rules, {"schema": 1, "rules": ["||new.example^"]})
    bump(paths.rules)
    assert state.check()
    state.notify()
    assert policies[-1].custom.verdict("new.example").value == "block"
    assert state.policy.matcher is first  # rules only: same matcher (and verdict cache)
    # A new manifest generation swaps the matcher; unchanged artifacts are not reopened.
    sec_artifact = state._artifacts[mf.load_manifest(paths.manifest).lists["sec_list"].artifact]
    extra = compile_into(paths, ["0.0.0.0 extra.example"])
    current = mf.load_manifest(paths.manifest)
    lists = dict(current.lists, ads_list=mf.ListEntry(extra.name, 1))
    mf.publish(paths.manifest, paths.previous_manifest, mf.Manifest(lists=lists))
    bump(paths.manifest)
    assert state.check()
    assert state.policy.matcher is not first
    assert state.policy.matcher.match("extra.example").blocked
    assert not state.policy.matcher.match("ads.example").blocked
    assert state._artifacts[current.lists["sec_list"].artifact] is sec_artifact
    # Disabling a list takes effect without the updater.
    write_json(paths.settings, {"schema": 1, "filters": {"enabled": ["ads_list"]}})
    bump(paths.settings)
    state.check()
    assert not state.policy.matcher.match("malware.example").blocked


def test_upstream_settings(tmp_path):
    configs = []
    paths = setup_state(tmp_path)
    state = StateManager(paths, catalog=CATALOG, on_upstreams=configs.append)
    state.load()
    assert configs == [] and [s.address for s in state.upstream_config.configured] == ["9.9.9.9", "149.112.112.112"]
    write_json(paths.settings, {"schema": 1, "dns": {"upstream": ["udp://192.0.2.53"], "fallback": []}})
    bump(paths.settings)
    state.check()
    state.notify()
    assert [s.address for s in configs[-1].configured] == ["192.0.2.53"] and configs[-1].fallback == ()
    write_json(paths.settings, {"schema": 1, "dns": {"upstream": ["udp://192.0.2.53"], "encrypted_only": True}})
    bump(paths.settings)
    state.check()
    assert any("using quad9" in p for p in state.problems)
    assert state.upstream_config.configured[0].protocol == "https"


def test_pause_expires(tmp_path):
    clock = [1000.0]
    paths = setup_state(tmp_path, protection={"paused": True, "pause_until": 2000})
    state = StateManager(paths, catalog=CATALOG, clock=lambda: clock[0])
    assert state.load().paused
    assert not state.check()
    clock[0] = 2000
    assert state.check() and not state.policy.paused


def test_missing_artifact_file(tmp_path):
    paths = setup_state(tmp_path)
    for artifact in paths.artifacts.iterdir():
        artifact.unlink()
    state = StateManager(paths, catalog=CATALOG)
    state.load()
    assert set(state.missing) == {"sec_list", "ads_list", "custom_mine"}
    assert state.policy.matcher.rule_count == 0


def test_helpers():
    settings, _ = Settings.from_dict({"schema": 1, "filters": {"enabled": ["sec_list", "gone", "nope"]}})
    assert list_hosts(settings, CATALOG) == {"sec.example.org", "old.example"}
    config, problem = settings_upstream_config(settings)
    assert problem == "" and config.configured
    assert upstream_config(["system"], None).system
    with pytest.raises(ValueError):
        upstream_config(["system", "quad9"], None)


def test_daemon_in_state_mode(tmp_path):
    """End to end: settings, rules and lists from a state directory; the log is written."""
    paths = setup_state(tmp_path, rules=["||custom.example^"])

    async def body():
        upstream = await UdpServer().start()
        write_json(paths.settings, {"schema": 1, "filters": {"enabled": ["easylist"]},
                                    "dns": {"upstream": [f"udp://127.0.0.1:{upstream.port}"], "fallback": []}})
        # The real catalog: use one of its ids in the manifest.
        current = mf.load_manifest(paths.manifest)
        mf.publish(paths.manifest, paths.previous_manifest,
                   mf.Manifest(lists={"easylist": current.lists["ads_list"]}))
        env = dict(os.environ, PYTHONPATH=os.pathsep.join(sys.path))
        process = await asyncio.create_subprocess_exec(
            sys.executable, "-m", "blockads_linux.daemon", "--dev", "--listen", "127.0.0.1:0", "--no-netmon",
            "--state-dir", str(paths.root), "--state-poll", "0.1", stderr=asyncio.subprocess.PIPE, env=env)
        lines = []
        try:
            port = None
            while port is None:
                line = (await asyncio.wait_for(process.stderr.readline(), 10)).decode()
                assert line, "daemon exited early:\n" + "".join(lines)
                lines.append(line)
                match = re.search(r"serving DNS on udp \('127\.0\.0\.1', (\d+)\)", line)
                port = int(match.group(1)) if match else None

            async def ask(name):
                reply = await asyncio.to_thread(query_udp, name, port)
                return dns.rcode.to_text(reply.rcode()), [r.to_text() for rr in reply.answer for r in rr]

            assert await ask("ads.example") == ("NOERROR", ["0.0.0.0"])
            assert await ask("custom.example") == ("NOERROR", ["0.0.0.0"])
            assert await ask("fine.example") == ("NOERROR", ["192.0.2.1"])
            write_json(paths.rules, {"schema": 1, "rules": ["||fine.example^"]})
            bump(paths.rules)
            for _ in range(50):
                await asyncio.sleep(0.1)
                if (await ask("fine.example"))[1] == ["0.0.0.0"]:
                    break
            else:
                pytest.fail("rule change not picked up")
            process.send_signal(signal.SIGTERM)
            assert await asyncio.wait_for(process.wait(), 10) == 0
        finally:
            if process.returncode is None:
                process.kill()
                await process.wait()
            upstream.close()
        store = LogStore(paths.db)
        names = [(r["name"], r["verdict"]) for r in store.query_log()]
        assert ("ads.example", "blocked") in names and ("fine.example", "forwarded") in names
        assert store.totals(0)["blocked"] >= 3

    asyncio.run(body())


def query_udp(name, port):
    import dns.query

    return dns.query.udp(dns.message.make_query(name, dns.rdatatype.A), "127.0.0.1", port=port, timeout=3)


HOME = "11111111-2222-4333-8444-555555555555"


@pytest.mark.parametrize("mode", ["pause", "network_dns"])
def test_trusted_network(tmp_path, mode):
    paths = setup_state(tmp_path)
    document = Settings().to_dict()
    document["filters"]["enabled"] = ["sec_list", "ads_list"]
    document["trusted_networks"] = [{"uuid": HOME, "name": "Home", "mode": mode}]
    write_json(paths.settings, document)
    policies = []
    manager = StateManager(paths, catalog=CATALOG, on_policy=policies.append)
    manager.load()
    assert manager.upstream_config.network_dns_uuids == (frozenset({HOME}) if mode == "network_dns" else frozenset())
    assert manager.protection_state == "active" and manager.trusted is None
    manager.set_network(HOME)
    assert manager.trusted.name == "Home"
    if mode == "pause":
        assert manager.protection_state == "trusted" and not manager.paused
        assert policies[-1].paused and policies[-1].pause_reason == "trusted_network"
    else:
        assert manager.protection_state == "active" and not policies[-1].paused
    manager.set_network("other")
    assert manager.protection_state == "active" and not policies[-1].paused


@pytest.mark.parametrize("mode", ["pause", "network_dns"])
def test_trusted_network_pinned_to_an_access_point(tmp_path, mode):
    paths = setup_state(tmp_path)
    document = Settings().to_dict()
    document["filters"]["enabled"] = ["sec_list", "ads_list"]
    document["trusted_networks"] = [{"uuid": HOME, "name": "Home", "mode": mode, "bssid": "aa:bb:cc:dd:ee:01"}]
    write_json(paths.settings, document)
    policies = []
    manager = StateManager(paths, catalog=CATALOG, on_policy=policies.append)
    manager.load()
    if mode == "network_dns":
        assert manager.upstream_config.network_dns_pins == frozenset({(HOME, "aa:bb:cc:dd:ee:01")})
    manager.set_network(HOME, "aa:bb:cc:dd:ee:02")  # same connection profile, another access point
    assert manager.trusted is None and manager.protection_state == "active"
    manager.set_network(HOME, "AA:BB:CC:DD:EE:01")
    assert manager.trusted.name == "Home"
    assert manager.protection_state == ("trusted" if mode == "pause" else "active")
    manager.set_network(HOME, "")  # access point unknown: not trusted
    assert manager.trusted is None and not policies[-1].paused
