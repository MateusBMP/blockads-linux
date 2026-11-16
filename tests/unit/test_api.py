"""Tests for daemon.api (what the D-Bus methods do), without a bus."""

import asyncio
import json
import os

import pytest

from blockads_linux.common.atomic import load_json, write_json
from blockads_linux.common.dbus_api import MAX_PAUSE_SECONDS, csv_cell, csv_rows
from blockads_linux.daemon.api import ApiError, DaemonApi
from blockads_linux.daemon.logstore import LogStore
from blockads_linux.daemon.pipeline import QueryEvent, Verdict
from blockads_linux.daemon.state import StateManager

from .test_state import CATALOG, setup_state

NOW = 1_800_000_000.0


def make_api(tmp_path, *, store=False, **kwargs):
    paths = setup_state(tmp_path, **kwargs)
    state = StateManager(paths, catalog=CATALOG, clock=lambda: NOW)
    state.load()
    log_store = None
    if store:
        log_store = LogStore(paths.db, clock=lambda: NOW)
        log_store.start()
    return DaemonApi(state, store=log_store, health=None, forwarder=None, clock=lambda: NOW), paths


def run(coroutine):
    return asyncio.run(coroutine)


def call(api, name, *args):
    async def go():
        return await getattr(api, name)(*args)
    return run(go())


def decoded(text):
    document = json.loads(text)
    assert document["api"] == 1
    return document


def settings_on_disk(paths):
    return load_json(paths.settings, lambda d: d).document


def rules_on_disk(paths):
    return load_json(paths.rules, lambda d: d).document


def test_status_and_settings(tmp_path):
    api, _ = make_api(tmp_path)
    status = decoded(call(api, "GetStatus"))
    assert status["protection"] == {"state": "active", "paused_until": 0, "trusted_network": None}
    assert status["filters"]["lists"] == 2 and status["filters"]["rules"] == 4
    assert status["alerts"] == [] and "bridge" not in status
    api.bridge = lambda: {"patterns": ["docker0"], "interfaces": ["docker0"], "subnets": 1,
                          "allowed": 5, "denied": 2, "dropped": 2}
    assert decoded(call(api, "GetStatus"))["bridge"]["allowed"] == 5
    settings = decoded(call(api, "GetSettings"))
    assert settings["settings"]["schema"] == 1 and settings["read_only"] is False
    rules = decoded(call(api, "GetRules"))
    assert rules["counts"] == {"block": 0, "allow": 0, "whitelist": 0}


def test_pause_and_resume(tmp_path):
    api, paths = make_api(tmp_path)
    call(api, "Pause", 900)
    assert settings_on_disk(paths)["protection"] == {"paused": True, "pause_until": int(NOW) + 900}
    assert api.state.policy.paused
    status = decoded(call(api, "GetStatus"))
    assert status["protection"] == {"state": "paused", "paused_until": int(NOW) + 900, "trusted_network": None}
    call(api, "Resume")
    assert settings_on_disk(paths)["protection"] == {"paused": False, "pause_until": 0}
    assert not api.state.policy.paused
    call(api, "Pause", 0)  # until resumed
    assert settings_on_disk(paths)["protection"] == {"paused": True, "pause_until": 0}
    with pytest.raises(ApiError) as err:
        call(api, "Pause", MAX_PAUSE_SECONDS + 1)
    assert err.value.kind == "InvalidArgs"


def test_rules_add_remove_and_verdicts(tmp_path):
    api, paths = make_api(tmp_path)
    assert decoded(call(api, "TestDomain", "x.ads.example"))["verdict"] == "blocked"
    assert decoded(call(api, "TestDomain", "x.ads.example"))["lists"] == ["ads_list"]
    call(api, "AddBlockRule", "Tracker.Example.")
    call(api, "AddBlockRule", "tracker.example")  # no duplicate
    call(api, "AddAllowRule", "ads.example")
    assert rules_on_disk(paths)["rules"] == ["||tracker.example^", "@@||ads.example^"]
    assert decoded(call(api, "TestDomain", "a.tracker.example"))["reason"] == "custom"
    assert decoded(call(api, "TestDomain", "x.ads.example")) | {} == {
        "api": 1, "domain": "x.ads.example", "verdict": "allowed", "reason": "custom_allow", "lists": [],
        "matched": "", "paused": False}
    call(api, "RemoveAllowRule", "ads.example")
    call(api, "RemoveBlockRule", "tracker.example")
    assert rules_on_disk(paths)["rules"] == []
    assert decoded(call(api, "TestDomain", "fine.example"))["verdict"] == "allowed"
    assert decoded(call(api, "TestDomain", "use-application-dns.net"))["verdict"] == "local"
    for bad in ("", "bad..name", "a" * 300, "||x^"):
        with pytest.raises(ApiError):
            call(api, "AddBlockRule", bad)
        with pytest.raises(ApiError):
            call(api, "TestDomain", bad)


def test_remove_allow_rule_also_removes_the_whitelist_entry(tmp_path):
    api, paths = make_api(tmp_path)
    write_json(paths.rules, {"schema": 1, "rules": ["@@allowed.example"], "whitelist": ["allowed.example"]})
    call(api, "RemoveAllowRule", "allowed.example")
    assert rules_on_disk(paths) == {"schema": 1, "rules": [], "whitelist": []}


def test_filters_enable_disable(tmp_path):
    api, paths = make_api(tmp_path, enabled=("sec_list",))
    call(api, "EnableFilters", ["ads_list"])
    assert settings_on_disk(paths)["filters"]["enabled"] == ["sec_list", "ads_list"]
    assert api.state.policy.matcher.list_ids == ("sec_list", "ads_list") or set(
        api.state.policy.matcher.list_ids) == {"sec_list", "ads_list"}
    call(api, "DisableFilters", ["sec_list", "custom_mine"])
    on_disk = settings_on_disk(paths)["filters"]
    assert on_disk["enabled"] == ["ads_list"]
    assert on_disk["custom"][0]["enabled"] is False
    for ids in (["nope"], ["ads_list", "nope"]):
        with pytest.raises(ApiError, match="unknown list id"):
            call(api, "EnableFilters", ids)
    with pytest.raises(ApiError, match="retired"):
        call(api, "EnableFilters", ["gone"])
    catalog = decoded(call(api, "GetFilterCatalog"))
    by_id = {entry["id"]: entry for entry in catalog["lists"]}
    assert by_id["ads_list"]["enabled"] and by_id["ads_list"]["downloaded"] and by_id["ads_list"]["rules"] == 2
    assert not by_id["sec_list"]["enabled"]
    assert by_id["gone"]["retired"]
    assert catalog["custom"][0]["id"] == "custom_mine"


def test_update_now_touches_the_request_file(tmp_path):
    api, paths = make_api(tmp_path)
    if paths.update_request.exists():
        paths.update_request.unlink()
    call(api, "UpdateFiltersNow")
    assert paths.update_request.exists()


def test_features(tmp_path):
    api, paths = make_api(tmp_path)
    call(api, "EnableFeature", "safesearch")
    assert settings_on_disk(paths)["dns"]["safesearch"] is True and api.state.policy.safesearch
    call(api, "DisableFeature", "cname_check")
    assert settings_on_disk(paths)["dns"]["cname_check"] is False
    with pytest.raises(ApiError):
        call(api, "EnableFeature", "logging")


def test_set_upstream(tmp_path):
    api, paths = make_api(tmp_path)
    seen = []
    api.state.on_upstreams = seen.append
    call(api, "SetUpstream", json.dumps({"upstream": ["cloudflare"], "encrypted_only": True}))
    assert settings_on_disk(paths)["dns"]["upstream"] == ["cloudflare"]
    assert seen and seen[-1].encrypted_only
    for bad in ('{"upstream": ["udp://not-an-ip"]}', '{"upstream": ["system", "quad9"]}', '{"nope": 1}',
                "[]", "not json", '{"encrypted_only": "yes"}'):
        with pytest.raises(ApiError) as err:
            call(api, "SetUpstream", bad)
        assert err.value.kind == "InvalidArgs", bad
    assert settings_on_disk(paths)["dns"]["upstream"] == ["cloudflare"]


def test_custom_filters(tmp_path):
    api, paths = make_api(tmp_path)
    first = call(api, "AddCustomFilter", json.dumps({"name": "My List!", "urls": ["https://l.example.org/a.txt"]}))
    second = call(api, "AddCustomFilter", json.dumps({"name": "My List!", "urls": ["https://l.example.org/b.txt"]}))
    assert (first, second) == ("custom_my_list", "custom_my_list_1")
    assert [c["id"] for c in settings_on_disk(paths)["filters"]["custom"]] == [
        "custom_mine", "custom_my_list", "custom_my_list_1"]
    for bad in ({"name": "x", "urls": ["http://plain.example/x"]}, {"name": "x", "urls": []}, {"name": "x"}):
        with pytest.raises(ApiError):
            call(api, "AddCustomFilter", json.dumps(bad))
    call(api, "RemoveCustomFilter", first)
    with pytest.raises(ApiError):
        call(api, "RemoveCustomFilter", first)
    assert [c["id"] for c in settings_on_disk(paths)["filters"]["custom"]] == ["custom_mine", "custom_my_list_1"]


def test_misc_setters(tmp_path):
    api, paths = make_api(tmp_path)
    call(api, "SetBlockedResponse", "nxdomain", 60)
    call(api, "SetFilterSchedule", 12, True)
    call(api, "SetLogging", False, 30)
    call(api, "SetTrustedNetworks", json.dumps({"networks": [{"uuid": "0123abcd-0000", "name": "Home"}]}))
    on_disk = settings_on_disk(paths)
    assert on_disk["dns"]["block_mode"] == "nxdomain" and on_disk["dns"]["block_ttl"] == 60
    assert on_disk["filters"]["update_interval_hours"] == 12 and on_disk["filters"]["unmetered_only"]
    assert on_disk["logging"] == {"enabled": False, "retention_days": 30}
    assert on_disk["trusted_networks"] == [{"uuid": "0123abcd-0000", "name": "Home", "mode": "pause"}]
    for name, args in (("SetBlockedResponse", ("bogus", 10)), ("SetBlockedResponse", ("null_ip", 10**6)),
                       ("SetFilterSchedule", (5, False)), ("SetLogging", (True, 0)),
                       ("SetTrustedNetworks", ('{"networks": [{"uuid": "!"}]}',))):
        with pytest.raises(ApiError):
            call(api, name, *args)
    assert settings_on_disk(paths) == on_disk


def test_import_backup_is_all_or_nothing_and_reset(tmp_path):
    api, paths = make_api(tmp_path)
    before = settings_on_disk(paths)
    bad = {"settings": {"schema": 1, "dns": {"block_ttl": -1}}, "rules": {"rules": ["||ok.example^"]}}
    with pytest.raises(ApiError):
        call(api, "ImportBackup", json.dumps(bad))
    assert settings_on_disk(paths) == before and not paths.rules.exists()
    good = {"settings": {"schema": 1, "dns": {"safesearch": True}}, "rules": {"rules": ["||ok.example^"]}}
    call(api, "ImportBackup", json.dumps(good))
    assert settings_on_disk(paths)["dns"]["safesearch"] is True
    assert rules_on_disk(paths)["rules"] == ["||ok.example^"]
    call(api, "ResetSettings")
    assert settings_on_disk(paths)["dns"]["safesearch"] is False


def test_newer_settings_are_never_overwritten(tmp_path):
    api, paths = make_api(tmp_path)
    write_json(paths.settings, {"schema": 99, "dns": {"safesearch": True}})
    os.utime(paths.settings, ns=(0, 10**9))
    with pytest.raises(ApiError) as err:
        call(api, "Pause", 60)
    assert err.value.kind == "ReadOnly"
    assert settings_on_disk(paths)["schema"] == 99
    assert decoded(call(api, "GetStatus"))["read_only"] is True


def test_hand_edit_is_not_lost(tmp_path):
    api, paths = make_api(tmp_path)
    document = settings_on_disk(paths)
    document["dns"]["youtube_restricted"] = True
    write_json(paths.settings, document)
    os.utime(paths.settings, ns=(0, 10**9))
    call(api, "Pause", 60)
    on_disk = settings_on_disk(paths)
    assert on_disk["dns"]["youtube_restricted"] is True and on_disk["protection"]["paused"] is True


def test_query_log_and_statistics(tmp_path):
    api, _ = make_api(tmp_path, store=True)
    try:
        assert decoded(call(api, "GetQueryLog", "", 0, 10))["entries"] == []  # no database yet
        for name, verdict in (("a.example", Verdict.FORWARDED), ("ads.example", Verdict.BLOCKED)):
            event = QueryEvent(name, 1, verdict, "ads_list" if verdict is Verdict.BLOCKED else "", 0)
            api.store.submit(event)
        api.store.flush()
        page = decoded(call(api, "GetQueryLog", "{}", 0, 10))
        assert [e["name"] for e in page["entries"]] == ["a.example", "ads.example"]
        blocked = decoded(call(api, "GetQueryLog", json.dumps({"verdict": "blocked"}), 0, 10**6))
        assert [e["name"] for e in blocked["entries"]] == ["ads.example"]
        for bad in ('{"verdict": "nope"}', '{"x": 1}', '{"before_id": -1}', '[1]'):
            with pytest.raises(ApiError):
                call(api, "GetQueryLog", bad, 0, 10)
        top = decoded(call(api, "GetTopDomains", 1, True, 10))
        assert top["domains"] == [{"name": "ads.example", "count": 1}]
        stats = decoded(call(api, "GetStatistics", "24h"))
        assert stats["totals"]["total"] == 2 and stats["totals"]["blocked"] == 1
        assert len(stats["series"]) == 24
        with pytest.raises(ApiError):
            call(api, "GetStatistics", "1y")
        with pytest.raises(ApiError):
            call(api, "GetTopDomains", 0, True, 10)
        status = decoded(call(api, "GetStatus"))
        assert status["log"] == {"recording": True, "dropped": 0}
        call(api, "ClearQueryLog")
        assert decoded(call(api, "GetQueryLog", "{}", 0, 10))["entries"] == []
    finally:
        api.store.stop()


def test_csv_guard():
    assert csv_cell("=cmd|' /C calc'!A0") == "'=cmd|' /C calc'!A0"
    assert csv_cell("+1") == "'+1" and csv_cell("@x") == "'@x" and csv_cell("ok.example") == "ok.example"
    assert csv_cell(["1.2.3.4", "::1"]) == "1.2.3.4;::1"
    text = csv_rows([{"id": 1, "name": "=evil.example", "answers": []}])
    assert text.splitlines()[1].startswith("1,,'=evil.example")


def test_status_on_a_trusted_network(tmp_path):
    from blockads_linux.daemon.netmon import LinkDns, NetworkState
    from blockads_linux.daemon.upstream.policy import UpstreamPolicy

    api, paths = make_api(tmp_path)
    home = "11111111-2222-4333-8444-555555555555"
    call(api, "SetTrustedNetworks", json.dumps({"networks": [{"uuid": home, "name": "Home", "mode": "pause"}]}))
    network = NetworkState("networkmanager", primary_uuid=home, primary_name="Home Wi-Fi",
                           primary_type="802-11-wireless", links=(
                               LinkDns("eth0", ("192.168.1.1",), default_route=True),
                               LinkDns("tun0", ("10.8.0.1",), routes=("corp.example",), default_route=False,
                                       vpn=True)))
    upstreams = UpstreamPolicy(api.state.upstream_config, network, build=lambda spec: spec)
    api.upstreams = lambda: upstreams
    api.state.set_network(home)
    status = decoded(call(api, "GetStatus"))
    assert status["protection"]["state"] == "trusted"
    assert status["protection"]["trusted_network"] == {"uuid": home, "name": "Home", "mode": "pause"}
    assert status["network"]["name"] == "Home Wi-Fi" and status["network"]["type"] == "802-11-wireless"
    assert status["network"]["split_dns"] == [
        {"domain": "corp.example", "interface": "tun0", "vpn": True, "servers": ["10.8.0.1"]}]
    assert decoded(call(api, "TestDomain", "x.ads.example"))["reason"] == "trusted_network"
