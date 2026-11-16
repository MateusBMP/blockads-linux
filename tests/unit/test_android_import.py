"""Tests for common.android_import (blockads-android ``blockads_settings.json``)."""

from pathlib import Path

import pytest

from blockads_linux.common.android_import import AndroidImportError, convert, is_android_backup, load
from blockads_linux.common.settings import Rules, Settings

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "android"


def current():
    settings = Settings().to_dict()
    settings["filters"]["enabled"] = ["stevenblack"]
    rules = Rules(("||already.example^",), ("bank.example.com",)).to_dict()
    return settings, rules


def test_detects_android_backups():
    assert is_android_backup({"version": 2, "configProfiles": []})
    assert is_android_backup({"upstreamDns": "9.9.9.9"})
    assert not is_android_backup({"settings": {}, "rules": {}, "configProfiles": []})
    assert not is_android_backup([1])
    with pytest.raises(AndroidImportError):
        load(b'{"settings": {}}')
    with pytest.raises(AndroidImportError):
        load(b"not json")


def test_version_2_profile():
    document = load((FIXTURES / "blockads_settings_v2.json").read_bytes())
    settings, rules = current()
    result = convert(document, settings, rules)
    new = Settings.from_dict(result.backup["settings"], strict=True)[0]
    assert new.dns.upstream == ("cloudflare_family",) and new.dns.fallback is None
    assert new.dns.safesearch is True and new.dns.youtube_restricted is False
    assert set(new.filters.enabled) == {"stevenblack", "easyprivacy"}
    assert [(c.name, c.urls) for c in new.filters.custom] == [
        ("My_Own_List", ("https://lists.example.org/my-own-list.txt",))]
    new_rules = Rules.from_dict(result.backup["rules"], strict=True)[0]
    assert new_rules.rules == ("||already.example^", "||tracker.example.org^", "||*.ads.example.com^")
    assert new_rules.whitelist == ("bank.example.com", "cdn.example.net")
    assert result.prefs == {"notify_daily_summary": True, "notify_milestones": True, "theme": "black",
                            "language": "pt_BR"}
    assert result.report == {
        "profiles_skipped": 1, "dns": 1, "lists": 1, "custom_lists": 1, "lists_skipped": 1, "rules": 2,
        "whitelist": 1, "rules_skipped": 1, "disabled_rules_skipped": 1, "apps_skipped": 2, "firewall_skipped": 1}


def test_version_1_legacy_fields():
    document = load((FIXTURES / "blockads_settings_v1.json").read_bytes())
    settings, rules = current()
    settings["dns"]["encrypted_only"] = True
    result = convert(document, settings, rules)
    new = Settings.from_dict(result.backup["settings"], strict=True)[0]
    # a LAN resolver: plain DNS, so "encrypted only" goes off; Android's fallback follows
    assert new.dns.upstream == ("udp://192.168.1.53",) and new.dns.fallback == ("udp://94.140.14.14",)
    assert not new.dns.encrypted_only
    assert new.dns.block_mode == "nxdomain" and new.dns.youtube_restricted is True
    # the mirror URL is not contacted: matched to the catalog by name; the disabled list is skipped
    assert new.filters.enabled == ("stevenblack",) and new.filters.custom == ()
    new_rules = Rules.from_dict(result.backup["rules"], strict=True)[0]
    assert new_rules.rules == ("||already.example^", "||tracker.example.org^", "@@||allowed.example^",
                               "! a comment", "*.sub.example.net")
    assert new_rules.whitelist == ("bank.example.com",)
    assert result.prefs == {"notify_daily_summary": False, "notify_milestones": True, "theme": "dark"}
    assert result.report["rules_skipped"] == 1 and result.report["apps_skipped"] == 1


def test_presets_and_odd_servers():
    settings, rules = current()
    for servers, upstream in ((["0.0.0.0"], ["system"]), (["9.9.9.9", "149.112.112.112"], ["quad9"]),
                              (["2620:fe::fe"], ["udp://[2620:fe::fe]"]),
                              (["https://dns.example/dns-query"], ["https://dns.example/dns-query"])):
        content = "[dns]\n" + "".join(f"server = {s}\n" for s in servers)
        result = convert({"version": 2, "configProfiles": [{"name": "x", "content": content}]}, settings, rules)
        assert result.backup["settings"]["dns"]["upstream"] == upstream, servers
    result = convert({"version": 2, "configProfiles": [{"name": "x", "content": "[dns]\nserver = quic://x\n"}]},
                     settings, rules)
    assert result.report == {"dns_skipped": 1}
    assert result.backup["settings"]["dns"]["upstream"] == settings["dns"]["upstream"]


def test_diagnostics_redaction():
    from blockads_linux.common import diagnostics

    status = {"protection": {"state": "trusted", "trusted_network": {"uuid": "u", "name": "Home", "mode": "pause"}},
              "network": {"uuid": "u", "name": "Home", "type": "802-11-wireless",
                          "split_dns": [{"domain": "corp.example"}]}}
    settings = Settings().to_dict()
    settings["trusted_networks"] = [{"uuid": "u", "name": "Home", "mode": "pause"}]
    settings["filters"]["custom"] = [{"id": "custom_x", "name": "X", "enabled": True,
                                      "urls": ["https://lists.example.org/secret-token/list.txt"]}]
    report = diagnostics.build(status=status, settings=settings, catalog={"lists": [], "custom": []},
                               env={"python": "3"}, now=5)
    text = __import__("json").dumps(report)
    assert "Home" not in text and "corp.example" not in text and "secret-token" not in text and '"u"' not in text
    assert report["status"]["network"]["split_dns_routes"] == 1
    assert report["settings"]["filters"]["custom"] == [{"id": "custom_x", "enabled": True,
                                                        "hosts": ["lists.example.org"]}]
    assert diagnostics.build(env={}, errors={"status": "down"})["status"] is None
