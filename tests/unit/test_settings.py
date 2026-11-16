"""Tests for common.settings (schema, validation, storage)."""

import json

import pytest

from blockads_linux.common.atomic import backup_path
from blockads_linux.common.settings import (
    CustomList,
    Rules,
    Settings,
    SettingsError,
    load_rules,
    load_settings,
    rule_counts,
    save,
)
from blockads_linux.filters.catalog import load_bundled_catalog


def test_defaults_round_trip():
    settings = Settings()
    assert settings.filters.enabled == tuple(sorted(load_bundled_catalog().default_enabled_ids()))
    assert settings.dns.upstream == ("quad9",) and settings.dns.block_ttl == 10
    assert settings.logging.retention_days == 7
    document = json.loads(json.dumps(settings.to_dict()))
    assert document["schema"] == 1
    assert Settings.from_dict(document) == (settings, [])


def test_one_bad_value_keeps_the_rest():
    document = Settings().to_dict()
    document["dns"].update(block_ttl=-1, safesearch=True, block_mode="bogus", upstream=["quad9", "bad spec!"])
    document["logging"] = {"retention_days": True, "enabled": False}
    document["filters"]["custom"] = [
        {"id": "custom_work", "name": "Work", "urls": ["https://example.com/a.txt", "http://example.com/b.txt"]},
        {"id": "notcustom"},
        "junk",
    ]
    document["future_feature"] = 1
    settings, problems = Settings.from_dict(document)
    assert settings.dns.block_ttl == 10 and settings.dns.safesearch and settings.dns.block_mode == "null_ip"
    assert settings.dns.upstream == ("quad9",)
    assert settings.logging.retention_days == 7 and settings.logging.enabled is False
    assert settings.filters.custom[0] == CustomList("custom_work", "Work", ("https://example.com/a.txt",), True)
    assert len(settings.filters.custom) == 1  # "notcustom" (bad id) and "junk" dropped
    text = "\n".join(problems)
    for expected in ("dns.block_ttl", "dns.block_mode", "dns.upstream[1]", "logging.retention_days",
                     "filters.custom[0].urls[1]", "filters.custom[1].id", "filters.custom[2]", "future_feature"):
        assert expected in text, expected
    with pytest.raises(SettingsError):
        Settings.from_dict(document, strict=True)


def test_consistency_checks():
    document = Settings().to_dict()
    document["dns"]["upstream"] = []
    document["trusted_networks"] = [{"uuid": "0000-1111-2222", "name": "home"}] * 2
    settings, problems = Settings.from_dict(document)
    assert settings.dns.upstream == ("quad9",)
    assert len(settings.trusted_networks) == 1
    assert any("duplicate UUID" in p for p in problems)
    for bad in ([], "x", None):
        with pytest.raises(SettingsError):
            Settings.from_dict(bad)


def test_control_characters_and_limits():
    document = Settings().to_dict()
    document["filters"]["custom"] = [{"id": "custom_x", "name": "a\x1bb", "urls": ["https://example.com/x"]}]
    document["filters"]["enabled"] = ["x"] * 2000
    settings, problems = Settings.from_dict(document)
    assert settings.filters.custom[0].name == "Custom list"
    assert settings.filters.enabled == Settings().filters.enabled
    assert any("more than 1000" in p for p in problems)


def test_rules():
    rules, problems = Rules.from_dict({"schema": 1, "rules": ["||ads.example^", "@@||ok.example^", "*.sub.example",
                                                              "! comment", "bad rule!", 5, "||ads.example^"],
                                       "whitelist": ["Good.Example", "-bad-", ""]})
    assert rules.rules == ("||ads.example^", "@@||ok.example^", "*.sub.example", "! comment")
    assert rules.whitelist == ("good.example",)
    assert problems == ["rules: 2 invalid entries dropped", "whitelist: 2 invalid entries dropped"]
    assert rule_counts(rules) == {"block": 2, "allow": 1, "whitelist": 1}
    assert Rules.from_dict(rules.to_dict()) == (rules, [])
    with pytest.raises(SettingsError):
        Rules.from_dict({"rules": ["bad rule!"]}, strict=True)


def test_storage_backup_and_corruption(tmp_path):
    path = tmp_path / "settings.json"
    stored = load_settings(path)
    assert stored.source == "missing" and stored.value == Settings() and stored.problems == []
    first = Settings.from_dict({"schema": 1, "dns": {"safesearch": True}})[0]
    save(path, first)
    second = Settings.from_dict({"schema": 1, "dns": {"safesearch": True, "block_ttl": 60}})[0]
    save(path, second)
    assert load_settings(path).value == second
    path.write_text('{"schema": 1, "dns": ')  # torn by a crash or disk error
    stored = load_settings(path)
    assert stored.source == "backup" and stored.value == first
    assert "restored from the backup" in stored.problems[0]
    path.unlink(missing_ok=True)
    backup_path(path).write_text("[]")
    stored = load_settings(path)
    assert stored.value == Settings() and stored.source == "invalid" and "defaults used" in stored.problems[0]


def test_newer_schema_is_never_overwritten(tmp_path):
    path = tmp_path / "settings.json"
    path.write_text(json.dumps({"schema": 99, "dns": {"safesearch": True}, "new_thing": {}}))
    stored = load_settings(path)
    assert stored.read_only and stored.value.dns.safesearch
    with pytest.raises(SettingsError):
        save(path, stored.value, stored)
    assert json.loads(path.read_text())["schema"] == 99


def test_rules_storage(tmp_path):
    path = tmp_path / "rules.json"
    save(path, Rules(("||x.example^",)))
    assert load_rules(path).value == Rules(("||x.example^",))


def test_trusted_network_bssid():
    from blockads_linux.common.settings import Settings
    doc = Settings().to_dict()
    doc["trusted_networks"] = [{"uuid": "0123abcd-0000", "name": "Home", "mode": "pause", "bssid": "AA:bb:CC:dd:EE:01"},
                               {"uuid": "0123abcd-0001", "name": "Cafe", "mode": "pause", "bssid": "nope"}]
    settings, problems = Settings.from_dict(doc)
    home, cafe = settings.trusted_networks
    assert home.matches("0123abcd-0000", "aa:bb:cc:dd:ee:01") and not home.matches("0123abcd-0000", "aa:bb:cc:dd:ee:02")
    assert not home.matches("0123abcd-0000", "") and not home.matches("", "aa:bb:cc:dd:ee:01")
    assert cafe.bssid == "" and any("bssid" in p for p in problems)  # a bad pin is dropped, not the network
    assert cafe.matches("0123abcd-0001", "anything")
    with pytest.raises(SettingsError):
        Settings.from_dict(doc, strict=True)
