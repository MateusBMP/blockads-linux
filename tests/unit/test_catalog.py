"""Tests for the bundled catalog, its loader, and the network-contact policy."""

import json
import re
from collections import Counter
from pathlib import Path

import pytest

from blockads_linux.filters.catalog import (
    CATEGORIES,
    CatalogError,
    load_bundled_catalog,
    load_doh_blocklist,
    parse_catalog,
    parse_doh_blocklist,
    validate_list_url,
)

SRC = Path(__file__).resolve().parents[2] / "src"
DEFAULTS = {
    "stevenblack",
    "easyprivacy",
    "adg_online_malicious_url_blocklist",
    "adg_phishing_url_blocklist",
    "adg_dandelion_sprouts_anti_malware_list",
    "adg_ublock_origin__badware_risks",
}


def test_bundled_catalog_matches_upstream_shape():
    catalog = load_bundled_catalog()
    assert len(catalog.entries) == 100
    assert Counter(e.category for e in catalog.entries) == {
        "security": 8, "ads": 7, "privacy": 8, "social": 4,
        "annoyances": 10, "regional": 55, "other": 8,
    }
    assert {e.id for e in catalog.entries if e.android_default} == {"stevenblack", "easyprivacy"}
    assert catalog.revision.startswith("fc95d66a")


def test_defaults_are_android_defaults_plus_security_set():
    catalog = load_bundled_catalog()
    assert catalog.default_enabled_ids() == DEFAULTS
    retired = catalog.get("urlhaus_malware")
    assert retired is not None and retired.retired and not retired.enabled_by_default


def test_every_list_url_is_an_original_https_publisher_url():
    for entry in load_bundled_catalog().entries:
        validate_list_url(entry.url)
        assert "pwhs.app" not in entry.url  # never the upstream project's compile servers


def test_by_category_is_ordered_security_first():
    groups = load_bundled_catalog().by_category()
    assert list(groups) == list(CATEGORIES)
    assert CATEGORIES[0] == "security"


def _minimal(**overrides):
    item = {
        "id": "x", "name": "X", "description": "", "category": "ads",
        "url": "https://example.org/list.txt", "enabled_by_default": False,
        "android_default": False, "approx_rules": 1,
    }
    item.update(overrides)
    return json.dumps({"schema": 1, "lists": [item]})


@pytest.mark.parametrize(
    "overrides",
    [
        {"url": "http://example.org/list.txt"},
        {"url": "https://user:pw@example.org/list.txt"},
        {"url": "https://example.org/a list.txt"},
        {"url": "file:///etc/passwd"},
        {"category": "malware"},
        {"id": "Bad-Id"},
        {"enabled_by_default": "yes"},
        {"approx_rules": True},
        {"retired": "gone", "enabled_by_default": True},
    ],
)
def test_parse_catalog_rejects_invalid_entries(overrides):
    with pytest.raises(CatalogError):
        parse_catalog(_minimal(**overrides))


def test_parse_catalog_rejects_bad_documents():
    for doc in ("not json", "[]", json.dumps({"schema": 2, "lists": []}), json.dumps({"schema": 1, "lists": []})):
        with pytest.raises(CatalogError):
            parse_catalog(doc)
    item = json.loads(_minimal())["lists"][0]
    with pytest.raises(CatalogError):
        parse_catalog(json.dumps({"schema": 1, "lists": [item, item]}))


def test_doh_blocklist():
    domains = load_doh_blocklist()
    assert len(domains) == 34
    assert {"dns.google", "cloudflare-dns.com", "mozilla.cloudflare-dns.com", "dns.quad9.net"} <= domains
    assert parse_doh_blocklist("# header\ndoh.example  # trailing comment\n\n") == {"doh.example"}
    for bad in ("Bad_Entry\n", "A.example\n", "nodot\n", "doh.example.\n"):
        with pytest.raises(CatalogError):
            parse_doh_blocklist(bad)


def test_shipped_code_never_references_upstream_project_servers():
    """Network-contact policy: no runtime contact with the upstream project's servers."""
    offenders = [
        str(path.relative_to(SRC))
        for path in SRC.rglob("*")
        if path.is_file() and path.suffix in {".py", ".json", ".txt"}
        and re.search(r"pwhs\.app", path.read_text("utf-8", errors="replace"))
    ]
    assert offenders == []
