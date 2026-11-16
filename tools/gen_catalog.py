#!/usr/bin/env python3
"""Regenerate the bundled filter catalog and DoH blocklist (dev-time only).

Reads blockads-android's catalog and DoH list at a pinned revision and writes:

  src/blockads_linux/filters/data/catalog.json
  src/blockads_linux/filters/data/doh_blocklist.txt

Only each list's *original publisher* URL is kept. The pre-compiled artifacts
on the upstream project's servers (filter.pwhs.app) are dropped on purpose:
blockads-linux downloads lists from their publishers and compiles them
locally. Default-enabled lists follow the Android app (its defaults + a
security set).

Usage: python3 -I tools/gen_catalog.py [--revision SHA]
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
import urllib.request
from pathlib import Path

DEFAULT_REVISION = "fc95d66a9443da14729e280c61b496a2bcdda86c"
RAW = "https://raw.githubusercontent.com/pass-with-high-score/blockads-android/{rev}/{path}"
CATALOG_PATH = "app/src/fdroid/assets/preset/default_filters.json"
DOH_PATH = "app/src/main/assets/blocklist_doh.txt"
OUT_DIR = Path(__file__).resolve().parents[1] / "src" / "blockads_linux" / "filters" / "data"

CATEGORIES = ("security", "ads", "privacy", "social", "annoyances", "regional", "other")

# Android defaults (StevenBlack Unified, EasyPrivacy) + security set.
# urlhaus_malware's endpoint is gone (HTTP 410), so its maintained URLhaus-derived
# successor from the same upstream catalog is enabled instead.
ENABLED_BY_DEFAULT = frozenset(
    {
        "stevenblack",
        "easyprivacy",
        "adg_online_malicious_url_blocklist",
        "adg_phishing_url_blocklist",
        "adg_dandelion_sprouts_anti_malware_list",
        "adg_ublock_origin__badware_risks",
    }
)

# Entries whose publisher endpoint no longer works; kept for parity, never enabled.
RETIRED = {
    "urlhaus_malware": (
        "The publisher retired this download (HTTP 410 Gone). "
        "Use \"Online Malicious URL Blocklist\" instead."
    ),
}

_ID_RE = re.compile(r"[a-z0-9_]{1,80}")
_DOMAIN_RE = re.compile(r"(?=.{1,253}$)([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]*[a-z0-9])?")


def fetch(revision: str, path: str) -> bytes:
    request = urllib.request.Request(
        RAW.format(rev=revision, path=path), headers={"User-Agent": "blockads-linux-gen-catalog/1"}
    )
    with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310 - fixed https URL
        return response.read()


def build_catalog(raw: bytes, revision: str) -> dict:
    upstream = json.loads(raw)
    lists = []
    seen: set[str] = set()
    errors = []
    for item in upstream:
        list_id = item.get("id", "")
        url = item.get("originalUrl", "")
        category = str(item.get("category", "")).lower()
        if not _ID_RE.fullmatch(list_id) or list_id in seen:
            errors.append(f"bad or duplicate id: {list_id!r}")
        if not url.startswith("https://"):
            errors.append(f"{list_id}: original URL is not https: {url!r}")
        if category not in CATEGORIES:
            errors.append(f"{list_id}: unknown category {category!r}")
        seen.add(list_id)
        entry = {
            "id": list_id,
            "name": item.get("name", list_id),
            "description": item.get("description", ""),
            "category": category,
            "url": url,
            "enabled_by_default": list_id in ENABLED_BY_DEFAULT,
            "android_default": bool(item.get("isEnabled", False)),
            "approx_rules": int(item.get("ruleCount", 0) or 0),
        }
        if list_id in RETIRED:
            entry["retired"] = RETIRED[list_id]
        lists.append(entry)
    missing = (ENABLED_BY_DEFAULT | RETIRED.keys()) - seen
    if missing:
        errors.append(f"configured ids not in upstream catalog: {sorted(missing)}")
    if errors:
        raise SystemExit("catalog validation failed:\n  " + "\n  ".join(errors))
    order = {name: i for i, name in enumerate(CATEGORIES)}
    lists.sort(key=lambda e: (order[e["category"]], e["name"].lower()))
    return {
        "schema": 1,
        "source": {
            "repository": "https://github.com/pass-with-high-score/blockads-android",
            "revision": revision,
            "file": CATALOG_PATH,
            "license": "GPL-3.0",
        },
        "generated": dt.date.today().isoformat(),
        "categories": list(CATEGORIES),
        "lists": lists,
    }


def build_doh_list(raw: bytes, revision: str) -> str:
    domains = []
    for line in raw.decode("utf-8").splitlines():
        line = line.split("#", 1)[0].strip().lower()
        if not line:
            continue
        if not _DOMAIN_RE.fullmatch(line):
            raise SystemExit(f"DoH blocklist: invalid entry {line!r}")
        if line not in domains:
            domains.append(line)
    header = (
        "# Known DNS-over-HTTPS resolver hostnames, blocked when\n"
        "# \"Block DNS-over-HTTPS bypass\" is enabled (domain and subdomains).\n"
        f"# Generated from blockads-android {DOH_PATH} @ {revision} (GPL-3.0).\n"
    )
    return header + "".join(f"{d}\n" for d in domains)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--revision", default=DEFAULT_REVISION)
    args = parser.parse_args()
    catalog = build_catalog(fetch(args.revision, CATALOG_PATH), args.revision)
    doh = build_doh_list(fetch(args.revision, DOH_PATH), args.revision)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / "catalog.json").write_text(json.dumps(catalog, indent=2, ensure_ascii=False) + "\n", "utf-8")
    (OUT_DIR / "doh_blocklist.txt").write_text(doh, "utf-8")
    enabled = [e["id"] for e in catalog["lists"] if e["enabled_by_default"]]
    print(f"catalog: {len(catalog['lists'])} lists, enabled by default: {', '.join(enabled)}")
    print(f"doh blocklist: {doh.count(chr(10)) - 3} domains")
    return 0


if __name__ == "__main__":
    sys.exit(main())
