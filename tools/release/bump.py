#!/usr/bin/env python3
"""Set the release version everywhere it is written, and add the release notes.

    tools/release/bump.py VERSION --notes NOTES.md [--date YYYY-MM-DD]
    tools/release/bump.py --current          print the version and the last tag

VERSION is PEP 440 as written in src/blockads_linux/__init__.py: 1.2.3,
1.2.3rc1, 1.2.3b1, 1.2.3.dev1. NOTES.md is the release's changelog in
Markdown: "### Heading" sections of "- item" bullets (continuation lines
indented by two spaces).

Changes:
  src/blockads_linux/__init__.py      __version__
  packaging/arch/PKGBUILD             pkgver (pkgrel back to 1)
  packaging/debian/changelog          a new entry from the bullets (~ for pre-releases)
  data/metainfo/*.metainfo.xml        a <release> with the date and the release URL
  CHANGELOG.md                        a "## [VERSION] - DATE" section with the notes
"""
from __future__ import annotations

import argparse
import datetime as dt
import email.utils
import re
import subprocess
import sys
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INIT = ROOT / "src" / "blockads_linux" / "__init__.py"
PKGBUILD = ROOT / "packaging" / "arch" / "PKGBUILD"
DEB_CHANGELOG = ROOT / "packaging" / "debian" / "changelog"
DEB_CONTROL = ROOT / "packaging" / "debian" / "control"
METAINFO = ROOT / "data" / "metainfo" / "io.github.mateusbmp.blockads-linux.metainfo.xml"
CHANGELOG = ROOT / "CHANGELOG.md"
REPO_URL = "https://github.com/MateusBMP/blockads-linux"
VERSION_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:(a|b|rc)(\d+)|\.dev(\d+))?$")
CHANGELOG_HEAD = """# Changelog

All notable changes to blockads-linux. Versions follow [PEP 440](https://peps.python.org/pep-0440/);
the Debian package spells a pre-release with `~` (1.0.0rc1 is 1.0.0~rc1).
"""


def current_version() -> str:
    return re.search(r'^__version__ = "(.*)"', INIT.read_text(), re.M).group(1)


def sort_key(v: str) -> tuple:
    m = VERSION_RE.match(v)
    if not m:
        sys.exit(f"bump.py: {v!r} is not a version like 1.2.3, 1.2.3rc1 or 1.2.3.dev1")
    major, minor, patch, pre, pre_n, dev_n = m.groups()
    # dev < a < b < rc < final
    if dev_n is not None:
        stage = (0, int(dev_n))
    elif pre:
        stage = ({"a": 1, "b": 2, "rc": 3}[pre], int(pre_n))
    else:
        stage = (4, 0)
    return (int(major), int(minor), int(patch), *stage)


def is_prerelease(v: str) -> bool:
    return sort_key(v)[3] < 4


def debian_version(v: str) -> str:
    # The same mapping as tests/unit/test_packaging.py.
    return re.sub(r"\.?(dev|a|b|rc)(\d+)$", r"~\1\2", v)


def last_tag() -> str:
    r = subprocess.run(["git", "-C", str(ROOT), "describe", "--tags", "--abbrev=0", "--match", "v*"],
                       capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else ""


def notes_bullets(notes: str) -> list[str]:
    """The "- item" bullets of the notes, continuation lines joined, Markdown links and code marks dropped."""
    items: list[str] = []
    for line in notes.splitlines():
        if line.startswith("- "):
            items.append(line[2:].strip())
        elif line.startswith("  ") and line.strip() and items:
            items[-1] += " " + line.strip()
    clean = []
    for item in items:
        item = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", item)
        item = item.replace("`", "").replace("**", "")
        clean.append(item)
    return clean


def update_init(v: str) -> None:
    text = INIT.read_text()
    INIT.write_text(re.sub(r'^__version__ = ".*"', f'__version__ = "{v}"', text, count=1, flags=re.M))


def update_pkgbuild(v: str) -> None:
    text = PKGBUILD.read_text()
    text = re.sub(r"^pkgver=.*$", f"pkgver={v}", text, count=1, flags=re.M)
    text = re.sub(r"^pkgrel=.*$", "pkgrel=1", text, count=1, flags=re.M)
    PKGBUILD.write_text(text)


def update_debian_changelog(v: str, bullets: list[str], when: dt.datetime) -> None:
    maint = re.search(r"^Maintainer: (.+)$", DEB_CONTROL.read_text(), re.M).group(1).strip()
    lines = [f"blockads-linux ({debian_version(v)}) unstable; urgency=medium", ""]
    for b in bullets:
        lines += textwrap.wrap(b, width=78, initial_indent="  * ", subsequent_indent="    ",
                               break_long_words=False, break_on_hyphens=False)
    lines += ["", f" -- {maint}  {email.utils.format_datetime(when)}", ""]
    DEB_CHANGELOG.write_text("\n".join(lines) + "\n" + DEB_CHANGELOG.read_text())


def update_metainfo(v: str, day: str) -> None:
    text = METAINFO.read_text()
    kind = ' type="development"' if is_prerelease(v) else ""
    entry = (f'    <release version="{v}" date="{day}"{kind}>\n'
             f"      <url>{REPO_URL}/releases/tag/v{v}</url>\n"
             f"    </release>\n")
    if "<releases>" in text:
        text = text.replace("<releases>\n", "<releases>\n" + entry, 1)
    else:
        text = text.replace("</component>", f"  <releases>\n{entry}  </releases>\n</component>", 1)
    METAINFO.write_text(text)


def update_changelog_md(v: str, day: str, notes: str) -> None:
    text = CHANGELOG.read_text() if CHANGELOG.exists() else CHANGELOG_HEAD
    section = f"## [{v}] - {day}\n\n{notes.strip()}\n\n"
    m = re.search(r"^## \[", text, re.M)
    text = text[:m.start()] + section + text[m.start():] if m else text.rstrip() + "\n\n" + section
    links = f"[{v}]: {REPO_URL}/releases/tag/v{v}\n"
    CHANGELOG.write_text(text.rstrip() + "\n" + ("\n" if "]: http" not in text else "") + links)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("version", nargs="?")
    ap.add_argument("--notes", type=Path)
    ap.add_argument("--date", help="release date, YYYY-MM-DD (default: today, UTC)")
    ap.add_argument("--current", action="store_true", help="print the version and the last tag, change nothing")
    a = ap.parse_args()

    cur = current_version()
    if a.current:
        print(f"version {cur}\nlast tag {last_tag() or '(none)'}")
        return
    if not a.version or not a.notes:
        ap.error("VERSION and --notes are required")
    v = a.version.removeprefix("v")
    tag = last_tag()
    floor = tag[1:] if tag else None
    if floor and sort_key(v) <= sort_key(floor):
        sys.exit(f"bump.py: {v} is not newer than the last release {floor}")
    if sort_key(v) < sort_key(cur):
        sys.exit(f"bump.py: {v} is older than the tree's version {cur}")
    if f"## [{v}]" in (CHANGELOG.read_text() if CHANGELOG.exists() else ""):
        sys.exit(f"bump.py: CHANGELOG.md already has {v}")
    notes = a.notes.read_text()
    bullets = notes_bullets(notes)
    if not bullets:
        sys.exit("bump.py: the notes have no '- ' bullets")

    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    day = a.date or now.date().isoformat()
    update_init(v)
    update_pkgbuild(v)
    update_debian_changelog(v, bullets, now)
    update_metainfo(v, day)
    update_changelog_md(v, day, notes)
    print(f"{cur} -> {v} (debian {debian_version(v)}); {len(bullets)} changelog items")


if __name__ == "__main__":
    main()
