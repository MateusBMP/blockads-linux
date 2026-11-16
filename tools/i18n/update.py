#!/usr/bin/env python3
"""Regenerate the GUI translations: extract (pylupdate6), fill from tools/i18n/<lang>.py, compile (lrelease).

    python3 tools/i18n/update.py            # all languages
    python3 tools/i18n/update.py --check    # exit 1 when a source has no translation
    python3 tools/i18n/update.py --compile  # only compile the shipped .ts into .qm (builds, CI)

The .ts files are generated; edit the tables in tools/i18n/ instead.
"""

from __future__ import annotations

import argparse
import importlib.util
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GUI = ROOT / "src" / "blockads_linux" / "gui"
OUT = GUI / "i18n"
LANGUAGES = ("pt_BR",)


def table(lang: str) -> dict[str, str]:
    spec = importlib.util.spec_from_file_location(f"i18n_{lang}", Path(__file__).with_name(f"{lang}.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.T


# Debian/Ubuntu (qt6-l10n-tools) install the Qt 6 tools outside PATH.
QT_BIN = "/usr/lib/qt6/bin:/usr/lib64/qt6/bin"


def tool(*names: str) -> str:
    for name in names:
        path = shutil.which(name) or shutil.which(name, path=QT_BIN)
        if path:
            return path
    sys.exit(f"none of {', '.join(names)} found")


def compile_qm(lang: str) -> None:
    subprocess.run([tool("lrelease6", "lrelease-qt6", "lrelease"), "-silent", str(OUT / f"blockads_{lang}.ts"),
                    "-qm", str(OUT / f"blockads_{lang}.qm")], check=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--compile", action="store_true", help="only compile the .ts files into .qm")
    args = parser.parse_args()
    if args.compile:
        for lang in LANGUAGES:
            compile_qm(lang)
        return 0
    sources = sorted(str(p.relative_to(ROOT)) for p in GUI.rglob("*.py"))
    missing_any = False
    for lang in LANGUAGES:
        ts = OUT / f"blockads_{lang}.ts"
        ts.unlink(missing_ok=True)
        subprocess.run([tool("pylupdate6"), "--no-obsolete", *sources, "-ts", str(ts)], cwd=ROOT, check=True,
                       stdout=subprocess.DEVNULL)
        tree = ET.parse(ts)
        tree.getroot().set("language", lang)
        translations = table(lang)
        missing = []
        for message in tree.iter("message"):
            source = message.find("source").text or ""
            target = message.find("translation")
            if source in translations:
                target.text = translations[source]
                target.attrib.pop("type", None)
            else:
                missing.append(source)
        tree.write(ts, encoding="utf-8", xml_declaration=True)
        compile_qm(lang)
        unused = set(translations) - {m.find("source").text or "" for m in tree.iter("message")}
        for source in sorted(set(missing)):
            print(f"{lang}: untranslated: {source!r}")
        for source in sorted(unused):
            print(f"{lang}: unused entry: {source!r}")
        missing_any |= bool(missing)
    return 1 if args.check and missing_any else 0


if __name__ == "__main__":
    raise SystemExit(main())
