"""The copyright and licence notices printed by --version and kept in NOTICE."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import os
import subprocess
import sys
from pathlib import Path

import pytest

from blockads_linux import __version__
from blockads_linux.common import legal

ROOT = Path(__file__).resolve().parents[2]


def load_helper():
    path = ROOT / "helper" / "blockads-fw"
    loader = importlib.machinery.SourceFileLoader("blockads_fw_legal", str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def test_version_text():
    text = legal.version_text("blockadsctl")
    assert text.splitlines()[0] == f"blockadsctl (blockads-linux) {__version__}"
    assert legal.COPYRIGHT in text
    assert "GNU GPL version 3 only" in text and "NO WARRANTY" in text
    assert legal.UPSTREAM in text


def test_helper_carries_the_same_notice():
    helper = load_helper()
    assert helper.COPYRIGHT == legal.COPYRIGHT
    assert helper.LICENSE_URL == legal.LICENSE_URL


def test_notice_and_metadata_agree():
    assert legal.COPYRIGHT in (ROOT / "NOTICE").read_text()
    assert f'license = "{legal.LICENSE_ID}"' in (ROOT / "pyproject.toml").read_text()
    metainfo = next((ROOT / "data" / "metainfo").glob("*.xml")).read_text()
    assert f"<project_license>{legal.LICENSE_ID}</project_license>" in metainfo
    assert (ROOT / "LICENSE").read_text().lstrip().startswith("GNU GENERAL PUBLIC LICENSE")


@pytest.mark.parametrize("module, prog", [
    ("blockads_linux.ctl", "blockadsctl"),
    ("blockads_linux.daemon", "blockadsd"),
    ("blockads_linux.updater", "blockads-update"),
])
def test_version_option(module, prog):
    env = dict(os.environ, PYTHONPATH=os.pathsep.join(sys.path))
    out = subprocess.run([sys.executable, "-m", module, "--version"], capture_output=True, text=True,
                         env=env, timeout=60, check=True).stdout
    assert out.strip() == legal.version_text(prog)


def test_helper_version_option(capsys):
    helper = load_helper()
    with pytest.raises(SystemExit) as exit_info:
        helper.build_parser().parse_args(["--version"])
    assert exit_info.value.code == 0
    out = capsys.readouterr().out
    assert out.startswith("blockads-fw (blockads-linux)\n" + legal.COPYRIGHT)
    assert "NO WARRANTY" in out
