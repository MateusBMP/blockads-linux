"""The packages, the Makefile and the tree agree (version, units, data files)."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

from blockads_linux import __version__

ROOT = Path(__file__).resolve().parents[2]


def test_package_versions_follow_the_code():
    pkgbuild = (ROOT / "packaging" / "arch" / "PKGBUILD").read_text()
    assert re.search(r"^pkgver=(.+)$", pkgbuild, re.M).group(1) == __version__
    first = (ROOT / "packaging" / "debian" / "changelog").read_text().splitlines()[0]
    debian = re.match(r"blockads-linux \(([^)]+)\)", first).group(1)
    # Debian spells a pre-release with ~ so that it sorts before the release.
    assert debian == re.sub(r"\.?(dev|a|b|rc)(\d+)$", r"~\1\2", __version__)


def test_makefile_installs_every_unit_and_data_file():
    makefile = (ROOT / "Makefile").read_text()
    units = set(re.search(r"^UNITS\s*:=(.*?)\n(?=\S)", makefile, re.M | re.S).group(1).replace("\\", " ").split())
    assert units == {p.name for p in (ROOT / "data" / "systemd").iterdir()}
    for path in (ROOT / "data").rglob("*"):
        if path.is_file() and path.parent.name not in ("systemd",):
            rel = path.relative_to(ROOT).as_posix()
            # The Makefile names some paths through $(NAME) / $(APP_ID).
            spelled = rel.replace("blockads-linux", "$(NAME)").replace("io.github.mateusbmp.$(NAME)", "$(APP_ID)")
            assert rel in makefile or spelled in makefile, f"{rel} is not installed by the Makefile"


@pytest.mark.skipif(shutil.which("make") is None, reason="needs make")
def test_staged_install(tmp_path):
    qm = ROOT / "src" / "blockads_linux" / "gui" / "i18n" / "blockads_pt_BR.qm"
    if not qm.exists():
        pytest.skip("translations not compiled (make build)")
    subprocess.run(["make", "-s", "-C", str(ROOT), "install-files", f"DESTDIR={tmp_path}", "PYCOMPILE=0",
                    "UNITDIR=/usr/lib/systemd/system", "SYSUSERSDIR=/usr/lib/sysusers.d",
                    "TMPFILESDIR=/usr/lib/tmpfiles.d"], check=True, capture_output=True)
    lib = tmp_path / "usr" / "lib" / "blockads-linux"
    for name in ("blockadsd", "blockads-update", "blockads-fw", "blockads-fw-emergency.sh"):
        assert (lib / name).stat().st_mode & 0o777 == 0o755
    assert (tmp_path / "usr/bin/blockadsctl").stat().st_mode & 0o777 == 0o755
    assert (tmp_path / "etc/blockads-linux/firewall.conf").exists()
    assert (lib / "python/blockads_linux/filters/data/catalog.json").exists()
    assert (lib / "python/blockads_linux/gui/i18n/blockads_pt_BR.qm").exists()
    installed = {p.relative_to(lib / "python").as_posix() for p in (lib / "python").rglob("*.py")}
    shipped = {p.relative_to(ROOT / "src").as_posix() for p in (ROOT / "src" / "blockads_linux").rglob("*.py")
               if "__pycache__" not in p.parts}
    assert installed == shipped
    # The launchers and units name the installed paths.
    assert "/usr/lib/blockads-linux/python" in (tmp_path / "usr/bin/blockadsctl").read_text()
    assert "/usr/lib/blockads-linux/blockads-fw" in (tmp_path / "usr/lib/systemd/system/blockadsd.service").read_text()
