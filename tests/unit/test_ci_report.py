"""tools/ci/report.py: CI must never turn a failure into a green check."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tools" / "ci" / "report.py"


def run(*args: str, summary: Path) -> tuple[int, str, str]:
    env = {"GITHUB_STEP_SUMMARY": str(summary), "PATH": "/usr/bin:/bin"}
    proc = subprocess.run([sys.executable, "-I", str(SCRIPT), *args], capture_output=True, text=True, env=env)
    return proc.returncode, proc.stdout, summary.read_text() if summary.exists() else ""


def test_all_pass(tmp_path):
    log = tmp_path / "ok.log"
    log.write_text("PASS  [nft] apply --verify\nPASS  probe      OK 0.00s\n87 passed in 7.95s\nexit=0\n")
    rc, out, summary = run("lines", str(log), "--title", "t", summary=tmp_path / "s.md")
    assert rc == 0 and "::error" not in out
    assert "**2 passed**" in summary and "pytest 87 passed" in summary


def test_fail_line_exit_status_and_empty_log(tmp_path):
    bad = tmp_path / "bad.log"
    bad.write_text("PASS  a\nFAIL  [nft] thing   want 0, got: 3\n")
    rc, out, _ = run("lines", str(bad), "--title", "t", summary=tmp_path / "s.md")
    assert rc == 1 and "::error title=t::[nft] thing: want 0, got: 3" in out

    status = tmp_path / "status.log"
    status.write_text("PASS  a\nexit=2\n")
    assert run("lines", str(status), "--title", "t", summary=tmp_path / "s.md")[0] == 1

    empty = tmp_path / "empty.log"
    empty.write_text("qemu: could not boot\n")
    rc, out, _ = run("lines", str(empty), "--title", "t", summary=tmp_path / "s.md")
    assert rc == 1 and "no results" in out

    missing = tmp_path / "missing.log"
    assert run("lines", str(missing), "--title", "t", summary=tmp_path / "s.md")[0] == 1


def test_pytest_failures_in_a_log(tmp_path):
    log = tmp_path / "vm.log"
    log.write_text("1 failed, 86 passed in 8.00s\nPASS  x\nexit=0\n")
    assert run("lines", str(log), "--title", "t", summary=tmp_path / "s.md")[0] == 1


def test_skips_warn_or_fail(tmp_path):
    log = tmp_path / "skip.log"
    log.write_text("PASS  a\nSKIP  [legacy] backend usable   no modules\n")
    rc, out, _ = run("lines", str(log), "--title", "t", summary=tmp_path / "s.md")
    assert rc == 0 and "::warning" in out
    rc, out, _ = run("lines", str(log), "--title", "t", "--no-skip", summary=tmp_path / "s.md")
    assert rc == 1 and "::error" in out


def test_junit(tmp_path):
    tests = tmp_path / "t"
    tests.mkdir()
    (tests / "test_x.py").write_text("def test_ok():\n    pass\n\ndef test_bad():\n    assert 1 == 2, 'boom'\n")
    xml = tmp_path / "j.xml"
    subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-p", "no:asyncio",
                    "-o", "junit_family=xunit1", f"--junitxml={xml}", str(tests)],
                   capture_output=True, cwd=tmp_path)
    rc, out, summary = run("junit", str(xml), "--title", "unit", summary=tmp_path / "s.md")
    assert rc == 1
    assert "::error file=" in out and "line=4" in out and "boom" in out
    assert "**1 passed**, 1 failed" in summary


def test_junit_missing_or_garbage(tmp_path):
    assert run("junit", str(tmp_path / "none.xml"), "--title", "u", summary=tmp_path / "s.md")[0] == 1
    garbage = tmp_path / "g.xml"
    garbage.write_text("not xml")
    assert run("junit", str(garbage), "--title", "u", summary=tmp_path / "s.md")[0] == 1


def test_annotation_escaping():
    spec = importlib.util.spec_from_file_location("report", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.escape("100%\nnext") == "100%25%0Anext"
    assert module.escape_prop("a:b,c") == "a%3Ab%2Cc"
