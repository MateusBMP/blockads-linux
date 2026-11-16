"""Tests for common.atomic and common.paths."""

import errno
import json
import os
import stat

import pytest

from blockads_linux.common import atomic
from blockads_linux.common.atomic import backup_path, load_json, write_atomic, write_json
from blockads_linux.common.paths import Paths


def test_write_atomic_and_backup(tmp_path):
    path = tmp_path / "sub" / "doc.json"
    write_atomic(path, b"one", backup=True)
    assert path.read_bytes() == b"one" and not backup_path(path).exists()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    write_atomic(path, b"two", backup=True)
    assert path.read_bytes() == b"two" and backup_path(path).read_bytes() == b"one"
    write_atomic(path, b"three")
    assert backup_path(path).read_bytes() == b"one"  # no backup requested
    assert sorted(p.name for p in path.parent.iterdir()) == ["doc.json", "doc.json.bak"]


def test_write_failure_leaves_the_old_file(tmp_path, monkeypatch):
    path = tmp_path / "doc.json"
    write_atomic(path, b"old")

    def full(fd):
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(atomic.os, "fsync", full)
    with pytest.raises(OSError) as info:
        write_atomic(path, b"new", backup=True)
    assert info.value.errno == errno.ENOSPC
    monkeypatch.undo()
    assert path.read_bytes() == b"old"
    assert [p.name for p in tmp_path.iterdir()] == ["doc.json"]  # no temporary left


def test_write_on_a_full_tmpfs(tmp_path):
    """Real ENOSPC: needs a tiny tmpfs (only inside a user+mount namespace)."""
    mount = tmp_path / "tiny"
    mount.mkdir()
    if os.system(f"mount -t tmpfs -o size=16k tmpfs {mount} 2>/dev/null") != 0:
        pytest.skip("cannot mount a tmpfs here (run under unshare -Urm)")
    try:
        path = mount / "doc.json"
        write_atomic(path, b"x" * 1000)
        with pytest.raises(OSError) as info:
            write_atomic(path, b"y" * 64 * 1024)
        assert info.value.errno == errno.ENOSPC
        assert path.read_bytes() == b"x" * 1000
    finally:
        os.system(f"umount {mount}")


def test_load_json_fallbacks(tmp_path):
    path = tmp_path / "doc.json"
    assert load_json(path).source == "missing"
    write_json(path, {"v": 1}, backup=True)
    write_json(path, {"v": 2}, backup=True)
    loaded = load_json(path)
    assert loaded.document == {"v": 2} and loaded.source == "main"
    path.write_text("{ torn")
    loaded = load_json(path, clock=lambda: 1000)
    assert loaded.document == {"v": 1} and loaded.source == "backup" and "JSONDecodeError" in loaded.problem
    assert (tmp_path / "doc.json.corrupt-1000").read_text() == "{ torn"
    assert not path.exists()


def test_load_json_validation_and_both_bad(tmp_path):
    path = tmp_path / "doc.json"
    write_json(path, {"v": "bad"}, backup=False)
    backup_path(path).write_bytes(b"\xff\xfe")

    def validate(doc):
        if not isinstance(doc["v"], int):
            raise ValueError("v must be an int")
        return doc

    loaded = load_json(path, validate)
    assert loaded.document is None and loaded.source == "invalid" and "v must be an int" in loaded.problem


def test_quarantine_keeps_a_few(tmp_path):
    path = tmp_path / "doc.json"
    for t in range(6):
        path.write_text("bad")
        atomic.quarantine(path, clock=lambda t=t: 100 + t)
    assert len(list(tmp_path.glob("doc.json.corrupt-*"))) == atomic.KEEP_CORRUPT


def test_paths(tmp_path, monkeypatch):
    monkeypatch.setenv("BLOCKADS_STATE_DIR", str(tmp_path / "state"))
    paths = Paths.default()
    paths.ensure()
    assert paths.settings == tmp_path / "state" / "config" / "settings.json"
    assert stat.S_IMODE(paths.artifacts.stat().st_mode) == 0o700
    monkeypatch.delenv("BLOCKADS_STATE_DIR")
    assert str(Paths.default().root) == "/var/lib/blockads-linux"
    assert json.loads(atomic.dump_json({"b": 1, "a": "é"})) == {"a": "é", "b": 1}
