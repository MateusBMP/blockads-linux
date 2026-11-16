"""Tests for daemon.logstore (query log, statistics, retention, failures)."""

import os
import sqlite3
import time

import dns.rdatatype
import pytest

from blockads_linux.daemon import logstore as logstore_module
from blockads_linux.daemon.logstore import LogStore, escape_text, local_day
from blockads_linux.daemon.pipeline import QueryEvent, Verdict

A = int(dns.rdatatype.A)
NOW = 1_800_000_000.0  # 2027-01-15


class Clock:
    def __init__(self, now=NOW):
        self.now = now

    def __call__(self):
        return self.now


def event(name, verdict=Verdict.FORWARDED, reason="", cached=False):
    return QueryEvent(name, A, verdict, reason=reason, upstream="udp://192.0.2.1", cached=cached,
                      answers=("192.0.2.1",) if verdict is Verdict.FORWARDED else (), elapsed_ms=1.234)


@pytest.fixture
def store(tmp_path):
    stores = []

    def make(**kwargs):
        kwargs.setdefault("clock", Clock())
        kwargs.setdefault("flush_interval", 0.02)
        s = LogStore(tmp_path / "db" / "blockads.sqlite3", **kwargs)
        s.start()
        stores.append(s)
        return s

    yield make
    for s in stores:
        s.stop()


def test_escape_text():
    assert escape_text("example.com") == "example.com"
    assert escape_text("café.example") == "caf\\195\\169.example"
    assert escape_text("a\nb") == "a\\010b"
    assert escape_text("x" * 2000) == "x" * 1024


def test_write_and_page(store):
    s = store()
    for i in range(5):
        s.submit(event(f"host{i}.example"))
    s.submit(event("ads.example", Verdict.BLOCKED, reason="hagezi_pro,stevenblack"))
    s.submit(event("100%_sure.example"))
    s.flush()
    rows = s.query_log(limit=3)
    assert [r["name"] for r in rows] == ["host0.example", "host1.example", "host2.example"]
    assert rows[0]["time_ms"] == int(NOW * 1000) and rows[0]["answers"] == ["192.0.2.1"]
    assert rows[0]["verdict"] == "forwarded" and rows[0]["elapsed_ms"] == 1.23
    newer = s.query_log(after_id=rows[-1]["id"])
    assert [r["name"] for r in newer] == ["host3.example", "host4.example", "ads.example", "100%_sure.example"]
    older = s.query_log(before_id=newer[-1]["id"], limit=2)
    assert [r["name"] for r in older] == ["ads.example", "host4.example"]
    assert [r["name"] for r in s.query_log(verdict="blocked")] == ["ads.example"]
    assert [r["name"] for r in s.query_log(search="0%_")] == ["100%_sure.example"]  # % and _ are literal
    assert [r["name"] for r in s.query_log(search="HOST4")] == ["host4.example"]
    assert len(s.query_log(limit=10_000)) == 7
    with pytest.raises(ValueError):
        s.query_log(verdict="bogus")
    assert s.written == 7 and s.dropped == 0


def test_statistics(store):
    clock = Clock()
    s = store(clock=clock)
    s.submit(event("a.example"))
    s.submit(event("a.example", cached=True))
    s.submit(event("ads.example", Verdict.BLOCKED, reason="hagezi_pro,stevenblack"))
    s.submit(event("ads.example", Verdict.BLOCKED, reason="hagezi_pro"))
    s.submit(event("x.example", Verdict.FAILED))
    clock.now = NOW - 2 * 86400
    s.submit(event("old.example", Verdict.BLOCKED, reason="custom"))
    s.flush()
    clock.now = NOW
    assert s.totals(NOW - 3600) == {"total": 5, "blocked": 2, "forwarded": 2, "local": 0, "failed": 1, "cached": 1}
    assert s.totals(0)["total"] == 6
    day = s.series("24h")
    assert len(day) == 24 and day[-1]["total"] == 5 and day[-1]["blocked"] == 2
    week = s.series("7d")
    assert len(week) == 7 and week[-1]["total"] == 5 and week[-3]["blocked"] == 1
    assert len(s.series("4w")) == 28 and sum(b["total"] for b in s.series("4w")) == 6
    months = s.series("12m")
    assert len(months) == 12 and months[-1]["total"] == 6
    with pytest.raises(ValueError):
        s.series("1y")
    assert s.top_domains(1) == [{"name": "ads.example", "count": 2}]
    assert s.top_domains(7) == [{"name": "ads.example", "count": 2}, {"name": "old.example", "count": 1}]
    assert s.top_domains(1, blocked=False)[0] == {"name": "a.example", "count": 2}
    assert s.reasons(1) == {"hagezi_pro": 2, "stevenblack": 1}
    assert s.reasons(7)["custom"] == 1


def test_recording_off_stores_no_names(store, tmp_path):
    s = store(recording=False)
    s.submit(event("secret.example", Verdict.BLOCKED, reason="custom"))
    s.flush()
    assert s.query_log() == [] and s.top_domains(1) == []
    assert s.totals(0)["blocked"] == 1 and s.reasons(1) == {"custom": 1}
    s.flush()
    with sqlite3.connect(s.path) as conn:
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    assert b"secret.example" not in s.path.read_bytes()


def test_queue_full_drops_and_counts(tmp_path):
    s = LogStore(tmp_path / "x.sqlite3", queue_size=2)  # writer not started
    assert s.submit(event("a")) and s.submit(event("b"))
    assert not s.submit(event("c"))
    assert s.dropped == 1


def test_clear_log_keeps_statistics_and_ids(store):
    s = store()
    s.submit(event("a.example"))
    s.flush()
    last = s.query_log()[-1]["id"]
    s.clear_log().result(5)
    assert s.query_log() == [] and s.totals(0)["total"] == 1
    s.submit(event("b.example"))
    s.flush()
    assert s.query_log()[0]["id"] > last  # AUTOINCREMENT: a poller's after_id stays valid
    s.clear_statistics().result(5)
    assert s.totals(0)["total"] == 0 and s.query_log(after_id=last)[0]["name"] == "b.example"


def test_retention_and_clock_jumps(store):
    clock = Clock()
    s = store(clock=clock, retention_days=7)
    for days_ago in (0, 3, 8, 30):
        clock.now = NOW - days_ago * 86400
        s.submit(event(f"d{days_ago}.example"))
    s.flush()
    clock.now = NOW
    assert s.maintain().result(5)["expired"] == 2
    assert {r["name"] for r in s.query_log()} == {"d0.example", "d3.example"}
    # The clock jumps ten years ahead (bad RTC): the recent log survives.
    clock.now = NOW + 10 * 365 * 86400
    s.maintain().result(5)
    assert {r["name"] for r in s.query_log()} == {"d0.example", "d3.example"}
    assert s.totals(0)["total"] == 4  # statistics too
    # ... entries written meanwhile are kept; once time moves on, old ones expire as usual.
    s.submit(event("future.example"))
    s.flush()
    s.maintain().result(5)
    assert {r["name"] for r in s.query_log()} == {"future.example"}
    # The clock jumps back: nothing written meanwhile is lost.
    clock.now = NOW
    s.maintain().result(5)
    assert {r["name"] for r in s.query_log()} == {"future.example"}
    assert s.totals(0)["total"] == 1  # older statistics expired relative to the newest entry


def test_size_cap_drops_the_oldest_rows(store):
    s = store(max_bytes=400 * 1024, batch=1000)
    answers = tuple(f"192.0.2.{i}" for i in range(30))
    for i in range(5000):
        s.submit(QueryEvent(f"host{i % 20}.example", A, Verdict.FORWARDED, reason=f"#{i}", answers=answers))
    s.flush()
    s.maintain().result(10)  # (the startup pass may already have trimmed)
    newest = s.query_log(before_id=10**9, limit=1)[0]
    assert newest["reason"] == "#4999"
    assert s.query_log()[0]["reason"] != "#0"  # the oldest went first
    with sqlite3.connect(s.path) as conn:
        size = (conn.execute("PRAGMA page_count").fetchone()[0] - conn.execute("PRAGMA freelist_count").fetchone()[0])
        size *= conn.execute("PRAGMA page_size").fetchone()[0]
    assert size <= 400 * 1024
    assert s.totals(0)["total"] == 5000  # statistics untouched


def test_corrupt_database_is_recreated(tmp_path, store):
    path = tmp_path / "db" / "blockads.sqlite3"
    path.parent.mkdir()
    path.write_bytes(b"this is not a database" * 100)
    s = store()
    s.submit(event("a.example"))
    s.flush()
    assert [r["name"] for r in s.query_log()] == ["a.example"]
    assert "db_recreated" in s.alerts
    assert list(path.parent.glob("blockads.sqlite3.corrupt-*"))


def test_disk_full_pauses_then_resumes(store, monkeypatch):
    s = store(retry_after=0.2)
    real_insert = LogStore._insert
    full = {"on": True}

    def insert(self, conn, rows):
        if full["on"]:
            exc = sqlite3.OperationalError("database or disk is full")
            exc.sqlite_errorcode = 13
            raise exc
        return real_insert(self, conn, rows)

    monkeypatch.setattr(LogStore, "_insert", insert)
    s.submit(event("lost.example"))
    s.flush()
    assert "disk_full" in s.alerts and s.dropped == 1
    full["on"] = False
    s.submit(event("also-lost.example"))  # still paused
    s.flush()
    assert s.dropped == 2
    time.sleep(0.25)
    s.submit(event("kept.example"))
    s.flush()
    assert [r["name"] for r in s.query_log()] == ["kept.example"] and "disk_full" not in s.alerts


def test_real_enospc_on_tmpfs(tmp_path):
    """Needs a mount namespace: run under ``unshare -Urm`` (tests/netns/storage_enospc.sh)."""
    mount = tmp_path / "tiny"
    mount.mkdir()
    if os.system(f"mount -t tmpfs -o size=1m tmpfs {mount} 2>/dev/null") != 0:
        pytest.skip("cannot mount a tmpfs here")
    s = LogStore(mount / "blockads.sqlite3", flush_interval=0.02, retry_after=0.1, batch=50)
    s.start()
    ballast = mount / "ballast"
    try:
        s.submit(event("before.example"))
        s.flush()
        fd = os.open(ballast, os.O_WRONLY | os.O_CREAT, 0o600)  # something else fills the disk
        try:
            while True:
                os.write(fd, b"\0" * 4096)
        except OSError:
            pass
        finally:
            os.close(fd)
        for i in range(2000):
            s.submit(event(f"host-{i:06d}-{'y' * 60}.example"))
        s.flush()
        assert "disk_full" in s.alerts and s.dropped > 0
        assert s.query_log()[0]["name"] == "before.example"  # what was written survives
        ballast.unlink()  # space comes back
        time.sleep(0.15)
        s.submit(event("after.example"))
        s.flush()
        assert s.query_log(before_id=10**9, limit=1)[0]["name"] == "after.example"
        assert "disk_full" not in s.alerts
    finally:
        s.stop()
        os.system(f"umount {mount}")


def test_local_day():
    assert local_day(NOW) - local_day(NOW - 86400) == 1
    assert isinstance(logstore_module.DB_SCHEMA, int)
