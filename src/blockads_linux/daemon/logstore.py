"""Query log and statistics in SQLite.

* One writer thread owns the write connection. The DNS path only calls
  :meth:`LogStore.submit`, which never blocks: a bounded queue feeds the
  writer, and when it is full the event is dropped and counted.
* The writer commits in batches (``batch`` events or ``flush_interval``
  seconds), updating ``query_log`` and the statistics tables
  (``stats_hourly``, ``stats_daily_domain``, ``stats_daily_reason``) in one
  transaction. Statistics survive log retention and "clear log".
* With recording off, nothing that holds a name is written (no
  ``query_log``, no ``stats_daily_domain``); the hourly and reason counters
  still count.
* Disk full (SQLITE_FULL / ENOSPC): the batch is dropped, logging pauses for
  ``retry_after`` seconds and an alert is raised; it resumes by itself.
* A corrupt database (SQLITE_CORRUPT / SQLITE_NOTADB, or a failed
  ``quick_check`` at open) is moved aside and recreated, with an alert.
* Maintenance (hourly, and on demand): retention (default 7 days) and a size
  cap that drops the oldest log rows first. Retention counts back from the
  newest entry when the clock is ahead of it, so a clock that jumps forward
  (wrong RTC, then NTP) cannot wipe the log.
* Names are stored as the pipeline gives them: lower case, with unusual
  bytes as ``\\DDD``; anything else that is not printable ASCII is escaped
  here too.

Reads use their own short-lived connections (WAL lets them run beside the
writer); the daemon calls them through ``asyncio.to_thread``.
"""

from __future__ import annotations

import concurrent.futures
import contextlib
import logging
import os
import queue
import sqlite3
import threading
import time
from collections import deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .pipeline import QueryEvent, Verdict

log = logging.getLogger("blockadsd.logstore")

DB_SCHEMA = 1
MAX_READ_LIMIT = 500
MAX_TEXT = 1024
KEEP_DOMAIN_ROWS_PER_DAY = 1000
STATS_RETENTION_DAYS = 400
VERDICT_CODES = {Verdict.FORWARDED: 0, Verdict.BLOCKED: 1, Verdict.LOCAL: 2, Verdict.FAILED: 3}
VERDICT_NAMES = {code: verdict.value for verdict, code in VERDICT_CODES.items()}
SQLITE_CORRUPT, SQLITE_FULL, SQLITE_NOTADB = 11, 13, 26

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS query_log(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,            -- Unix time, milliseconds
    name TEXT NOT NULL,
    qtype INTEGER NOT NULL,
    verdict INTEGER NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    rcode INTEGER NOT NULL DEFAULT 0,
    upstream TEXT NOT NULL DEFAULT '',
    tier TEXT NOT NULL DEFAULT '',
    cached INTEGER NOT NULL DEFAULT 0,
    elapsed REAL NOT NULL DEFAULT 0,
    answers TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS query_log_ts ON query_log(ts);
CREATE TABLE IF NOT EXISTS stats_hourly(
    hour INTEGER PRIMARY KEY,       -- Unix time // 3600
    total INTEGER NOT NULL DEFAULT 0, blocked INTEGER NOT NULL DEFAULT 0,
    forwarded INTEGER NOT NULL DEFAULT 0, local INTEGER NOT NULL DEFAULT 0,
    failed INTEGER NOT NULL DEFAULT 0, cached INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS stats_daily_domain(
    day INTEGER NOT NULL, name TEXT NOT NULL,
    total INTEGER NOT NULL DEFAULT 0, blocked INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(day, name)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS stats_daily_reason(
    day INTEGER NOT NULL, reason TEXT NOT NULL, count INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(day, reason)
) WITHOUT ROWID;
"""


def escape_text(text: str, limit: int = MAX_TEXT) -> str:
    """Printable ASCII only: anything else becomes ``\\DDD`` (per UTF-8 byte)."""
    if text.isascii() and text.isprintable():
        return text[:limit]
    out = []
    for ch in text:
        if ch.isascii() and ch.isprintable():
            out.append(ch)
        else:
            out.extend(f"\\{byte:03d}" for byte in ch.encode("utf-8", "surrogateescape"))
    return "".join(out)[:limit]


def local_day(ts: float) -> int:
    """Days since the epoch in local time (statistics are per local day)."""
    return int((ts + time.localtime(ts).tm_gmtoff) // 86400)


@dataclass(slots=True)
class _Row:
    ts: float  # seconds
    event: QueryEvent


class LogStore:
    def __init__(self, path: Path, *, retention_days: int = 7, recording: bool = True,
                 max_bytes: int = 256 * 1024 * 1024, queue_size: int = 10_000, batch: int = 500,
                 flush_interval: float = 1.0, retry_after: float = 60.0, maintenance_every: float = 3600.0,
                 clock: Callable[[], float] = time.time, monotonic: Callable[[], float] = time.monotonic) -> None:
        self.path = path
        self.retention_days = retention_days
        self.recording = recording
        self.max_bytes = max_bytes
        self.batch = batch
        self.flush_interval = flush_interval
        self.retry_after = retry_after
        self.maintenance_every = maintenance_every
        self._clock = clock
        self._monotonic = monotonic
        self._queue: queue.Queue[_Row] = queue.Queue(queue_size)
        self._commands: deque[tuple[Callable[[sqlite3.Connection], Any], concurrent.futures.Future[Any]]] = deque()
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._conn: sqlite3.Connection | None = None
        self._paused_until = 0.0  # monotonic; disk full
        self._next_maintenance = 0.0
        self.dropped = 0  # queue full, disk full or database errors
        self.written = 0
        self.alerts: dict[str, str] = {}  # kind -> detail (no names): disk_full, db_recreated, db_error

    # --- life cycle ---------------------------------------------------------

    def start(self) -> None:
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._thread = threading.Thread(target=self._run, name="blockadsd-logstore", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        self._wake.set()
        if self._thread is not None:
            self._thread.join(timeout)

    def submit(self, event: QueryEvent) -> bool:
        """Queue one event; never blocks. False if it was dropped."""
        try:
            self._queue.put_nowait(_Row(self._clock(), event))
        except queue.Full:
            self.dropped += 1
            return False
        return True

    def call(self, function: Callable[[sqlite3.Connection], Any]) -> concurrent.futures.Future[Any]:
        """Run ``function(connection)`` on the writer thread, after the queued events."""
        future: concurrent.futures.Future[Any] = concurrent.futures.Future()
        self._commands.append((function, future))
        self._wake.set()
        return future

    def flush(self, timeout: float = 10.0) -> None:
        """Wait until everything submitted so far is written (tests, shutdown)."""
        self.call(lambda conn: None).result(timeout)

    def clear_log(self) -> concurrent.futures.Future[Any]:
        return self.call(lambda conn: _execute(conn, "DELETE FROM query_log"))

    def clear_statistics(self) -> concurrent.futures.Future[Any]:
        def clear(conn: sqlite3.Connection) -> None:
            with conn:
                for table in ("stats_hourly", "stats_daily_domain", "stats_daily_reason"):
                    conn.execute(f"DELETE FROM {table}")
        return self.call(clear)

    def maintain(self) -> concurrent.futures.Future[Any]:
        return self.call(self._maintenance)

    # --- writer thread --------------------------------------------------------

    def _run(self) -> None:
        try:
            self._open()
        except sqlite3.Error as exc:
            self.alerts["db_error"] = type(exc).__name__
            log.error("cannot open the log database: %s", type(exc).__name__)
        while True:
            rows = self._take()
            if rows:
                self._write(rows)
            if self._commands:
                # Commands run after everything queued before them.
                while rows := self._take():
                    self._write(rows)
            while self._commands:
                function, future = self._commands.popleft()
                self._command(function, future)
            if self._conn is not None and self._monotonic() >= self._next_maintenance:
                self._next_maintenance = self._monotonic() + self.maintenance_every
                self._guarded(self._maintenance)
            if self._stop.is_set() and self._queue.empty() and not self._commands:
                break
        if self._conn is not None:
            self._conn.close()

    def _take(self) -> list[_Row]:
        rows: list[_Row] = []
        deadline = self._monotonic() + self.flush_interval
        while len(rows) < self.batch:
            if self._commands or self._stop.is_set():
                timeout = 0.0
            else:
                timeout = max(0.0, deadline - self._monotonic())
            try:
                rows.append(self._queue.get(timeout=timeout) if timeout else self._queue.get_nowait())
            except queue.Empty:
                break
        return rows

    def _command(self, function: Callable[[sqlite3.Connection], Any], future: concurrent.futures.Future[Any]) -> None:
        if self._conn is None:
            future.set_exception(RuntimeError("log database unavailable"))
            return
        try:
            future.set_result(function(self._conn))
        except sqlite3.Error as exc:
            future.set_exception(exc)
            self._database_error(exc)
        except Exception as exc:
            future.set_exception(exc)

    def _open(self) -> None:
        conn = sqlite3.connect(self.path, isolation_level=None, check_same_thread=False, timeout=5.0)
        try:
            conn.execute("PRAGMA auto_vacuum=INCREMENTAL")  # only effective before the first table
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            result = conn.execute("PRAGMA quick_check").fetchone()
            if result is None or result[0] != "ok":
                raise sqlite3.DatabaseError("quick_check failed")
            conn.executescript(SCHEMA)
            conn.execute("INSERT OR IGNORE INTO meta VALUES('schema', ?)", (str(DB_SCHEMA),))
            os.chmod(self.path, 0o600)
        except sqlite3.DatabaseError as exc:
            conn.close()
            if _code(exc) in (SQLITE_CORRUPT, SQLITE_NOTADB) or "quick_check" in str(exc):
                self._recreate(f"{type(exc).__name__} at open")
                return
            raise
        self._conn = conn

    def _recreate(self, why: str) -> None:
        """Move a corrupt database aside and start a new one."""
        if self._conn is not None:
            self._conn.close()
            self._conn = None
        stamp = int(self._clock())
        for suffix in ("", "-wal", "-shm"):
            source = Path(f"{self.path}{suffix}")
            if source.exists():
                os.replace(source, Path(f"{self.path}.corrupt-{stamp}{suffix}"))
        old = sorted(self.path.parent.glob(f"{self.path.name}.corrupt-*"))
        keep = {p.name.split("-wal")[0].split("-shm")[0] for p in old[-3:]}
        for extra in old:
            if extra.name.split("-wal")[0].split("-shm")[0] not in keep:
                extra.unlink(missing_ok=True)
        self.alerts["db_recreated"] = why
        log.warning("log database was corrupt (%s); moved aside and recreated", why)
        self._open()

    def _write(self, rows: list[_Row]) -> None:
        if self._conn is None or self._monotonic() < self._paused_until:
            self.dropped += len(rows)
            return
        try:
            self._insert(self._conn, rows)
        except sqlite3.Error as exc:
            self.dropped += len(rows)
            self._database_error(exc)
            return
        self.written += len(rows)
        if self.alerts.pop("disk_full", None) is not None:
            log.info("log database writable again")

    def _insert(self, conn: sqlite3.Connection, rows: Iterable[_Row]) -> None:
        hourly: dict[int, list[int]] = {}
        domains: dict[tuple[int, str], list[int]] = {}
        reasons: dict[tuple[int, str], int] = {}
        log_rows = []
        for row in rows:
            event = row.event
            code = VERDICT_CODES[event.verdict]
            name = escape_text(event.name, 255 * 4)
            counters = hourly.setdefault(int(row.ts // 3600), [0, 0, 0, 0, 0, 0])
            counters[0] += 1
            counters[1 + code] += 1
            counters[5] += 1 if event.cached else 0
            day = local_day(row.ts)
            if event.blocked:
                for reason in (event.reason or "unknown").split(","):
                    key = (day, escape_text(reason, 100))
                    reasons[key] = reasons.get(key, 0) + 1
            if self.recording:
                totals = domains.setdefault((day, name), [0, 0])
                totals[0] += 1
                totals[1] += 1 if event.blocked else 0
                log_rows.append((int(row.ts * 1000), name, event.qtype, code, escape_text(event.reason, 200),
                                 event.rcode, escape_text(event.upstream, 200), escape_text(event.tier, 40),
                                 int(event.cached), round(event.elapsed_ms, 2),
                                 escape_text(",".join(event.answers), 400)))
        with conn:  # one transaction
            conn.execute("BEGIN")
            conn.executemany(
                "INSERT INTO query_log(ts, name, qtype, verdict, reason, rcode, upstream, tier, cached, elapsed,"
                " answers) VALUES(?,?,?,?,?,?,?,?,?,?,?)", log_rows)
            # forwarded, blocked, local, failed follow VERDICT_CODES order
            conn.executemany(
                "INSERT INTO stats_hourly(hour, total, forwarded, blocked, local, failed, cached)"
                " VALUES(?,?,?,?,?,?,?) ON CONFLICT(hour) DO UPDATE SET total=total+excluded.total,"
                " forwarded=forwarded+excluded.forwarded, blocked=blocked+excluded.blocked,"
                " local=local+excluded.local, failed=failed+excluded.failed, cached=cached+excluded.cached",
                [(hour, *c) for hour, c in hourly.items()])
            conn.executemany(
                "INSERT INTO stats_daily_domain(day, name, total, blocked) VALUES(?,?,?,?)"
                " ON CONFLICT(day, name) DO UPDATE SET total=total+excluded.total, blocked=blocked+excluded.blocked",
                [(day, name, *c) for (day, name), c in domains.items()])
            conn.executemany(
                "INSERT INTO stats_daily_reason(day, reason, count) VALUES(?,?,?)"
                " ON CONFLICT(day, reason) DO UPDATE SET count=count+excluded.count",
                [(day, reason, count) for (day, reason), count in reasons.items()])

    def _guarded(self, function: Callable[[sqlite3.Connection], Any]) -> None:
        if self._conn is None:
            return
        try:
            function(self._conn)
        except sqlite3.Error as exc:
            self._database_error(exc)

    def _database_error(self, exc: sqlite3.Error) -> None:
        code = _code(exc)
        if code == SQLITE_FULL or "full" in str(exc).lower():
            self._paused_until = self._monotonic() + self.retry_after
            if "disk_full" not in self.alerts:
                log.warning("disk full: query logging paused for %.0f s", self.retry_after)
            self.alerts["disk_full"] = "no space left for the log database"
        elif code in (SQLITE_CORRUPT, SQLITE_NOTADB) or isinstance(exc, sqlite3.DatabaseError) and \
                "malformed" in str(exc):
            self._recreate(type(exc).__name__)
        else:
            self.alerts["db_error"] = type(exc).__name__
            log.warning("log database error: %s", type(exc).__name__)
        if self._conn is not None:
            try:
                self._conn.rollback()
            except sqlite3.Error:
                pass

    def _maintenance(self, conn: sqlite3.Connection) -> dict[str, int]:
        now = self._clock()
        newest = conn.execute("SELECT MAX(ts) FROM query_log").fetchone()[0]
        reference = min(now, newest / 1000) if newest is not None else now
        cutoff_ms = int((reference - self.retention_days * 86400) * 1000)
        removed = _execute(conn, "DELETE FROM query_log WHERE ts < ?", (cutoff_ms,))
        newest_hour = conn.execute("SELECT MAX(hour) FROM stats_hourly").fetchone()[0]
        stats_reference = min(now, (newest_hour + 1) * 3600) if newest_hour is not None else now
        stats_cutoff = stats_reference - STATS_RETENTION_DAYS * 86400
        with conn:
            conn.execute("BEGIN")
            conn.execute("DELETE FROM stats_hourly WHERE hour < ?", (int(stats_cutoff // 3600),))
            conn.execute("DELETE FROM stats_daily_reason WHERE day < ?", (local_day(stats_cutoff),))
            conn.execute("DELETE FROM stats_daily_domain WHERE day < ?", (local_day(stats_cutoff),))
            # Finished days keep only their top domains.
            conn.execute(
                "DELETE FROM stats_daily_domain WHERE day < ? AND (day, name) NOT IN ("
                " SELECT day, name FROM (SELECT day, name, ROW_NUMBER() OVER"
                " (PARTITION BY day ORDER BY total DESC, name) AS position FROM stats_daily_domain WHERE day < ?)"
                " WHERE position <= ?)", (local_day(now), local_day(now), KEEP_DOMAIN_ROWS_PER_DAY))
        trimmed = 0
        while self._size(conn) > self.max_bytes:
            count = conn.execute("SELECT COUNT(*) FROM query_log").fetchone()[0]
            if not count:
                break
            step = max(1, count // 10)
            trimmed += _execute(conn, "DELETE FROM query_log WHERE id IN"
                                      " (SELECT id FROM query_log ORDER BY id LIMIT ?)", (step,))
            self._reclaim(conn)
        self._reclaim(conn)
        return {"expired": removed, "trimmed": trimmed}

    @staticmethod
    def _reclaim(conn: sqlite3.Connection) -> None:
        """Give free pages back to the file system; best effort (a full disk may refuse)."""
        for pragma in ("wal_checkpoint(TRUNCATE)", "incremental_vacuum", "wal_checkpoint(TRUNCATE)"):
            with contextlib.suppress(sqlite3.OperationalError):
                conn.execute(f"PRAGMA {pragma}").fetchall()

    @staticmethod
    def _size(conn: sqlite3.Connection) -> int:
        pages = conn.execute("PRAGMA page_count").fetchone()[0] - conn.execute("PRAGMA freelist_count").fetchone()[0]
        return pages * conn.execute("PRAGMA page_size").fetchone()[0]

    # --- reads (any thread) ------------------------------------------------------

    def _reader(self) -> sqlite3.Connection:
        conn = sqlite3.connect(f"file:{self.path}?mode=ro", uri=True, timeout=5.0)
        conn.row_factory = sqlite3.Row
        return conn

    def query_log(self, *, after_id: int = 0, before_id: int | None = None, limit: int = 100,
                  verdict: str | None = None, search: str | None = None, since_ms: int | None = None,
                  until_ms: int | None = None) -> list[dict[str, Any]]:
        """Entries newer than ``after_id`` (ascending), or older than ``before_id`` (descending)."""
        limit = max(1, min(int(limit), MAX_READ_LIMIT))
        where, args = ["id > ?"], [int(after_id)]
        if before_id is not None:
            where.append("id < ?")
            args.append(int(before_id))
        if verdict is not None:
            codes = {name: code for code, name in VERDICT_NAMES.items()}
            if verdict not in codes:
                raise ValueError(f"unknown verdict {verdict!r}")
            where.append("verdict = ?")
            args.append(codes[verdict])
        if search:
            pattern = search.lower()[:255].replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            where.append("name LIKE ? ESCAPE '\\'")
            args.append(f"%{pattern}%")
        if since_ms is not None:
            where.append("ts >= ?")
            args.append(int(since_ms))
        if until_ms is not None:
            where.append("ts < ?")
            args.append(int(until_ms))
        order = "DESC" if before_id is not None else "ASC"
        with contextlib.closing(self._reader()) as conn:
            rows = conn.execute(f"SELECT * FROM query_log WHERE {' AND '.join(where)} ORDER BY id {order} LIMIT ?",
                                (*args, limit)).fetchall()
        return [{
            "id": r["id"], "time_ms": r["ts"], "name": r["name"], "qtype": r["qtype"],
            "verdict": VERDICT_NAMES.get(r["verdict"], "?"), "reason": r["reason"], "rcode": r["rcode"],
            "upstream": r["upstream"], "tier": r["tier"], "cached": bool(r["cached"]),
            "elapsed_ms": r["elapsed"], "answers": r["answers"].split(",") if r["answers"] else [],
        } for r in rows]

    def totals(self, since: float, until: float | None = None) -> dict[str, int]:
        with contextlib.closing(self._reader()) as conn:
            row = conn.execute(
                "SELECT COALESCE(SUM(total),0), COALESCE(SUM(blocked),0), COALESCE(SUM(forwarded),0),"
                " COALESCE(SUM(local),0), COALESCE(SUM(failed),0), COALESCE(SUM(cached),0) FROM stats_hourly"
                " WHERE hour >= ? AND hour < ?",
                (int(since // 3600), int((until if until is not None else 2**40) // 3600) + 1)).fetchone()
        return dict(zip(("total", "blocked", "forwarded", "local", "failed", "cached"), row))

    def series(self, period: str, now: float | None = None) -> list[dict[str, int]]:
        """Chart buckets: 24h → 24 hours, 7d → 7 days, 4w → 28 days, 12m → 12 months (local time)."""
        now = self._clock() if now is None else now
        if period == "24h":
            first_hour = int(now // 3600) - 23
            keys = list(range(first_hour, first_hour + 24))
            bucket: Callable[[int], int] = lambda hour: hour  # noqa: E731
            since_hour = first_hour
        elif period in ("7d", "4w"):
            days = 7 if period == "7d" else 28
            today = local_day(now)
            keys = list(range(today - days + 1, today + 1))
            bucket = lambda hour: local_day(hour * 3600)  # noqa: E731
            since_hour = int(now // 3600) - days * 24 - 24
        elif period == "12m":
            current = time.localtime(now)
            months = [(current.tm_year * 12 + current.tm_mon - 1) - i for i in range(11, -1, -1)]
            keys = months

            def bucket(hour: int) -> int:
                t = time.localtime(hour * 3600)
                return t.tm_year * 12 + t.tm_mon - 1
            since_hour = int(now // 3600) - 370 * 24
        else:
            raise ValueError(f"unknown period {period!r}")
        result = {key: {"total": 0, "blocked": 0} for key in keys}
        with contextlib.closing(self._reader()) as conn:
            for hour, total, blocked in conn.execute(
                    "SELECT hour, total, blocked FROM stats_hourly WHERE hour >= ?", (since_hour,)):
                key = bucket(hour)
                if key in result:
                    result[key]["total"] += total
                    result[key]["blocked"] += blocked
        return [{"bucket": key, **values} for key, values in result.items()]

    def top_domains(self, days: int = 1, *, blocked: bool = True, limit: int = 10,
                    now: float | None = None) -> list[dict[str, Any]]:
        today = local_day(self._clock() if now is None else now)
        column = "blocked" if blocked else "total"
        with contextlib.closing(self._reader()) as conn:
            rows = conn.execute(
                f"SELECT name, SUM({column}) AS n FROM stats_daily_domain WHERE day > ? GROUP BY name"
                f" HAVING n > 0 ORDER BY n DESC, name LIMIT ?",
                (today - days, max(1, min(limit, MAX_READ_LIMIT)))).fetchall()
        return [{"name": name, "count": count} for name, count in rows]

    def reasons(self, days: int = 1, *, now: float | None = None) -> dict[str, int]:
        today = local_day(self._clock() if now is None else now)
        with contextlib.closing(self._reader()) as conn:
            rows = conn.execute("SELECT reason, SUM(count) FROM stats_daily_reason WHERE day > ?"
                                " GROUP BY reason ORDER BY 2 DESC", (today - days,)).fetchall()
        return dict(rows)


def _execute(conn: sqlite3.Connection, sql: str, args: tuple = ()) -> int:
    with conn:
        return conn.execute(sql, args).rowcount


def _code(exc: BaseException) -> int | None:
    code = getattr(exc, "sqlite_errorcode", None)
    return code & 0xFF if isinstance(code, int) else None
