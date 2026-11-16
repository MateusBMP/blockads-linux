"""Tests for the updater run (updater.run, updater.manifest, updater.__main__)."""

import asyncio
import json

import pytest

from blockads_linux.common.atomic import write_json
from blockads_linux.common.paths import Paths
from blockads_linux.filters.artifact import LoadedArtifact
from blockads_linux.filters.catalog import Catalog, CatalogEntry
from blockads_linux.updater import manifest as mf
from blockads_linux.updater.__main__ import main as update_main
from blockads_linux.updater.fetch import Fetcher
from blockads_linux.updater.run import Target, Updater, is_due
from blockads_linux.updater.manifest import ListEntry, Source

from .https_server import HttpsServer, static
from .upstreams import make_test_ca, server_tls_context

pytest.importorskip("cryptography")

NOW = 1_800_000_000


def hosts(n, prefix="d"):
    return "".join(f"0.0.0.0 {prefix}{i}.example\n" for i in range(n)).encode()


class Clock:
    def __init__(self):
        self.now = NOW

    def __call__(self):
        return self.now


@pytest.fixture(scope="module")
def tls(tmp_path_factory):
    ca, cert, key = make_test_ca(tmp_path_factory.mktemp("ca"), names=("lists.test",))
    return str(ca), server_tls_context(cert, key)


class World:
    """A state directory, a list server and an updater wired together."""

    def __init__(self, tmp_path, tls):
        self.paths = Paths(tmp_path / "state")
        self.tls = tls
        self.clock = Clock()
        self.content = {"/a.txt": hosts(100, "a"), "/b.txt": hosts(50, "b"), "/c1.txt": hosts(10, "c"),
                        "/c2.txt": hosts(10, "e"), "/retired.txt": hosts(5, "r")}
        self.metered = False
        self.server = None

    def route(self, path):
        def handler(request):
            body = self.content[path]
            if isinstance(body, tuple):  # (status, headers, body)
                return body
            etag = f'"{hash(body) & 0xffffffff:x}"'
            return static(body, etag=etag)(request)
        return handler

    def catalog(self):
        base = f"https://lists.test:{self.server.port}"
        def entry(list_id, path, retired=None):
            return CatalogEntry(list_id, list_id, "", "ads", base + path, False, False, 0, retired)
        return Catalog("test", (entry("list_a", "/a.txt"), entry("list_b", "/b.txt"),
                                entry("old_list", "/retired.txt", retired="gone")))

    def settings(self, enabled=("list_a", "list_b", "old_list"), custom=True, interval=24, unmetered=False):
        base = f"https://lists.test:{self.server.port}"
        doc = {"schema": 1, "filters": {"enabled": list(enabled), "update_interval_hours": interval,
                                        "unmetered_only": unmetered, "custom": []}}
        if custom:
            doc["filters"]["custom"] = [{"id": "custom_mine", "name": "Mine", "urls": [base + "/c1.txt",
                                                                                      base + "/c2.txt"]}]
        write_json(self.paths.settings, doc)

    async def start(self):
        self.server = await HttpsServer(self.tls[1], {p: self.route(p) for p in self.content}).start()

    def updater(self):
        async def resolve(host):
            return ["127.0.0.1"]

        async def metered():
            return self.metered

        fetcher = Fetcher(resolve, cafile=self.tls[0], allow_address=lambda a: True)
        return Updater(self.paths, fetcher, catalog=self.catalog(), metered=metered, clock=self.clock)

    async def run(self, **kwargs):
        return await self.updater().run(**kwargs)

    def manifest(self):
        return mf.load_manifest(self.paths.manifest)

    def requests(self):
        return len(self.server.requests)


@pytest.fixture
def world(tmp_path, tls):
    return World(tmp_path, tls)


def run(world, scenario):
    async def body():
        await world.start()
        try:
            await scenario()
        finally:
            world.server.close()
    asyncio.run(body())


def test_first_run_then_nothing_due(world):
    async def scenario():
        world.settings()
        status = await world.run()
        assert status["summary"] == {"updated": 3, "unchanged": 0, "failed": 0}
        assert "old_list" not in status["lists"]  # retired lists are skipped
        m = world.manifest()
        assert m.generation == 1 and set(m.lists) == {"list_a", "list_b", "custom_mine"}
        assert m.lists["list_a"].rules == 100 and m.lists["custom_mine"].rules == 20  # merged URLs
        for entry in m.lists.values():
            artifact = LoadedArtifact.open(world.paths.artifacts / entry.artifact)
            assert artifact.info.block_count == entry.rules
        assert json.loads(world.paths.update_status.read_text())["summary"]["updated"] == 3
        assert not list(world.paths.download_dir.iterdir())  # downloads cleaned up
        requests = world.requests()
        world.clock.now += 3600
        status = await world.run()
        assert status["lists"] == {} and world.requests() == requests and world.manifest().generation == 1

    run(world, scenario)


def test_conditional_unchanged_keeps_the_rollback_copy(world):
    async def scenario():
        world.settings()
        await world.run()
        world.content["/a.txt"] = hosts(120, "a")
        await world.run(force=True)
        assert world.manifest().generation == 2
        prev = mf.load_manifest(world.paths.previous_manifest)
        assert prev.generation == 1 and prev.lists["list_a"].rules == 100
        world.clock.now += 25 * 3600
        status = await world.run()  # all due; the server answers 304
        assert status["summary"] == {"updated": 0, "unchanged": 3, "failed": 0}
        assert all(r.headers.get("if-none-match") for r in world.server.requests[-4:])
        m = world.manifest()
        assert m.generation == 2 and m.lists["list_a"].checked_at == NOW + 25 * 3600
        assert m.lists["list_a"].changed_at == NOW
        assert mf.load_manifest(world.paths.previous_manifest).generation == 1  # untouched
        # Both generations' artifacts are kept; a third generation drops the first's.
        names = {p.name for p in world.paths.artifacts.iterdir()}
        assert prev.lists["list_a"].artifact in names
        world.content["/a.txt"] = hosts(130, "a")
        await world.run(force=True)
        names = {p.name for p in world.paths.artifacts.iterdir()}
        assert prev.lists["list_a"].artifact not in names

    run(world, scenario)


def test_bad_updates_keep_the_last_good_list(world):
    async def scenario():
        world.settings(custom=False)
        await world.run()
        good = world.manifest().lists["list_a"]
        for body, message in [
            (hosts(5, "a"), "shrank from 100 to 5"),
            (b"# nothing here\n! only comments\n", "no valid rules"),
            ((200, {"Content-Type": "text/html"}, b"<html>portal</html>"), "HTML page"),
            ((500, {}, b"oops"), "HTTP 500"),
        ]:
            world.content["/a.txt"] = body
            status = await world.run(force=True)
            assert status["lists"]["list_a"]["result"] == "failed"
            entry = world.manifest().lists["list_a"]
            assert message in entry.error, message
            assert entry.artifact == good.artifact and entry.rules == 100
            assert (world.paths.artifacts / good.artifact).exists()
        # A failed list is retried after an hour, not only after the interval.
        world.content["/a.txt"] = hosts(100, "a2")
        world.clock.now += 1800
        assert "list_a" not in (await world.run())["lists"]
        world.clock.now += 1800
        status = await world.run()
        assert status["lists"]["list_a"]["result"] == "updated" and world.manifest().lists["list_a"].error == ""

    run(world, scenario)


def test_disabling_metered_request_file_and_clock(world):
    async def scenario():
        world.settings(unmetered=True)
        world.metered = True
        status = await world.run()
        assert status["skipped"] == "metered" and world.manifest() is None
        world.paths.update_request.touch()  # "Update now" overrides metered
        status = await world.run()
        assert status["forced"] and status["summary"]["updated"] == 3
        assert not world.paths.update_request.exists()
        world.settings(enabled=("list_a",), custom=False)
        world.metered = False
        await world.run()
        assert set(world.manifest().lists) == {"list_a"}  # disabled lists leave the manifest
        # The clock went back a year: everything is due again.
        world.clock.now -= 365 * 86400
        status = await world.run()
        assert status["lists"]["list_a"]["result"] == "unchanged"

    run(world, scenario)


def test_manual_interval_still_fetches_new_lists(world):
    async def scenario():
        world.settings(enabled=("list_a",), custom=False, interval=0)
        await world.run()
        world.clock.now += 400 * 86400
        assert (await world.run())["lists"] == {}  # manual: never due again
        world.settings(enabled=("list_a", "list_b"), custom=False, interval=0)
        status = await world.run()
        assert list(status["lists"]) == ["list_b"]
        status = await world.run(force=True, only={"list_a"})
        assert list(status["lists"]) == ["list_a"]

    run(world, scenario)


def test_rollback_and_cli(world, monkeypatch, capsys):
    async def scenario():
        world.settings(custom=False)
        await world.run()
        world.content["/a.txt"] = hosts(150, "a")
        await world.run(force=True)

    run(world, scenario)
    monkeypatch.setenv("BLOCKADS_STATE_DIR", str(world.paths.root))
    assert world.manifest().lists["list_a"].rules == 150
    assert update_main(["--rollback"]) == 0
    assert world.manifest().lists["list_a"].rules == 100 and world.manifest().generation == 3
    assert update_main(["--rollback"]) == 0  # undo
    assert world.manifest().lists["list_a"].rules == 150
    world.paths.previous_manifest.unlink()
    assert update_main(["--rollback"]) == 1
    assert "no previous generation" in capsys.readouterr().err


def test_concurrent_runs_are_refused(world, monkeypatch):
    import fcntl

    monkeypatch.setenv("BLOCKADS_STATE_DIR", str(world.paths.root))
    world.paths.ensure()
    with open(world.paths.update_lock, "a+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        assert update_main([]) == 75


def test_is_due():
    target = Target("x", ("https://a.example/x",))
    entry = ListEntry("0" * 64 + ".bkf", 10, NOW, NOW, NOW, (Source("https://a.example/x"),))
    assert is_due(target, None, 24, NOW)
    assert not is_due(target, entry, 24, NOW + 3600)
    assert is_due(target, entry, 24, NOW + 24 * 3600)
    assert is_due(Target("x", ("https://b.example/x",)), entry, 24, NOW)  # URL changed
    assert is_due(target, entry, 24, NOW - 2 * 86400)  # checked "in the future"


def test_manifest_validation(tmp_path):
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps({"schema": 1, "lists": {"x": {"artifact": "../../etc/passwd"}}}))
    assert mf.load_manifest(path) is None
    good = mf.Manifest(1, NOW, {"x": ListEntry("a" * 64 + ".bkf", 5)})
    assert mf.Manifest.from_dict(good.to_dict()) == good
    with pytest.raises(mf.ManifestError):
        mf.rollback(tmp_path / "m.json", tmp_path / "p.json")
