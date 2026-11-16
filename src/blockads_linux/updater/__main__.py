"""``blockads-update``: download and compile the enabled filter lists.

Run by ``blockads-update.timer`` (hourly) and ``blockads-update.path``
("Update now" touches ``update.request``), as user ``blockads``::

    blockads-update                 # lists that are due
    blockads-update --force         # every enabled list
    blockads-update --list ID       # just these (forced)
    blockads-update --rollback      # back to the previous generation

Development: ``BLOCKADS_STATE_DIR=/tmp/state blockads-update --resolver 127.0.0.1:5300``.
"""

from __future__ import annotations

import argparse
import asyncio
import fcntl
import logging
import os
import sys

from ..common.legal import add_version_option
from ..common.paths import Paths
from . import manifest as mf
from .fetch import DaemonResolver, Fetcher
from .run import Updater

log = logging.getLogger("blockads-update")
EXIT_BUSY = 75  # EX_TEMPFAIL: another run holds the lock


def _resolver(text: str) -> tuple[str, int]:
    host, _, port = text.rpartition(":")
    if not host or not port.isdigit():
        raise argparse.ArgumentTypeError("expected ADDR:PORT")
    return host.strip("[]"), int(port)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="blockads-update", description="update blockads-linux filter lists")
    add_version_option(parser, "blockads-update")
    parser.add_argument("--force", action="store_true", help="update every enabled list now")
    parser.add_argument("--list", action="append", default=[], metavar="ID", help="update only this list (forced)")
    parser.add_argument("--rollback", action="store_true", help="restore the previous generation of lists")
    parser.add_argument("--resolver", type=_resolver, default=("127.0.0.1", 153), metavar="ADDR:PORT",
                        help="DNS server used to resolve list hosts (default: the daemon, 127.0.0.1:153)")
    parser.add_argument("--cafile", help=argparse.SUPPRESS)  # tests only
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser


async def metered() -> bool:
    """NetworkManager's Metered property; unknown (no bus, no NM) counts as unmetered."""
    try:
        from jeepney.io.asyncio import open_dbus_router

        from ..daemon.netmon import DBusProperties, read_state

        async with asyncio.timeout(3):
            async with open_dbus_router("SYSTEM") as router:
                state = await read_state(DBusProperties(router))
        return state.metered.metered
    except Exception:
        return False


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(levelname)s %(name)s: %(message)s")
    for noisy in ("httpx", "httpcore", "hpack", "h2"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    os.umask(0o077)
    paths = Paths.default()
    paths.ensure()
    with open(paths.update_lock, "a+") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print("blockads-update: another update is running", file=sys.stderr)
            return EXIT_BUSY
        if args.rollback:
            try:
                restored = mf.rollback(paths.manifest, paths.previous_manifest)
            except mf.ManifestError as exc:
                print(f"blockads-update: {exc}", file=sys.stderr)
                return 1
            log.info("rolled back to the previous lists (generation %d)", restored.generation)
            return 0
        fetcher = Fetcher(DaemonResolver(*args.resolver), cafile=args.cafile)
        updater = Updater(paths, fetcher, metered=metered)
        status = asyncio.run(updater.run(force=args.force or bool(args.list), only=set(args.list) or None))
    if status["skipped"]:
        log.info("skipped: %s connection", status["skipped"])
        return 0
    summary = status["summary"]
    log.info("%d updated, %d unchanged, %d failed (generation %d)", summary["updated"], summary["unchanged"],
             summary["failed"], status["generation"])
    return 1 if summary["failed"] and not (summary["updated"] or summary["unchanged"]) else 0


if __name__ == "__main__":
    sys.exit(main())
