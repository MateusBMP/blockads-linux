"""Where blockads-linux keeps its state.

Everything lives under one directory, ``/var/lib/blockads-linux`` (mode
0700, owned by user ``blockads``). ``BLOCKADS_STATE_DIR`` overrides it for
development and tests::

    config/settings.json  config/rules.json     (+ .bak)
    db/blockads.sqlite3                          query log and statistics
    filters/manifest.json filters/manifest.prev.json
    filters/artifacts/<sha256>.bkf
    filters/tmp/                                 downloads in progress
    update.request                               "Update now" (watched by blockads-update.path)
    update-status.json                           last updater run, for the GUI
    update.lock
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

DEFAULT_STATE_DIR = Path("/var/lib/blockads-linux")
STATE_DIR_ENV = "BLOCKADS_STATE_DIR"


@dataclass(frozen=True, slots=True)
class Paths:
    root: Path

    @classmethod
    def default(cls) -> Paths:
        override = os.environ.get(STATE_DIR_ENV)
        return cls(Path(override) if override else DEFAULT_STATE_DIR)

    @property
    def config(self) -> Path:
        return self.root / "config"

    @property
    def settings(self) -> Path:
        return self.config / "settings.json"

    @property
    def rules(self) -> Path:
        return self.config / "rules.json"

    @property
    def db_dir(self) -> Path:
        return self.root / "db"

    @property
    def db(self) -> Path:
        return self.db_dir / "blockads.sqlite3"

    @property
    def filters(self) -> Path:
        return self.root / "filters"

    @property
    def artifacts(self) -> Path:
        return self.filters / "artifacts"

    @property
    def manifest(self) -> Path:
        return self.filters / "manifest.json"

    @property
    def previous_manifest(self) -> Path:
        return self.filters / "manifest.prev.json"

    @property
    def download_dir(self) -> Path:
        return self.filters / "tmp"

    @property
    def update_request(self) -> Path:
        return self.root / "update.request"

    @property
    def update_status(self) -> Path:
        return self.root / "update-status.json"

    @property
    def update_lock(self) -> Path:
        return self.root / "update.lock"

    def ensure(self) -> None:
        """Create the directories (private: 0700)."""
        for directory in (self.root, self.config, self.db_dir, self.filters, self.artifacts, self.download_dir):
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
