#!/usr/bin/env python3
"""Run helper/blockads-fw inside a test namespace with test constants.

The helper has no CLI or environment overrides on purpose; this wrapper
patches its module constants instead. Only used by tests/netns/fw_helper.sh.

    FW_BIN_DIRS=/run/bin-nft  FW_TIMEOUT=2  python3 -I fw_run.py HELPER apply --verify

- root inside a user namespace sees real root's files as uid 65534, so 65534
  is trusted as well as 0;
- the 'blockads' user is played by uid 1, systemd-resolve is absent;
- firewall.conf lives in /run/etc (the namespace's private /run tmpfs).
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import os
import pwd
import sys


def main() -> int:
    helper = sys.argv[1]
    loader = importlib.machinery.SourceFileLoader("blockads_fw", helper)
    spec = importlib.util.spec_from_loader("blockads_fw", loader)
    mod = importlib.util.module_from_spec(spec)
    sys.dont_write_bytecode = True
    loader.exec_module(mod)

    mod.TRUSTED_UIDS = frozenset({0, 65534})
    mod.SERVICE_USER = pwd.getpwuid(1).pw_name
    mod.RESOLVED_USER = "blockads-test-no-such-user"
    mod.CONF_PATH = "/run/etc/blockads-linux/firewall.conf"
    mod.RUN_DIR = "/run/blockads-fw"
    if os.environ.get("FW_BIN_DIRS"):
        mod.BIN_DIRS = tuple(os.environ["FW_BIN_DIRS"].split(":"))
    if os.environ.get("FW_TIMEOUT"):
        seconds = float(os.environ["FW_TIMEOUT"])
        mod.CMD_TIMEOUT = seconds
        mod.RESTORE_TIMEOUT = seconds
    return mod.main(sys.argv[2:])


if __name__ == "__main__":
    sys.exit(main())
