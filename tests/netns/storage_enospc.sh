#!/bin/sh
# Storage checks that need a private mount namespace (rootless):
# real ENOSPC on a tiny tmpfs for atomic writes and the log database.
#   sh tests/netns/storage_enospc.sh
set -eu
HERE=$(cd "$(dirname "$0")/../.." && pwd)
cd "$HERE"
exec unshare -Urm python3 -m pytest -q -p no:asyncio -p no:cacheprovider \
    tests/unit/test_atomic.py tests/unit/test_logstore.py -k "tmpfs or enospc" -rs
