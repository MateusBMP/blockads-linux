#!/usr/bin/env bash
# Offline check: the standalone resolver in a network
# namespace that has only loopback. Blocked names must still be answered,
# forwarded names must fail fast with SERVFAIL (never hang), garbage must not
# hurt, and SIGTERM must stop the daemon cleanly.
#
# Rootless: runs inside `unshare --map-root-user --net`, so it never touches
# the host network or firewall.
#
# Usage: tests/netns/offline_resolver.sh          (exit status 0 = all checks passed)
set -eu
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ "${1:-}" != "--inner" ]]; then
    exec unshare --map-root-user --net -- bash "${BASH_SOURCE[0]}" --inner
fi
ip link set lo up
exec python3 "$HERE/offline_resolver.py"
