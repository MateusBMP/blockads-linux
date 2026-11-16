#!/bin/sh
# The GUI tests with no network at all.
# A new network namespace has only a loopback interface: the private
# dbus-daemon, the dev daemon on 127.0.0.1 and the fake upstream work; any
# other connection fails at once, so a GUI path that needs the network fails
# its test instead of passing silently.
#   sh tests/netns/gui_offline.sh
set -eu
HERE=$(cd "$(dirname "$0")/../.." && pwd)
cd "$HERE"
python3 -c 'import PyQt6.QtWidgets' 2>/dev/null || { echo "SKIP  PyQt6 is not installed"; exit 0; }
exec unshare -Urn sh -c '
    ip link set lo up
    if ip route get 9.9.9.9 >/dev/null 2>&1; then echo "FAIL  the namespace has a route out"; exit 1; fi
    QT_QPA_PLATFORM=offscreen exec python3 -m pytest -q -p no:asyncio -p no:cacheprovider tests/unit/test_gui.py -rs
'
