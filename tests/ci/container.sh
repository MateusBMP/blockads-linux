#!/bin/bash
# Run a test suite inside a distro container with that distro's own packages
# (the point is to test the versions each distribution ships).
#
#   docker run --rm [--privileged] -v "$PWD:/src" -v "$PWD/results:/results" -w /src \
#       debian:12 bash tests/ci/container.sh unit|netns
#
# unit   pytest as an unprivileged user (like on a desktop); JUnit XML in
#        /results/unit.xml, console output in /results/unit.log
# netns  the tests/netns suites as root in user + network namespaces
#        (needs --privileged; for legacy iptables the host must have loaded the
#        ip_tables / ip6_tables modules); logs in /results/<suite>.log, each
#        ending with "exit=N"
#
# Used by .github/workflows/ci.yml; tools/ci/report.py reads the results.
set -euo pipefail
suite=${1:?usage: container.sh unit|netns}
RESULTS=${RESULTS:-/results}
export PYTHONDONTWRITEBYTECODE=1
. /etc/os-release

install_packages() {
    local netns=$1
    case "$ID" in
    debian|ubuntu)
        export DEBIAN_FRONTEND=noninteractive
        local pkgs=(python3 python3-dnspython python3-httpx python3-h2 python3-jeepney
                    python3-pytest python3-cryptography dbus passwd util-linux)
        # GUI tests (offscreen; also netns gui_offline): the platform plugins are only a Recommends of libqt6gui6
        pkgs+=(python3-pyqt6 qt6-qpa-plugins pyqt6-dev-tools)
        [[ $netns == 1 ]] && pkgs+=(iptables nftables iproute2 uidmap procps)
        apt-get update -qq
        apt-get install -y -qq --no-install-recommends "${pkgs[@]}" >/dev/null
        ;;
    fedora)
        local pkgs=(python3 python3-dns python3-httpx python3-h2 python3-jeepney
                    python3-pytest python3-cryptography dbus-daemon shadow-utils util-linux)
        pkgs+=(python3-pyqt6)
        [[ $netns == 1 ]] && pkgs+=(iptables-nft iptables-legacy nftables iproute procps-ng)
        dnf install -y -q --setopt=install_weak_deps=False "${pkgs[@]}" >/dev/null
        ;;
    arch)
        local pkgs=(python python-dnspython python-httpx python-h2 python-jeepney
                    python-pytest python-cryptography dbus shadow util-linux)
        pkgs+=(python-pyqt6)
        [[ $netns == 1 ]] && pkgs+=(iptables nftables iproute2 procps-ng)
        pacman -Syu --noconfirm --needed --noprogressbar "${pkgs[@]}" >/dev/null
        ;;
    *)
        echo "container.sh: unsupported distribution $ID" >&2
        exit 2
        ;;
    esac
}

versions() {
    echo "distro: $PRETTY_NAME"
    python3 -I -c 'import sys, dns.version, httpx, jeepney
try:
    import httpcore; hc = httpcore.__version__
except Exception: hc = "?"
try:
    from PyQt6.QtCore import PYQT_VERSION_STR, QT_VERSION_STR; qt = f"PyQt {PYQT_VERSION_STR} (Qt {QT_VERSION_STR})"
except Exception: qt = "no PyQt6"
print(f"python {sys.version.split()[0]}, dnspython {dns.version.version}, httpx {httpx.__version__}, httpcore {hc}, jeepney {jeepney.__version__}, {qt}")'
    command -v iptables >/dev/null && iptables -V || true
}

mkdir -p "$RESULTS"
chmod 0777 "$RESULTS"

case "$suite" in
unit)
    install_packages 0
    versions | tee "$RESULTS/versions.txt"
    # Unprivileged, like a desktop user (root would bypass permission checks).
    id ci >/dev/null 2>&1 || useradd --create-home --shell /bin/bash ci
    set +e
    setpriv --reuid=ci --regid=ci --init-groups env HOME=/home/ci PYTHONDONTWRITEBYTECODE=1 \
        python3 -m pytest -q -p no:cacheprovider -o junit_family=xunit1 \
        --junitxml="$RESULTS/unit.xml" 2>&1 | tee "$RESULTS/unit.log"
    rc=${PIPESTATUS[0]}
    set -e
    echo "exit=$rc" >>"$RESULTS/unit.log"
    ;;
netns)
    install_packages 1
    versions | tee "$RESULTS/versions.txt"
    # `unshare --map-auto` needs a subordinate range for the calling user (root here).
    # First in the file: util-linux 2.39's --map-auto (Ubuntu 24.04) takes the first range,
    # which there is the image's own "ubuntu" user's.
    for f in /etc/subuid /etc/subgid; do
        grep -q '^root:' "$f" 2>/dev/null || { echo 'root:200000:65536'; cat "$f" 2>/dev/null; } >"$f.new"
        [[ -f $f.new ]] && mv "$f.new" "$f"
    done
    # The suites play the 'blockads' daemon user with uid 1.
    getent passwd 1 >/dev/null || useradd --system --uid 1 --no-create-home --shell /usr/sbin/nologin uid1
    for name in interception offline_resolver storage_enospc fw_helper self_healing bridge gui_offline; do
        echo "::group::$name"
        set +e
        timeout 25m bash "tests/netns/$name.sh" 2>&1 | tee "$RESULTS/$name.log"
        rc=${PIPESTATUS[0]}
        set -e
        echo "exit=$rc" >>"$RESULTS/$name.log"
        echo "::endgroup::"
    done
    ;;
*)
    echo "container.sh: unknown suite $suite" >&2
    exit 2
    ;;
esac
# The verdict comes from tools/ci/report.py on the logs, so a failing suite
# never hides the others' results.
exit 0
