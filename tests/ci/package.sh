#!/bin/bash
# Build, lint, install and remove the distribution package inside a distro
# container (no systemd running: the maintainer scripts must cope).
#
#   docker run --rm -v "$PWD:/src:ro" -v "$PWD/results:/results" debian:12 bash /src/tests/ci/package.sh
#
# Debian/Ubuntu: dpkg-buildpackage, lintian, apt install, purge.
# Arch: makepkg as an unprivileged user, namcap, pacman -U, pacman -Rns.
# Fedora has no package yet (make install covers it).
#
# Output: /results/package.log with PASS/FAIL/INFO lines (tools/ci/report.py),
# the built package in /results/.
set -uo pipefail
RESULTS=${RESULTS:-/results}
mkdir -p "$RESULTS"; chmod 0777 "$RESULTS"
trap 'chmod -R a+rX "$RESULTS"' EXIT
LOG=$RESULTS/package.log
. /etc/os-release
D="[$ID${VERSION_ID:+$VERSION_ID}]"; [[ $ID == arch ]] && D="[arch]"  # VERSION_ID there is a build date
report() { printf '%-5s %-62s %s\n' "$1" "$D $2" "${3:-}" | tee -a "$LOG"; }
ok() { local name=$1 detail=$2; shift 2; if "$@"; then report PASS "$name" "$detail"; else report FAIL "$name" "$detail"; fi; }
: >"$LOG"

# Work on a copy: the source mount stays read-only and clean.
WORK=/build/blockads-linux
mkdir -p /build
cp -a /src "$WORK"
rm -rf "$WORK/.git" "$WORK/results" "$WORK/.vm" "$WORK"/src/blockads_linux/gui/i18n/*.qm
find "$WORK" -name __pycache__ -prune -exec rm -rf {} +

installed_files() {  # the package's own files and links (not directories)
    case $ID in
    arch) pacman -Qlq blockads-linux | grep -v '/$' ;;
    # Not directories, nor links to them (dpkg lists /lib, a link to usr/lib on merged-/usr).
    *) dpkg -L blockads-linux | while read -r f; do [[ ( -f $f || -L $f ) && ! -d $f ]] && echo "$f"; done ;;
    esac
}

after_install_checks() {
    ok "blockadsctl --version" "$(blockadsctl --version 2>&1 | head -1)" bash -c 'blockadsctl --version | grep -q "Copyright (C) 2026 MateusBMP"'
    ok "blockads-fw --version (root helper)" "" bash -c '/usr/lib/blockads-linux/blockads-fw --version | grep -q "NO WARRANTY"'
    ok "the daemon user exists" "$(id blockads 2>&1)" id blockads
    ok "/etc/blockads-linux/firewall.conf" "$(stat -c '%U %a' /etc/blockads-linux/firewall.conf 2>&1)" \
        test "$(stat -c '%U %a' /etc/blockads-linux/firewall.conf 2>/dev/null)" = "root 644"
    ok "the daemon modules import (installed python)" "" \
        python3 -I -c 'import sys; sys.path.insert(0, "/usr/lib/blockads-linux/python"); import blockads_linux.daemon.__main__, blockads_linux.updater.__main__, blockads_linux.ctl.cli'
    ok "byte code compiled" "$(find /usr/lib/blockads-linux/python -name '*.pyc' | wc -l) files" \
        bash -c '[ "$(find /usr/lib/blockads-linux/python -name "*.pyc" | wc -l)" -gt 50 ]'
    ok "translations shipped" "" test -f /usr/lib/blockads-linux/python/blockads_linux/gui/i18n/blockads_pt_BR.qm
    local unitdir; unitdir=$(dirname "$(installed_files | grep -m1 '/blockadsd.service$')")
    ok "systemd units installed" "$unitdir" test -f "$unitdir/blockadsd.socket" -a -f "$unitdir/blockads-failsafe.service"
    ok "nothing enabled" "" bash -c '! ls /etc/systemd/system/*/blockads* >/dev/null 2>&1'
}

case $ID in
debian|ubuntu)
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends build-essential devscripts equivs lintian >/dev/null
    cp -a "$WORK/packaging/debian" "$WORK/debian"
    (cd "$WORK" && mk-build-deps -i -r -t 'apt-get -y -qq --no-install-recommends' debian/control >/dev/null 2>&1)
    out=$(cd "$WORK" && dpkg-buildpackage -us -uc -b 2>&1); rc=$?
    echo "$out" >"$RESULTS/build.log"
    ok "dpkg-buildpackage" "$(tail -1 <<<"$out")" test $rc -eq 0
    deb=$(ls /build/blockads-linux_*_all.deb 2>/dev/null | head -1)
    [[ -n $deb ]] || { report FAIL "package built" "see build.log"; exit 0; }
    cp "$deb" "$RESULTS/"
    info=$(dpkg-deb -I "$deb" | grep -E '^ (Version|Depends):' | tr -s ' ' | tr '\n' ';')
    report INFO "package" "$(basename "$deb"); $info"
    lint=$(lintian --tag-display-limit 0 "$deb" 2>&1); echo "$lint" >"$RESULTS/lintian.log"
    ok "lintian: no errors" "$(grep -c '^E:' <<<"$lint") E, $(grep -c '^W:' <<<"$lint") W" bash -c "! grep -q '^E:' '$RESULTS/lintian.log'"
    grep -E '^(E|W):' <<<"$lint" | head -15 | while IFS= read -r l; do report INFO "lintian" "$l"; done
    out=$(apt-get install -y -qq --no-install-recommends "$deb" 2>&1); rc=$?
    ok "apt install" "$(tail -1 <<<"$out")" test $rc -eq 0
    files=$(installed_files)
    after_install_checks
    out=$(apt-get purge -y -qq blockads-linux 2>&1); rc=$?
    ok "apt purge" "$(tail -1 <<<"$out")" test $rc -eq 0
    ;;
arch)
    pacman -Syu --noconfirm --needed --noprogressbar base-devel namcap python python-dnspython python-httpx \
        python-h2 python-jeepney iptables polkit qt6-tools >/dev/null 2>&1
    id builder >/dev/null 2>&1 || useradd -m builder
    chown -R builder: /build
    out=$(cd "$WORK" && su builder -c 'make arch-pkg MAKEPKG_FLAGS="--noconfirm --nodeps"' 2>&1); rc=$?
    echo "$out" >"$RESULTS/build.log"
    ok "makepkg" "$(tail -1 <<<"$out")" test $rc -eq 0
    pkg=$(ls "$WORK"/packaging/arch/blockads-linux-*.pkg.tar.* 2>/dev/null | head -1)
    [[ -n $pkg ]] || { report FAIL "package built" "see build.log"; exit 0; }
    cp "$pkg" "$RESULTS/"
    report INFO "package" "$(basename "$pkg")"
    lint=$(namcap "$WORK/packaging/arch/PKGBUILD" "$pkg" 2>&1); echo "$lint" >"$RESULTS/namcap.log"
    ok "namcap: no errors" "$(grep -c ' E: ' <<<"$lint") E, $(grep -c ' W: ' <<<"$lint") W" bash -c "! grep -q ' E: ' '$RESULTS/namcap.log'"
    grep -E ' (E|W): ' <<<"$lint" | head -15 | while IFS= read -r l; do report INFO "namcap" "$l"; done
    out=$(pacman -U --noconfirm --noprogressbar "$pkg" 2>&1); rc=$?
    ok "pacman -U" "$(tail -1 <<<"$out")" test $rc -eq 0
    files=$(installed_files)
    after_install_checks
    out=$(pacman -Rns --noconfirm blockads-linux 2>&1); rc=$?
    ok "pacman -Rns" "$(tail -1 <<<"$out")" test $rc -eq 0
    ;;
*)
    report SKIP "package" "no package for $ID (use make install)"; exit 0 ;;
esac

left=$(while IFS= read -r f; do [[ -n $f && ( -e $f || -L $f ) ]] && echo "$f"; done <<<"$files")
ok "removal leaves none of the package's files" "${left:-none}" test -z "$left"
ok "removal leaves no /usr/lib/blockads-linux" "" test ! -e /usr/lib/blockads-linux
exit 0
