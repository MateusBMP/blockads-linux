#!/usr/bin/env bash
# Install (or remove) blockads-linux from this source tree into the real system
# paths, the way a package would. For disposable VMs and CI runners only.
#
#   install.sh install [SRC]     default SRC: the tree this script lives in
#   install.sh uninstall         stop the units, revert the firewall, delete files
#
# install does not enable or start anything. Every installed path is recorded
# in /var/lib/blockads-linux-install.manifest so that uninstall removes exactly
# those (the state directory /var/lib/blockads-linux is kept, as on a package
# removal without purge).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFEST=/var/lib/blockads-linux-install.manifest
LIB=/usr/lib/blockads-linux
UNITS=(blockadsd.socket blockadsd-ipv6.socket blockadsd-bridge.socket blockadsd.service
       blockads-update.service blockads-update.timer blockads-update.path blockads-failsafe.service)

[[ $(id -u) -eq 0 ]] || { echo "install.sh: run as root" >&2; exit 2; }

put() {  # put MODE SRC DEST
    install -D -m "$1" -o root -g root "$2" "$3"
    echo "$3" >>"$MANIFEST"
}

reload_bus() {
    busctl --system call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus ReloadConfig \
        >/dev/null 2>&1 || systemctl reload dbus 2>/dev/null || true
}

cmd_install() {
    local src=${1:-$(cd "$HERE/../.." && pwd)}
    [[ -f $src/data/systemd/blockadsd.service ]] || { echo "install.sh: $src is not a source tree" >&2; exit 2; }
    [[ -e $MANIFEST ]] && cmd_uninstall
    : >"$MANIFEST"

    # Private code directory, root-owned, byte-compiled now (the sandbox's
    # ProtectSystem=strict would make a later write fail anyway).
    rm -rf "$LIB/python"
    mkdir -p "$LIB/python"
    (cd "$src/src" && find blockads_linux -name __pycache__ -prune -o -type f \( -name '*.py' -o -path '*/data/*' -o -path '*/i18n/*.qm' \) -print) |
        while read -r f; do put 0644 "$src/src/$f" "$LIB/python/$f"; done
    python3 -I -m compileall -q "$LIB/python/blockads_linux" >/dev/null
    find "$LIB/python" -name '*.pyc' >>"$MANIFEST"

    put 0755 "$src/data/launchers/blockadsd" "$LIB/blockadsd"
    put 0755 "$src/data/launchers/blockads-update" "$LIB/blockads-update"
    put 0755 "$src/helper/blockads-fw" "$LIB/blockads-fw"
    put 0755 "$src/helper/blockads-fw-emergency.sh" "$LIB/blockads-fw-emergency.sh"
    put 0755 "$src/data/launchers/blockadsctl" /usr/bin/blockadsctl
    put 0755 "$src/data/launchers/blockads" /usr/bin/blockads
    put 0644 "$src/data/applications/io.github.mateusbmp.blockads-linux.desktop" \
        /usr/share/applications/io.github.mateusbmp.blockads-linux.desktop
    put 0644 "$src/data/metainfo/io.github.mateusbmp.blockads-linux.metainfo.xml" \
        /usr/share/metainfo/io.github.mateusbmp.blockads-linux.metainfo.xml
    put 0644 "$src/data/icons/hicolor/scalable/apps/io.github.mateusbmp.blockads-linux.svg" \
        /usr/share/icons/hicolor/scalable/apps/io.github.mateusbmp.blockads-linux.svg

    local u
    for u in "${UNITS[@]}"; do put 0644 "$src/data/systemd/$u" "/usr/lib/systemd/system/$u"; done
    put 0644 "$src/data/sysusers.d/blockads-linux.conf" /usr/lib/sysusers.d/blockads-linux.conf
    put 0644 "$src/data/tmpfiles.d/blockads-linux.conf" /usr/lib/tmpfiles.d/blockads-linux.conf
    put 0644 "$src/data/dbus-1/system.d/io.github.mateusbmp.BlockAds1.conf" \
        /usr/share/dbus-1/system.d/io.github.mateusbmp.BlockAds1.conf
    put 0644 "$src/data/polkit-1/actions/io.github.mateusbmp.blockads.policy" \
        /usr/share/polkit-1/actions/io.github.mateusbmp.blockads.policy
    put 0644 "$src/data/polkit-1/rules.d/50-blockads-linux.rules" \
        /usr/share/polkit-1/rules.d/50-blockads-linux.rules
    # A config file: kept if the admin changed it.
    if [[ ! -e /etc/blockads-linux/firewall.conf ]]; then
        put 0644 "$src/data/firewall.conf" /etc/blockads-linux/firewall.conf
    fi

    # SELinux (Fedora): a lib_t executable started by systemd stays in init_t,
    # which may not open TCP to 443 (DoH), 153 or 9 (probe). bin_t, as for any
    # third-party service, gives unconfined_service_t. A package does this with
    # an fcontext rule (`semanage fcontext -a -t bin_t ...`).
    if command -v selinuxenabled >/dev/null && selinuxenabled; then
        chcon -t bin_t "$LIB/blockadsd" "$LIB/blockads-update" "$LIB/blockads-fw" "$LIB/blockads-fw-emergency.sh"
    fi
    systemd-sysusers /usr/lib/sysusers.d/blockads-linux.conf
    systemd-tmpfiles --create /usr/lib/tmpfiles.d/blockads-linux.conf
    systemctl daemon-reload
    reload_bus
    echo "installed ($(wc -l <"$MANIFEST") paths)"
}

cmd_uninstall() {
    if [[ -x $LIB/blockads-fw ]]; then
        # Never name blockadsd-ipv6.socket in a stop job: on an ipv6.disable=1 boot it is
        # not loadable and systemd 262 rejects the whole job. It is PartOf blockadsd.socket.
        systemctl disable "${UNITS[@]}" >/dev/null 2>&1 || true
        systemctl stop blockadsd.socket blockadsd.service blockads-update.timer blockads-update.path \
            blockads-update.service >/dev/null 2>&1 || true
        "$LIB/blockads-fw" revert --all-backends >/dev/null 2>&1 || true
    fi
    if [[ -e $MANIFEST ]]; then
        local f
        while read -r f; do [[ -n $f ]] && rm -f -- "$f"; done <"$MANIFEST"
        rm -f "$MANIFEST"
    fi
    rm -rf "$LIB" /run/blockads-fw
    rmdir /etc/blockads-linux 2>/dev/null || true
    systemctl daemon-reload
    systemctl reset-failed "${UNITS[@]}" >/dev/null 2>&1 || true
    reload_bus
    echo uninstalled
}

case ${1:-} in
    install) shift; cmd_install "$@" ;;
    uninstall) cmd_uninstall ;;
    *) sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 2 ;;
esac
