#!/usr/bin/env bash
# Live install and uninstall for `make install` / `make uninstall` (no package
# manager). Run by the Makefile as root.
#
#   manifest.sh install STAGE    copy the staged tree STAGE into /, recording every
#                                path; an upgrade replaces the previous install
#   manifest.sh uninstall        stop the units, revert the firewall, remove exactly
#                                the recorded paths
#
# Install is all-or-nothing for the files: before anything is copied it refuses
# paths that another package or the admin owns; if a copy or the system steps
# after it fail, the files are put back as they were (the previous version on an
# upgrade, nothing on a first install). A changed /etc/blockads-linux/firewall.conf
# is never overwritten. Nothing is enabled or started; an upgrade restarts a
# running service.
set -Eeuo pipefail   # -E: the rollback trap also fires inside functions
umask 022

NAME=blockads-linux
MANIFEST=/var/lib/$NAME-install.manifest
LIB=/usr/lib/$NAME
CONF=/etc/$NAME/firewall.conf
UNITS=(blockadsd.socket blockadsd-ipv6.socket blockadsd-bridge.socket blockadsd.service
       blockads-update.service blockads-update.timer blockads-update.path blockads-failsafe.service)

log() { echo "manifest.sh: $*" >&2; }
die() { log "$*"; exit 1; }
[[ $(id -u) -eq 0 ]] || die "run as root"

reload_bus() {
    busctl --system call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus ReloadConfig \
        >/dev/null 2>&1 || systemctl reload dbus 2>/dev/null || true
}
systemd_running() { [[ -d /run/systemd/system ]]; }

# Owned by a package? (dpkg, pacman or rpm, whichever exists)
packaged() {
    { command -v dpkg >/dev/null && dpkg -S "$1" >/dev/null 2>&1; } ||
    { command -v pacman >/dev/null && pacman -Qoq "$1" >/dev/null 2>&1; } ||
    { command -v rpm >/dev/null && rpm -qf "$1" >/dev/null 2>&1; }
}

selinux_label() {
    command -v selinuxenabled >/dev/null && selinuxenabled || return 0
    # A lib_t executable started by systemd stays in init_t, which may not open TCP to 443
    # (DoH), 153 or 9 (probe); bin_t gives unconfined_service_t, as for any third-party service.
    local spec="$LIB/(blockadsd|blockads-update|blockads-fw|blockads-fw-emergency\\.sh)"
    if command -v semanage >/dev/null; then
        semanage fcontext -a -t bin_t "$spec" 2>/dev/null || semanage fcontext -m -t bin_t "$spec"
        restorecon -F "$LIB"/blockadsd "$LIB"/blockads-update "$LIB"/blockads-fw "$LIB"/blockads-fw-emergency.sh
    else
        chcon -t bin_t "$LIB"/blockadsd "$LIB"/blockads-update "$LIB"/blockads-fw "$LIB"/blockads-fw-emergency.sh
    fi
}

saved_ruleset_warning() {
    local f
    for f in /etc/iptables/rules.v4 /etc/iptables/rules.v6 /etc/iptables/iptables.rules \
             /etc/iptables/ip6tables.rules /etc/sysconfig/iptables /etc/sysconfig/ip6tables; do
        [[ -f $f ]] && grep -q BLOCKADS_ "$f" 2>/dev/null &&
            log "warning: $f contains BLOCKADS_ rules saved while protection was on; remove them"
    done
    return 0
}

stop_and_revert() {
    systemd_running || return 0
    # Never name blockadsd-ipv6.socket in a stop job: on an ipv6.disable=1 boot it is not
    # loadable and systemd rejects the whole job. It is PartOf blockadsd.socket.
    systemctl disable "${UNITS[@]}" >/dev/null 2>&1 || true
    systemctl stop blockadsd.socket blockadsd.service blockads-update.timer blockads-update.path \
        blockads-update.service >/dev/null 2>&1 || true
    [[ -x $LIB/blockads-fw ]] && "$LIB/blockads-fw" revert --all-backends >/dev/null 2>&1 || true
    [[ -f /run/blockads-fw/emergency.sh ]] && sh /run/blockads-fw/emergency.sh >/dev/null 2>&1 || true
}

cmd_install() {
    local stage=${1:?usage: manifest.sh install STAGE}
    [[ -f $stage$LIB/blockads-fw ]] || die "$stage is not a staged tree (make install-files DESTDIR=...)"
    stage=$(cd "$stage" && pwd)

    local -A old=()
    local p
    if [[ -f $MANIFEST ]]; then
        while IFS= read -r p; do [[ -n $p ]] && old[$p]=1; done <"$MANIFEST"
    fi

    # The new set: files and the directories they need (directories end in /).
    local -a files=() dirs=()
    while IFS= read -r p; do files+=("${p#.}"); done < <(cd "$stage" && find . \( -type f -o -type l \) | sort)
    while IFS= read -r p; do dirs+=("${p#.}/"); done < <(cd "$stage" && find . -mindepth 1 -type d | sort)

    # 1. Refuse before touching anything: a path we did not install that exists already.
    local conflicts=()
    for p in "${files[@]}"; do
        [[ $p == "$CONF" ]] && continue
        if [[ -e $p || -L $p ]] && [[ -z ${old[$p]:-} ]]; then conflicts+=("$p"); fi
    done
    if ((${#conflicts[@]})); then
        local c; for c in "${conflicts[@]:0:10}"; do
            if packaged "$c"; then log "conflict: $c belongs to a package (remove that package first)"
            else log "conflict: $c exists and was not installed by make install"; fi
        done
        die "nothing was changed"
    fi

    # 2. Copy, keeping what is replaced, so that a failure can put it back.
    local backup; backup=$(mktemp -d /var/tmp/$NAME-backup.XXXXXX)
    local -a created_files=() created_dirs=() replaced=()
    local new_manifest; new_manifest=$(mktemp "$MANIFEST.new.XXXXXX")
    rollback() {
        log "failed; rolling back"
        local f
        for f in "${replaced[@]}"; do cp -a "$backup$f" "$f" 2>/dev/null || log "could not restore $f"; done
        for f in "${created_files[@]}"; do rm -f -- "$f"; done
        local i; for ((i = ${#created_dirs[@]} - 1; i >= 0; i--)); do rmdir -- "${created_dirs[$i]}" 2>/dev/null || true; done
        rm -rf "$backup" "$new_manifest"
        systemd_running && systemctl daemon-reload 2>/dev/null || true
        exit 1
    }
    trap rollback ERR INT TERM

    for p in "${dirs[@]}"; do
        local d=${p%/}
        if [[ ! -d $d ]]; then
            mkdir -m 0755 "$d"
            created_dirs+=("$d")
            echo "$p" >>"$new_manifest"
        elif [[ -n ${old[$p]:-} ]]; then
            echo "$p" >>"$new_manifest"   # ours from before: still ours
        fi
    done
    for p in "${files[@]}"; do
        if [[ $p == "$CONF" && -e $p && -z ${old[$p]:-} ]]; then
            continue  # the admin's own firewall.conf, not ours to record or replace
        fi
        if [[ $p == "$CONF" && -e $p ]] && ! cmp -s "$p" "$stage$p"; then
            echo "$p" >>"$new_manifest"   # changed by the admin: kept as is
            cp -a "$stage$p" "$p.new"; log "kept the changed $p; the new default is $p.new"
            continue
        fi
        if [[ -e $p || -L $p ]]; then
            mkdir -p "$backup$(dirname "$p")"; cp -a "$p" "$backup$p"; replaced+=("$p")
        else
            created_files+=("$p")
        fi
        # Write next to the target, then rename: a running service never sees half a file.
        cp -a "$stage$p" "$p.$NAME-tmp"
        chown -h root:root "$p.$NAME-tmp"
        mv -f "$p.$NAME-tmp" "$p"
        echo "$p" >>"$new_manifest"
    done
    # The byte code the launchers compile on a later Python goes away with us too.
    echo "$LIB/" >>"$new_manifest"

    # 3. System steps; a failure here rolls the files back as well.
    selinux_label
    local conf
    conf=$(grep -m1 "/sysusers.d/$NAME.conf\$" "$new_manifest")
    systemd-sysusers "$conf"
    conf=$(grep -m1 "/tmpfiles.d/$NAME.conf\$" "$new_manifest")
    systemd-tmpfiles --create "$conf"
    if systemd_running; then systemctl daemon-reload; fi
    trap - ERR INT TERM

    # 4. Committed: drop what the previous version had and this one has not.
    local -A now=()
    while IFS= read -r p; do now[$p]=1; done <"$new_manifest"
    for p in "${!old[@]}"; do
        [[ -n ${now[$p]:-} || $p == */ ]] && continue
        rm -f -- "$p"
    done
    for p in $(printf '%s\n' "${!old[@]}" | grep '/$' | sort -r); do
        [[ -n ${now[$p]:-} ]] || rmdir -- "${p%/}" 2>/dev/null || true
    done
    sort -u "$new_manifest" >"$MANIFEST.tmp" && mv -f "$MANIFEST.tmp" "$MANIFEST"
    rm -f "$new_manifest"; rm -rf "$backup"
    chmod 0644 "$MANIFEST"
    reload_bus
    if systemd_running && systemctl -q is-active blockadsd.service; then
        systemctl try-restart blockadsd.service
        log "restarted the running blockadsd.service"
    fi
    echo "installed $NAME ($(grep -vc '/$' "$MANIFEST") files; manifest $MANIFEST)"
    if ! { systemd_running && systemctl -q is-enabled blockadsd.service 2>/dev/null; }; then
        echo "To turn protection on (and keep it on after a reboot):"
        echo "  systemctl enable --now blockadsd.service blockads-update.timer blockads-update.path"
    fi
}

cmd_uninstall() {
    [[ -f $MANIFEST ]] || die "no $MANIFEST: nothing installed by make install"
    stop_and_revert
    local p
    # Files first, then directories deepest first; a directory that is not empty stays.
    while IFS= read -r p; do
        [[ -n $p && $p != */ ]] && rm -f -- "$p"
    done <"$MANIFEST"
    rm -f "$CONF.new"
    find "$LIB" -name __pycache__ -type d -prune -exec rm -rf {} + 2>/dev/null || true
    for p in $(grep '/$' "$MANIFEST" | sort -r); do rmdir -- "${p%/}" 2>/dev/null || true; done
    if command -v selinuxenabled >/dev/null && selinuxenabled && command -v semanage >/dev/null; then
        semanage fcontext -d "$LIB/(blockadsd|blockads-update|blockads-fw|blockads-fw-emergency\\.sh)" 2>/dev/null || true
    fi
    rm -f "$MANIFEST"
    rm -rf /run/blockads-fw
    if systemd_running; then
        systemctl daemon-reload
        systemctl reset-failed "${UNITS[@]}" >/dev/null 2>&1 || true
    fi
    reload_bus
    saved_ruleset_warning
    echo "uninstalled $NAME (settings and logs kept in /var/lib/$NAME; the blockads user is kept)"
}

case ${1:-} in
    install) shift; cmd_install "$@" ;;
    uninstall) cmd_uninstall ;;
    *) sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 2 ;;
esac
