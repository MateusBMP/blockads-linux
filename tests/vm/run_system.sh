#!/usr/bin/env bash
# Run the system-integration checks (tests/vm/system_checks.sh) in disposable
# VMs, in parallel: the real units, bus policy and polkit files under systemd.
#
# Usage: tests/vm/run_system.sh [IMAGE...]           (default: arch debian12)
#        SECTIONS="install start" tests/vm/run_system.sh arch
#        KEEP=1 tests/vm/run_system.sh ...           leave the VMs running afterwards
#        REUSE=1 tests/vm/run_system.sh ...          use a kept VM: skip boot and provisioning
# Logs: ${BLOCKADS_VM_DIR:-~/.cache/blockads-vm}/results/<image>-system.log
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
VM="$HERE/vm.sh"
RES=${BLOCKADS_VM_DIR:-$HOME/.cache/blockads-vm}/results
# "reboot" is done here: system_checks.sh runs the sections before it, then the VM
# reboots, then the rest runs (put prereboot before it and afterboot after it).
SECTIONS=${SECTIONS:-install start api polkit faults coexist porttaken bridge libvirt zones resolveddot clock suspend captive wireguard networks prereboot reboot afterboot noipv6set reboot noipv6 gui stop uninstall}
mkdir -p "$RES"
images=("$@"); [[ ${#images[@]} -eq 0 ]] && images=(arch debian12)

run_one() {
    local img=$1 name=$1-system log=$RES/$1-system.log
    {
        local fresh=1
        if [[ ${REUSE:-} ]] && "$VM" ssh "$name" 'pkill -f "[m]5_checks.sh"; true' 2>/dev/null; then fresh=""
        else "$VM" up "$img" "$name" || return 1; fi
        tar -C "$ROOT" --exclude=.git --exclude='__pycache__' --exclude='*.part' -cf - src tests tools helper data pyproject.toml LICENSE NOTICE \
            | "$VM" ssh "$name" 'rm -rf /opt/blockads && mkdir -p /opt/blockads && tar -C /opt/blockads -xf - && chmod -R a+rX /opt/blockads'
        [[ -z $fresh ]] || "$VM" ssh "$name" 'bash /opt/blockads/tests/vm/provision.sh' || echo "FAIL provision"
        local total=0 i rc
        local -a parts; IFS='|' read -ra parts <<<"${SECTIONS// reboot /|}"
        for i in "${!parts[@]}"; do
            if (( i > 0 )); then
                echo "--- reboot"
                "$VM" ssh "$name" 'systemctl reboot' 2>/dev/null; sleep 10
                "$VM" wait "$name" || { echo "FAIL [$img] reboot: no SSH"; total=$((total + 1)); break; }
            fi
            "$VM" ssh "$name" "bash /opt/blockads/tests/vm/system_checks.sh ${parts[i]}"; rc=$?
            total=$((total + rc))
        done
        echo "exit=$total"
    } >"$log" 2>&1
    [[ ${KEEP:-} ]] || "$VM" down "$name"
}

for img in "${images[@]}"; do run_one "$img" & done
wait
for img in "${images[@]}"; do
    echo "== $img: $(grep -c '^PASS' "$RES/$img-system.log") pass, $(grep -c '^FAIL' "$RES/$img-system.log") fail," \
         "$(grep -a '^exit=' "$RES/$img-system.log" | tail -1 || true) ($RES/$img-system.log)"
done
