#!/usr/bin/env bash
# Run the platform checks (tests/vm/platform_checks.sh) in disposable VMs, in parallel.
#
# Usage: tests/vm/run_platform.sh [IMAGE...]     (default: the whole matrix below)
#        KEEP=1 tests/vm/run_platform.sh ...     leave the VMs running afterwards
# Logs: ${BLOCKADS_VM_DIR:-~/.cache/blockads-vm}/results/<image>.log
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
VM="$HERE/vm.sh"
RES=${BLOCKADS_VM_DIR:-$HOME/.cache/blockads-vm}/results
mkdir -p "$RES"

. "$HERE/platform_sections.sh"
images=("$@"); [[ ${#images[@]} -eq 0 ]] && images=(debian12 debian13 ubuntu2404 fedora44)

run_one() {
    local img=$1 log=$RES/$1.log
    {
        "$VM" up "$img" || return 1
        tar -C "$ROOT" --exclude=.git --exclude='__pycache__' --exclude='*.part' -cf - src tests tools helper data packaging Makefile pyproject.toml LICENSE NOTICE \
            | "$VM" ssh "$img" 'rm -rf /opt/blockads && mkdir -p /opt/blockads && tar -C /opt/blockads -xf - && chmod -R a+rX /opt/blockads'
        "$VM" ssh "$img" 'bash /opt/blockads/tests/vm/provision.sh' || echo "FAIL provision"
        "$VM" ssh "$img" "bash /opt/blockads/tests/vm/platform_checks.sh $(platform_sections "$img")"
        echo "exit=$?"
    } >"$log" 2>&1
    [[ ${KEEP:-} ]] || "$VM" down "$img"
}

for img in "${images[@]}"; do run_one "$img" & done
wait
for img in "${images[@]}"; do
    echo "== $img: $(grep -c '^PASS' "$RES/$img.log") pass, $(grep -c '^FAIL' "$RES/$img.log") fail," \
         "$(grep -a '^exit=' "$RES/$img.log" | tail -1 || true) ($RES/$img.log)"
done
