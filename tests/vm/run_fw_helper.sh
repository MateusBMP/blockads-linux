#!/usr/bin/env bash
# Run the firewall helper checks in disposable VMs (in parallel): the namespace test
# tests/netns/fw_helper.sh (real nft + legacy iptables, with the legacy modules
# preloaded by provision.sh) and the helper's unit tests on the distro Python.
#
# Usage: tests/vm/run_fw_helper.sh [IMAGE...]     (default: debian12 fedora44)
# Logs: ${BLOCKADS_VM_DIR:-~/.cache/blockads-vm}/results/fw_helper-<image>.log
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
VM="$HERE/vm.sh"
RES=${BLOCKADS_VM_DIR:-$HOME/.cache/blockads-vm}/results
mkdir -p "$RES"
images=("$@"); [[ ${#images[@]} -eq 0 ]] && images=(debian12 fedora44)

run_one() {
    local img=$1 log=$RES/fw_helper-$1.log
    {
        "$VM" up "$img" || return 1
        tar -C "$ROOT" --exclude=.git --exclude='__pycache__' -cf - src tests tools helper pyproject.toml \
            | "$VM" ssh "$img" 'rm -rf /opt/blockads && mkdir -p /opt/blockads && tar -C /opt/blockads -xf - && chmod -R a+rX /opt/blockads'
        "$VM" ssh "$img" 'bash /opt/blockads/tests/vm/provision.sh' || echo "FAIL provision"
        "$VM" ssh "$img" 'cd /opt/blockads && python3 -m pytest -q -p no:cacheprovider tests/unit/test_fw_helper.py 2>&1 | tail -3'
        "$VM" ssh "$img" 'bash /opt/blockads/tests/netns/fw_helper.sh'
        echo "exit=$?"
    } >"$log" 2>&1
    [[ ${KEEP:-} ]] || "$VM" down "$img"
}

for img in "${images[@]}"; do run_one "$img" & done
wait
for img in "${images[@]}"; do
    echo "== $img: $(grep -c '^PASS' "$RES/fw_helper-$img.log") pass, $(grep -c '^FAIL' "$RES/fw_helper-$img.log") fail," \
         "$(grep -c '^SKIP' "$RES/fw_helper-$img.log") skip; $(grep -E 'passed|failed' "$RES/fw_helper-$img.log" | head -1) ($RES/fw_helper-$img.log)"
done
