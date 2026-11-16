#!/usr/bin/env bash
# Install, upgrade, downgrade and remove the real packages in disposable VMs
# with systemd running (tests/vm/system_checks.sh pkg* sections, plus the
# ordinary start/api/faults checks on the packaged files).
#
# Usage: tests/vm/run_package.sh [IMAGE...]     (default: arch debian12)
#        KEEP=1 / REUSE=1 / SECTIONS=...         as for run_system.sh
# Logs: ${BLOCKADS_VM_DIR:-~/.cache/blockads-vm}/results/<image>-package.log
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export TAG=package
export SECTIONS=${SECTIONS:-pkgbuild pkginstall start api reboot pkgboot faults pkgupgrade pkgdowngrade pkgremove}
exec "$HERE/run_system.sh" "$@"
