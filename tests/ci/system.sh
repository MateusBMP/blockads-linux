#!/bin/bash
# Run the system-integration suites (tests/vm/platform_checks.sh, then the
# sections of tests/vm/system_checks.sh except the reboot) on THIS machine,
# as root, the way tests/vm/run_platform.sh runs it inside a qemu VM. For CI runners
# whose OS is a supported target (GitHub's ubuntu-24.04): no VM needed.
#
#   sudo tests/ci/system.sh IMAGE LOG       e.g. sudo tests/ci/system.sh ubuntu2404 results/system.log
#
# WARNING: it changes the machine (packages, users, services, firewall rules
# while it runs). Only for disposable machines such as CI runners.
set -uo pipefail
image=${1:?usage: system.sh IMAGE LOG}
log=${2:?usage: system.sh IMAGE LOG}
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
[[ $(id -u) -eq 0 ]] || { echo "system.sh: run as root (disposable machines only)" >&2; exit 2; }
[[ -n ${CI:-} ]] || { echo "system.sh: refusing to run outside CI (set CI=1 on a disposable machine)" >&2; exit 2; }
. "$ROOT/tests/vm/platform_sections.sh"
sections=$(platform_sections "$image") || exit 2

mkdir -p "$(dirname "$log")"
{
    # platform_checks.sh expects the tree at /opt/blockads, readable by every user.
    rm -rf /opt/blockads && mkdir -p /opt/blockads
    tar -C "$ROOT" --exclude=.git --exclude='__pycache__' --exclude=results --exclude=.vm \
        -cf - src tests tools helper data pyproject.toml LICENSE NOTICE | tar -C /opt/blockads -xf -
    chmod -R a+rX /opt/blockads
    bash /opt/blockads/tests/vm/provision.sh || echo "FAIL provision"
    bash /opt/blockads/tests/vm/platform_checks.sh $sections
    echo "exit=$?"
    # The real units under this machine's systemd. No reboot, clock change
    # or suspend on a runner (they would break the runner itself).
    bash /opt/blockads/tests/vm/system_checks.sh install start api polkit faults coexist porttaken bridge libvirt zones resolveddot networks stop uninstall
    echo "exit=$?"
} 2>&1 | tee "$log"
# The verdict comes from tools/ci/report.py on the log.
exit 0
