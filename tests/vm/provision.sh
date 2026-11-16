#!/usr/bin/env bash
# Install what the VM checks need, from the distribution's own packages
# (the point is to test the versions each distro ships). Runs as root in the VM.
set -euo pipefail
. /etc/os-release

case $ID in
debian|ubuntu)
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends \
        iptables nftables conntrack iproute2 util-linux uidmap \
        python3 python3-dnspython python3-httpx python3-h2 python3-jeepney \
        python3-pytest python3-cryptography kbd \
        network-manager polkitd dbus >/dev/null
    # polkit's JS rules engine lives in a separate package on Debian 13 / Ubuntu.
    apt-get install -y -qq --no-install-recommends pkexec >/dev/null 2>&1 || true
    ;;
fedora)
    dnf install -y -q iptables-nft iptables-legacy nftables conntrack-tools iproute \
        util-linux shadow-utils python3 python3-dns python3-httpx python3-h2 python3-jeepney \
        python3-pytest python3-cryptography kbd NetworkManager polkit firewalld >/dev/null
    ;;
arch)
    # --ignore linux: upgrading the kernel package deletes the RUNNING kernel's
    # modules, and modprobe (nat, legacy xtables, Docker) then fails until a reboot.
    pacman -Syu --noconfirm --needed --noprogressbar --ignore linux,linux-lts iptables nftables conntrack-tools iproute2 \
        util-linux shadow python python-dnspython python-httpx python-h2 python-jeepney \
        python-pytest python-cryptography kbd networkmanager polkit dbus >/dev/null
    ;;
*) echo "unsupported distro $ID" >&2; exit 1 ;;
esac

# Rootless-style harness used by interception.sh: give root a subordinate range.
grep -q '^root:' /etc/subuid || echo 'root:200000:65536' >>/etc/subuid
grep -q '^root:' /etc/subgid || echo 'root:200000:65536' >>/etc/subgid

# Legacy xtables modules cannot be auto-loaded from inside a user namespace.
for m in ip_tables iptable_nat iptable_filter ip6_tables ip6table_nat ip6table_filter; do
    modprobe "$m" 2>/dev/null || true
done

# The daemon's system user (normally created by sysusers.d).
id blockads >/dev/null 2>&1 || useradd --system --no-create-home --home-dir /nonexistent \
    --shell /usr/sbin/nologin blockads
# An ordinary desktop-like user for the polkit / NM checks.
id alice >/dev/null 2>&1 || useradd --create-home alice
echo provisioned
