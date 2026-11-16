#!/usr/bin/env bash
# Disposable qemu/KVM VMs for the tests that cannot run rootless on the host
#.
#
# Each VM is a copy-on-write overlay on a pristine cloud image, provisioned by
# cloud-init (NoCloud seed served from a qemu vvfat drive labelled "cidata"),
# and driven over SSH as root. Destroying a VM deletes its overlay; the base
# image is never written.
#
# Usage:
#   tests/vm/vm.sh fetch [IMAGE...]        download base images (default: all)
#   tests/vm/vm.sh up IMAGE [NAME]         boot NAME (default IMAGE) and wait for SSH
#   tests/vm/vm.sh ssh NAME [CMD...]       run a command as root (or a shell)
#   tests/vm/vm.sh wait NAME               wait for SSH again (after a reboot)
#   tests/vm/vm.sh push NAME SRC... DEST   copy files into the VM (scp -r)
#   tests/vm/vm.sh down NAME               power off and delete the overlay
#   tests/vm/vm.sh list
#
# IMAGE is one of: debian12 debian13 ubuntu2404 ubuntu2604 fedora44 arch
# State lives in ${BLOCKADS_VM_DIR:-~/.cache/blockads-vm}.
set -euo pipefail

VM_DIR=${BLOCKADS_VM_DIR:-$HOME/.cache/blockads-vm}
IMG_DIR=$VM_DIR/images
RUN_DIR=$VM_DIR/run
KEY=$VM_DIR/id_ed25519
MEM=${VM_MEM:-2048}
CPUS=${VM_CPUS:-2}

declare -A URLS=(
    [debian12]=https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-amd64.qcow2
    [debian13]=https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2
    [ubuntu2404]=https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img
    [ubuntu2604]=https://cloud-images.ubuntu.com/resolute/current/resolute-server-cloudimg-amd64.img
    [fedora44]=https://download.fedoraproject.org/pub/fedora/linux/releases/44/Cloud/x86_64/images/Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2
    [arch]=https://geo.mirror.pkgbuild.com/images/latest/Arch-Linux-x86_64-cloudimg.qcow2
)

die() { echo "vm.sh: $*" >&2; exit 1; }
SSH_OPTS=(-i "$KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
          -o LogLevel=ERROR -o ConnectTimeout=5 -o BatchMode=yes)

port_of() { cat "$RUN_DIR/$1/port" 2>/dev/null || die "no VM named $1"; }

cmd_fetch() {
    mkdir -p "$IMG_DIR"
    local names=("$@"); [[ ${#names[@]} -eq 0 ]] && names=("${!URLS[@]}")
    for n in "${names[@]}"; do
        [[ -n ${URLS[$n]:-} ]] || die "unknown image $n"
        [[ -s $IMG_DIR/$n.qcow2 ]] && continue
        curl -fSL -o "$IMG_DIR/$n.qcow2.part" "${URLS[$n]}"
        mv "$IMG_DIR/$n.qcow2.part" "$IMG_DIR/$n.qcow2"
    done
}

cmd_up() {
    local image=$1 name=${2:-$1} d=$RUN_DIR/${2:-$1}
    [[ -s $IMG_DIR/$image.qcow2 ]] || cmd_fetch "$image"
    [[ -e $d/pid ]] && kill -0 "$(cat "$d/pid")" 2>/dev/null && die "$name is already running"
    [[ -s $KEY ]] || ssh-keygen -q -t ed25519 -N '' -f "$KEY"
    rm -rf "$d"; mkdir -p "$d/seed"

    qemu-img create -q -f qcow2 -b "$IMG_DIR/$image.qcow2" -F qcow2 "$d/disk.qcow2" 16G
    cat >"$d/seed/meta-data" <<EOF
instance-id: $name-$(date +%s)
local-hostname: $name
EOF
    cat >"$d/seed/user-data" <<EOF
#cloud-config
disable_root: false
ssh_pwauth: false
users:
  - name: root
    lock_passwd: true
    ssh_authorized_keys:
      - $(cat "$KEY.pub")
EOF
    # S3 is enabled (-global ICH9-LPC.disable_s3=0) for the suspend/resume check (rtcwake).
    # Matched by MAC: Arch's networkd renderer left eth0 down with a name glob.
    local MAC=52:54:00:12:34:56
    # Static IPv4 on slirp's fixed plan. Guest IPv6 stays off: with qemu 11.1 +
    # libslirp 4.9.5, ipv6=on broke all guest IPv4 (no DHCP, no ping to 10.0.2.2).
    cat >"$d/seed/network-config" <<EOF
version: 2
ethernets:
  nic0:
    match: {macaddress: "$MAC"}
    addresses: [10.0.2.15/24]
    routes: [{to: default, via: 10.0.2.2}]
    nameservers: {addresses: [10.0.2.3]}
    dhcp6: false
EOF

    # A free host port for SSH forwarding.
    local port
    port=$(python3 -I -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
    echo "$port" >"$d/port"; echo "$image" >"$d/image"

    qemu-system-x86_64 -machine q35,accel=kvm -cpu host -m "$MEM" -smp "$CPUS" \
        -name "$name" -display none -daemonize -pidfile "$d/pid" \
        -serial "file:$d/console.log" \
        -drive "if=virtio,file=$d/disk.qcow2,format=qcow2,discard=unmap" \
        -drive "if=virtio,driver=vvfat,dir=$d/seed,label=cidata,read-only=on" \
        -netdev "user,id=n0,ipv6=off,hostfwd=tcp:127.0.0.1:$port-:22" \
        -device "virtio-net-pci,netdev=n0,mac=$MAC" \
        -device virtio-rng-pci \
        -global ICH9-LPC.disable_s3=0

    cmd_wait "$name"
}

cmd_wait() {
    local name=$1 d=$RUN_DIR/$1 port; port=$(port_of "$1")
    local t
    for t in $(seq 180); do
        if ssh "${SSH_OPTS[@]}" -p "$port" root@127.0.0.1 \
               'cloud-init status --wait >/dev/null 2>&1; true' 2>/dev/null; then
            echo "$name up (ssh port $port)"; return 0
        fi
        kill -0 "$(cat "$d/pid")" 2>/dev/null || die "$name: qemu exited; see $d/console.log"
        sleep 2
    done
    die "$name: SSH did not come up; see $d/console.log"
}

cmd_ssh() {
    local name=$1; shift
    ssh "${SSH_OPTS[@]}" -p "$(port_of "$name")" root@127.0.0.1 "$@"
}

cmd_push() {
    local name=$1; shift
    local dest=${*: -1} srcs=("${@:1:$#-1}")
    scp -q -r "${SSH_OPTS[@]}" -P "$(port_of "$name")" "${srcs[@]}" "root@127.0.0.1:$dest"
}

cmd_down() {
    local d=$RUN_DIR/$1
    [[ -d $d ]] || return 0
    if [[ -e $d/pid ]]; then
        local pid; pid=$(cat "$d/pid")
        kill "$pid" 2>/dev/null || true
        for _ in $(seq 50); do kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
        kill -9 "$pid" 2>/dev/null || true
    fi
    rm -rf "$d"
}

cmd_list() {
    local d
    for d in "$RUN_DIR"/*/; do
        [[ -d $d ]] || continue
        local st=down; [[ -e $d/pid ]] && kill -0 "$(cat "$d/pid")" 2>/dev/null && st=up
        printf '%-14s %-11s %-5s port %s\n' "$(basename "$d")" "$(cat "$d/image")" "$st" "$(cat "$d/port")"
    done
}

sub=${1:-}; shift || true
case $sub in
    fetch|up|wait|ssh|push|down|list) "cmd_$sub" "$@" ;;
    *) sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 2 ;;
esac
