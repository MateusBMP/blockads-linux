#!/usr/bin/env bash
# The opt-in bridge redirect end to end, inside throwaway user + network +
# mount namespaces (never the host firewall).
#
#   "host" netns:  the daemon (uid 1, real launcher, systemd-style fds incl. dns-bridge)
#                  and the real blockads-fw with bridge_interfaces=br-+
#   "ctr"  netns:  a container behind br-test0 (172.30.0.2, fd30::2), whose
#                  resolver points at an outside address (192.0.2.53, 2001:db8::53)
#   "lan"  netns:  a LAN host behind lan0 (10.40.0.2), not a bridge
#
# Checks: the container's queries to an outside resolver are redirected and
# answered by the daemon (UDP/TCP, IPv4/IPv6); direct queries to port 154 are
# dropped by BLOCKADS_IN (ctstate DNAT) from the container, the LAN and
# loopback; with BLOCKADS_IN removed, the daemon's source ACL alone still
# ignores the LAN and loopback but answers the container; the watchdog keeps
# probing only the loopback listeners; no BLOCKADS_ left after revert.
#
# Usage: tests/netns/bridge.sh      (exit status 0 = all expectations met)
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
if [[ "${1:-}" != "--inner" ]]; then
    exec unshare --map-auto --map-root-user --net --mount --propagation private \
        -- bash "${BASH_SOURCE[0]}" --inner
fi

FAILURES=0
PASSES=0
mount -t tmpfs -o mode=755 tmpfs /run
install -m 644 "$HERE/dnsprobe.py" /run/dnsprobe.py
install -m 644 "$HERE/sd_launch.py" /run/sd_launch.py
install -m 644 "$HERE/fw_run.py" /run/fw_run.py
install -m 755 "$ROOT/helper/blockads-fw" /run/blockads-fw-helper
mkdir -p /run/etc/blockads-linux /run/python
cp -r "$ROOT/src/blockads_linux" /run/python/
find /run/python -name __pycache__ -prune -exec rm -rf {} +
chmod -R a+rX /run/python
sed 's#/usr/lib/blockads-linux/python#/run/python#' "$ROOT/data/launchers/blockadsd" >/run/blockadsd
chmod 755 /run/blockadsd

report() {  # report STATUS NAME DETAIL
    printf '%-5s %-66s %s\n' "$1" "$2" "$3"
    [[ "$1" == FAIL ]] && FAILURES=$((FAILURES + 1))
    [[ "$1" == PASS ]] && PASSES=$((PASSES + 1))
    return 0
}
check() {
    local name=$1; shift
    local out; if out="$("$@" 2>&1)"; then report PASS "$name" ""; else report FAIL "$name" "$(echo "$out" | tail -3 | tr '\n' '|')"; fi
}
expect() {  # expect NAME EXPECTED_FIRST_WORD COMMAND...
    local name=$1 want=$2; shift 2
    local out; out="$("$@" 2>&1)"
    if [[ "${out%% *}" == "$want" ]]; then report PASS "$name" "$out"; else report FAIL "$name" "want $want, got: $out"; fi
}

FW_BIN_DIRS=""
fw() { FW_BIN_DIRS="$FW_BIN_DIRS" python3 -I /run/fw_run.py /run/blockads-fw-helper "$@"; }
state() { python3 -I -c "import json,sys; s=json.load(open('/run/blockads-fw/state.json')); print(eval(sys.argv[1], {'s': s}))" "$1"; }
printf 'port=153\nbridge_interfaces=br-+\nbridge_port=154\n' >/run/etc/blockads-linux/firewall.conf

# --- network fixture ---------------------------------------------------------
trap 'kill $(jobs -p) 2>/dev/null' EXIT
ip link set lo up
ip link add d0 type dummy   # the host's uplink
ip addr add 10.9.9.1/24 dev d0
ip -6 addr add fd00:9::1/64 dev d0 nodad
ip link set d0 up
ip route add default dev d0
ip -6 route add default dev d0

# Child network namespaces, each held by a sleeper (started here, not in $(...),
# whose stdout the sleeper would keep open).
unshare --net sleep infinity </dev/null >/dev/null 2>&1 &
CTR=$!
unshare --net sleep infinity </dev/null >/dev/null 2>&1 &
LAN=$!
sleep 0.2
in_ctr() { nsenter -t "$CTR" -n "$@"; }
in_lan() { nsenter -t "$LAN" -n "$@"; }

ip link add br-test0 type veth peer name eth0 netns "$CTR"
ip addr add 172.30.0.1/24 dev br-test0
ip -6 addr add fd30::1/64 dev br-test0 nodad
ip link set br-test0 up
in_ctr ip link set lo up
in_ctr ip addr add 172.30.0.2/24 dev eth0
in_ctr ip -6 addr add fd30::2/64 dev eth0 nodad
in_ctr ip link set eth0 up
in_ctr ip route add default via 172.30.0.1
in_ctr ip -6 route add default via fd30::1

ip link add lan0 type veth peer name eth0 netns "$LAN"
ip addr add 10.40.0.1/24 dev lan0
ip link set lan0 up
in_lan ip link set lo up
in_lan ip addr add 10.40.0.2/24 dev eth0
in_lan ip link set eth0 up
in_lan ip route add default via 10.40.0.1

python3 -I /run/sd_launch.py sink /run/notify.sock /run/notify.log &
for _ in $(seq 50); do grep -q SINK-READY /run/notify.log 2>/dev/null && break; sleep 0.1; done

DAEMON=""
start_daemon() {
    : >/run/notify.log
    rm -rf /run/state /run/daemon.rc /run/daemon.pid; mkdir -p /run/state; chown 1:1 /run/state; chmod 700 /run/state
    {
        NOTIFY_SOCKET=/run/notify.sock WATCHDOG_USEC=1500000 BLOCKADS_STATE_DIR=/run/state \
            python3 -I /run/sd_launch.py launch --port 153 --bridge-port 154 --uid 1 -- \
            python3 -I /run/blockadsd --no-netmon --upstream udp://127.0.0.1:1 --fallback none --health-interval 1 \
            >/run/daemon.log 2>&1 &
        echo $! >/run/daemon.pid
        wait $!
        echo $? >/run/daemon.rc
    } &
    for _ in $(seq 50); do [[ -s /run/daemon.pid ]] && break; sleep 0.05; done
    DAEMON=$(cat /run/daemon.pid)
    for _ in $(seq 100); do grep -q '^READY=1' /run/notify.log && return 0; kill -0 "$DAEMON" 2>/dev/null || break; sleep 0.1; done
    return 1
}
wait_exit() {
    local _
    for _ in $(seq $(($1 * 10))); do
        if [[ -s /run/daemon.rc ]]; then cat /run/daemon.rc; return; fi
        sleep 0.1
    done
    echo RUNNING
}
pings() { grep -c '^WATCHDOG=1' /run/notify.log; }
left() { for t in iptables ip6tables; do "$t-$1-save" 2>/dev/null; done | grep -c BLOCKADS_; }
Q=(python3 -I /run/dnsprobe.py query --timeout 0.7)  # an array: nsenter cannot run shell functions
q() { "${Q[@]}" "$@"; }

usable() {
    "iptables-$1" -w 5 -t nat -S OUTPUT >/dev/null 2>&1 && "iptables-$1" -w 5 -t filter -S OUTPUT >/dev/null 2>&1
}

run_backend() {
    local b=$1
    echo "=== backend: $b ($(iptables-$b -V 2>&1)) ==="
    if ! usable "$b"; then
        report SKIP "[$b] backend usable in a user namespace" "$(iptables-$b -t nat -S OUTPUT 2>&1 | tail -1)"
        return
    fi
    mkdir -p "/run/bin-$b"
    for tool in iptables iptables-restore ip6tables ip6tables-restore; do
        ln -sf "$(command -v "${tool/tables/tables-$b}")" "/run/bin-$b/$tool"
    done
    FW_BIN_DIRS="/run/bin-$b"

    if start_daemon; then report PASS "[$b] daemon ready with dns-v4, dns-v6 and dns-bridge fds" ""
    else report FAIL "[$b] daemon ready with dns-v4, dns-v6 and dns-bridge fds" "$(tail -3 /run/daemon.log | tr '\n' '|')"; return; fi
    expect "[$b] daemon serves all six listeners" 8 grep -c 'serving DNS on' /run/daemon.log
    check "[$b] apply --verify (bridge on)" fw apply --verify
    expect "[$b] state: bridge v4 active" active state 's["bridge"]["families"]["ipv4"]["status"]'
    expect "[$b] state: bridge v6 active" active state 's["bridge"]["families"]["ipv6"]["status"]'
    sleep 2.2  # past the ACL's refresh interval: the new state.json is read on the next unknown source

    # Redirected queries from the container.
    expect "[$b] ctr -> 192.0.2.53:53 udp answered by the daemon" OK in_ctr "${Q[@]}" 192.0.2.53 53
    expect "[$b] ctr -> 192.0.2.53:53 tcp answered by the daemon" OK in_ctr "${Q[@]}" --proto tcp 192.0.2.53 53
    expect "[$b] ctr -> [2001:db8::53]:53 udp answered" OK in_ctr "${Q[@]}" 2001:db8::53 53
    expect "[$b] ctr -> [2001:db8::53]:53 tcp answered" OK in_ctr "${Q[@]}" --proto tcp 2001:db8::53 53
    # Layer 1: only redirected packets reach port 154.
    expect "[$b] ctr -> 172.30.0.1:154 direct: dropped" TIMEOUT in_ctr "${Q[@]}" 172.30.0.1 154
    expect "[$b] ctr -> 172.30.0.1:154 tcp direct: reset" REFUSED in_ctr "${Q[@]}" --proto tcp 172.30.0.1 154
    expect "[$b] lan -> 10.40.0.1:154 direct: dropped" TIMEOUT in_lan "${Q[@]}" 10.40.0.1 154
    expect "[$b] lan -> 192.0.2.53:53 not redirected (lan0 is no bridge)" TIMEOUT in_lan "${Q[@]}" 192.0.2.53 53

    # Layer 2: the daemon's source ACL alone.
    iptables-$b -w 5 -D INPUT -j BLOCKADS_IN && ip6tables-$b -w 5 -D INPUT -j BLOCKADS_IN
    expect "[$b] without BLOCKADS_IN: lan -> 10.40.0.1:154 ignored by the ACL" TIMEOUT in_lan "${Q[@]}" 10.40.0.1 154
    expect "[$b] without BLOCKADS_IN: lan tcp -> 10.40.0.1:154 closed" ERROR in_lan "${Q[@]}" --proto tcp 10.40.0.1 154
    expect "[$b] without BLOCKADS_IN: host -> 127.0.0.1:154 ignored" TIMEOUT q 127.0.0.1 154
    expect "[$b] without BLOCKADS_IN: ctr -> 172.30.0.1:154 answered" OK in_ctr "${Q[@]}" 172.30.0.1 154
    expect "[$b] without BLOCKADS_IN: ctr -> [fd30::1]:154 answered" OK in_ctr "${Q[@]}" fd30::1 154

    # The watchdog probes only loopback; the bridge listener never trips it.
    sleep 1
    if (( $(pings) >= 2 )); then report PASS "[$b] WATCHDOG=1 pings" "$(pings)"; else report FAIL "[$b] WATCHDOG=1 pings" "$(pings)"; fi
    expect "[$b] no probe failure" 0 grep -c 'probe failed' /run/daemon.log
    expect "[$b] daemon still running" RUNNING wait_exit 0

    kill -TERM "$DAEMON"
    expect "[$b] SIGTERM: exit 0" 0 wait_exit 10
    fw revert >/dev/null 2>&1
    expect "[$b] no BLOCKADS_ left after revert" 0 left "$b"
}

run_backend nft
run_backend legacy

echo "--- $PASSES passed, $FAILURES failed"
[[ $FAILURES -eq 0 ]]
