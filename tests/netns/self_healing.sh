#!/usr/bin/env bash
# The daemon's self-healing against the real helper and real iptables,
# inside a throwaway user + network + mount namespace (never the host firewall).
#
#   uid 0  root: binds port 153 and hands the fds over (systemd's part), runs blockads-fw
#   uid 1  the 'blockads' daemon user: runs the real daemon via the real launcher
#   uid 2  an ordinary user
#
# Checks: socket activation (dns-v4/dns-v6 fds, READY=1), WATCHDOG=1 pings that
# stop while the daemon is SIGSTOPped, the interception probe passing while the
# rules are in place (the daemon's own probe to port 9 is redirected even though
# its other traffic is exempt), and exit status 75 after the rules are flushed:
# `iptables -t nat -F`, `ip6tables -t nat -F` and `nft flush ruleset`.
#
# Usage: tests/netns/self_healing.sh      (exit status 0 = all expectations met)
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
# The code must be readable by uid 1, which cannot enter the user's home.
cp -r "$ROOT/src/blockads_linux" /run/python/
find /run/python -name __pycache__ -prune -exec rm -rf {} +
chmod -R a+rX /run/python
sed 's#/usr/lib/blockads-linux/python#/run/python#' "$ROOT/data/launchers/blockadsd" >/run/blockadsd
chmod 755 /run/blockadsd

report() {  # report STATUS NAME DETAIL
    printf '%-5s %-62s %s\n' "$1" "$2" "$3"
    [[ "$1" == FAIL ]] && FAILURES=$((FAILURES + 1))
    [[ "$1" == PASS ]] && PASSES=$((PASSES + 1))
    return 0
}
check() {  # check NAME COMMAND... (PASS when the command succeeds)
    local name=$1; shift
    local out; if out="$("$@" 2>&1)"; then report PASS "$name" ""; else report FAIL "$name" "$(echo "$out" | tail -3 | tr '\n' '|')"; fi
}
expect() {  # expect NAME EXPECTED_FIRST_WORD COMMAND...
    local name=$1 want=$2; shift 2
    local out; out="$("$@" 2>&1)"
    if [[ "${out%% *}" == "$want" ]]; then report PASS "$name" "$out"; else report FAIL "$name" "want $want, got: $out"; fi
}
as_uid() { local uid=$1; shift; setpriv --reuid="$uid" --regid="$uid" --clear-groups "$@"; }

FW_BIN_DIRS=""
fw() { FW_BIN_DIRS="$FW_BIN_DIRS" python3 -I /run/fw_run.py /run/blockads-fw-helper "$@"; }
state() { python3 -I -c "import json,sys; s=json.load(open('/run/blockads-fw/state.json')); print(eval(sys.argv[1], {'s': s}))" "$1"; }
printf 'port=153\n' >/run/etc/blockads-linux/firewall.conf

# --- network fixture ---------------------------------------------------------
ip link set lo up
ip link add d0 type dummy
ip addr add 10.9.9.1/24 dev d0
ip -6 addr add fd00:9::1/64 dev d0 nodad
ip link set d0 up
ip route add default dev d0
ip -6 route add default dev d0

trap 'kill $(jobs -p) 2>/dev/null' EXIT
python3 -I /run/sd_launch.py sink /run/notify.sock /run/notify.log &
for _ in $(seq 50); do grep -q SINK-READY /run/notify.log 2>/dev/null && break; sleep 0.1; done

DAEMON=""
start_daemon() {  # start the daemon as uid 1 with systemd-style fds; waits for READY=1
    : >/run/notify.log
    rm -rf /run/state /run/daemon.rc /run/daemon.pid; mkdir -p /run/state; chown 1:1 /run/state; chmod 700 /run/state
    {   # the exit status lands in /run/daemon.rc ($(...) subshells cannot `wait` for it)
        NOTIFY_SOCKET=/run/notify.sock WATCHDOG_USEC=1500000 BLOCKADS_STATE_DIR=/run/state \
            python3 -I /run/sd_launch.py launch --port 153 --uid 1 -- \
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
wait_exit() {  # wait_exit SECONDS: prints the daemon's exit status, or RUNNING
    local _
    for _ in $(seq $(($1 * 10))); do
        if [[ -s /run/daemon.rc ]]; then cat /run/daemon.rc; return; fi
        sleep 0.1
    done
    echo RUNNING
}
stop_daemon() { kill "$DAEMON" 2>/dev/null; wait_exit 10 >/dev/null; }
pings() { grep -c '^WATCHDOG=1' /run/notify.log; }
left() { for t in iptables ip6tables; do "$t-$1-save" 2>/dev/null; done | grep -c BLOCKADS_; }

usable() {
    "iptables-$1" -w 5 -t nat -S OUTPUT >/dev/null 2>&1 && "iptables-$1" -w 5 -t filter -S OUTPUT >/dev/null 2>&1
}

flush_case() {  # flush_case BACKEND NAME COMMAND...: apply, flush with COMMAND, expect exit 75
    local b=$1 name=$2; shift 2
    if ! start_daemon; then report FAIL "[$b] $name: daemon ready" "$(tail -3 /run/daemon.log | tr '\n' '|')"; stop_daemon; return; fi
    check "[$b] $name: apply --verify" fw apply --verify
    sleep 2.5  # a few probe rounds with the rules in place
    expect "[$b] $name: probes pass while applied" RUNNING wait_exit 0
    "$@"
    expect "[$b] $name: daemon exits 75" 75 wait_exit 15
    expect "[$b] $name: alert logged" 1 grep -c 'alert: DNS interception stopped working' /run/daemon.log
    fw revert >/dev/null 2>&1
    expect "[$b] $name: no BLOCKADS_ left" 0 left "$b"
    stop_daemon
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

    # Socket activation, interception and the watchdog.
    if start_daemon; then report PASS "[$b] daemon ready on systemd fds (READY=1)" ""
    else report FAIL "[$b] daemon ready on systemd fds (READY=1)" "$(tail -3 /run/daemon.log | tr '\n' '|')"; return; fi
    expect "[$b] daemon serves dns-v4 and dns-v6" 4 grep -c 'serving DNS on' /run/daemon.log
    check "[$b] apply --verify" fw apply --verify
    expect "[$b] state: ipv6 active" active state 's["families"]["ipv6"]["status"]'
    expect "[$b] user -> 192.0.2.1:53 answered by the daemon" OK as_uid 2 python3 -I /run/dnsprobe.py query 192.0.2.1 53
    expect "[$b] user -> [2001:db8::1]:53 tcp answered" OK as_uid 2 python3 -I /run/dnsprobe.py query --proto tcp 2001:db8::1 53
    sleep 2
    local before; before=$(pings)
    if (( before >= 2 )); then report PASS "[$b] WATCHDOG=1 pings" "$before"; else report FAIL "[$b] WATCHDOG=1 pings" "$before"; fi
    kill -STOP "$DAEMON"; sleep 0.3; before=$(pings); sleep 2
    expect "[$b] no pings while stopped (systemd would kill)" "$before" pings
    kill -CONT "$DAEMON"; sleep 1.5
    if (( $(pings) > before )); then report PASS "[$b] pings resume after SIGCONT" ""; else report FAIL "[$b] pings resume after SIGCONT" ""; fi
    expect "[$b] still running, no probe failure" 0 grep -c 'interception probe failed' /run/daemon.log
    kill -TERM "$DAEMON"
    expect "[$b] SIGTERM: exit 0" 0 wait_exit 10
    expect "[$b] STOPPING=1 sent" 1 grep -c '^STOPPING=1' /run/notify.log
    fw revert >/dev/null 2>&1

    # Rules flushed behind our back.
    flush_case "$b" "iptables -t nat -F" "iptables-$b" -w 5 -t nat -F
    flush_case "$b" "ip6tables -t nat -F" "ip6tables-$b" -w 5 -t nat -F
    if [[ "$b" == nft ]] && command -v nft >/dev/null; then
        flush_case "$b" "nft flush ruleset" nft flush ruleset
    fi
}

run_backend nft
run_backend legacy

echo "--- $PASSES passed, $FAILURES failed"
[[ $FAILURES -eq 0 ]]
