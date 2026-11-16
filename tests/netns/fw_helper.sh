#!/usr/bin/env bash
# The real helper/blockads-fw and blockads-fw-emergency.sh against real
# iptables (nft and legacy), inside a throwaway user + network + mount
# namespace. It can never modify the host firewall.
#
#   uid 0  root (blockads-fw, and the socket holder on port 153/154)
#   uid 1  the 'blockads' daemon user
#   uid 2  an ordinary user
#
# Usage: tests/netns/fw_helper.sh      (exit status 0 = all expectations met)
# A backend that is unusable in a user namespace (legacy without its kernel
# modules loaded) is reported as SKIP.
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
install -m 755 "$ROOT/helper/blockads-fw" /run/blockads-fw-helper
install -m 755 "$ROOT/helper/blockads-fw-emergency.sh" /run/emergency.sh
install -m 644 "$HERE/fw_run.py" /run/fw_run.py
mkdir -p /run/etc/blockads-linux

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
query() { python3 -I /run/dnsprobe.py query "$@"; }

FW_BIN_DIRS=""
FW_TIMEOUT=""
fw() { FW_BIN_DIRS="$FW_BIN_DIRS" FW_TIMEOUT="$FW_TIMEOUT" python3 -I /run/fw_run.py /run/blockads-fw-helper "$@"; }
conf() { printf '%s\n' "$@" >/run/etc/blockads-linux/firewall.conf; chmod 644 /run/etc/blockads-linux/firewall.conf; }
state() { python3 -I -c "import json,sys; s=json.load(open('/run/blockads-fw/state.json')); print(eval(sys.argv[1], {'s': s}))" "$1"; }

# --- network fixture ---------------------------------------------------------
ip link set lo up
ip link add d0 type dummy
ip addr add 10.9.9.1/24 dev d0
ip -6 addr add fd00:9::1/64 dev d0 nodad
ip link set d0 up
ip route add default dev d0
ip -6 route add default dev d0

trap 'kill $(jobs -p) 2>/dev/null' EXIT
python3 -I /run/dnsprobe.py serve --port 153 127.0.0.1 ::1 >/run/serve.log 2>&1 &
python3 -I /run/dnsprobe.py serve --port 154 --tag bridge 0.0.0.0 >/run/serve-bridge.log 2>&1 &
for _ in $(seq 50); do grep -q READY /run/serve.log 2>/dev/null && grep -q READY /run/serve-bridge.log 2>/dev/null && break; sleep 0.1; done
grep -q READY /run/serve.log || { echo "responder failed: $(cat /run/serve.log)"; exit 1; }

save_all() { for t in iptables ip6tables; do "$t-$1-save" 2>/dev/null; done; }
left() { save_all "$1" | grep -c BLOCKADS_; }
jumps() {  # jumps BACKEND FAMILY_CMD TABLE BUILTIN CHAIN
    "$2-$1" -w 5 -t "$3" -S "$4" 2>/dev/null | grep -cx -- "-A $4 -j $5"
}

usable() {
    "iptables-$1" -w 5 -t nat -S OUTPUT >/dev/null 2>&1 && "iptables-$1" -w 5 -t filter -S OUTPUT >/dev/null 2>&1
}

# Wrappers that fail or hang on the N-th call (counted across all tools).
make_fault_bin() {  # make_fault_bin BACKEND
    local b=$1 dir=/run/fault-$1 name multi
    multi=$(readlink -f "$(command -v "iptables-$b")")
    rm -rf "$dir"; mkdir -p "$dir"
    echo 0 >"$dir/count"; echo 0 >"$dir/at"; echo fail >"$dir/mode"
    for name in iptables iptables-restore ip6tables ip6tables-restore; do
        cat >"$dir/$name" <<EOF
#!/bin/bash
n=\$(( \$(cat $dir/count) + 1 )); echo \$n >$dir/count
if [ "\$n" = "\$(cat $dir/at)" ]; then
    case \$(cat $dir/mode) in
        fail) echo "injected failure" >&2; exit 4 ;;
        timeout) exec sleep 30 ;;
    esac
fi
exec -a $name $multi "\$@"
EOF
        chmod 755 "$dir/$name"
    done
}

run_backend() {
    local b=$1
    echo "=== backend: $b ($(iptables-$b -V 2>&1)) ==="
    if ! usable "$b"; then
        report SKIP "[$b] backend usable in a user namespace" "$(iptables-$b -t nat -S OUTPUT 2>&1 | tail -1)"
        return
    fi
    mkdir -p "/run/bin-$b"
    ln -sf "$(command -v "iptables-$b")" "/run/bin-$b/iptables"
    ln -sf "$(command -v "iptables-$b-restore")" "/run/bin-$b/iptables-restore"
    ln -sf "$(command -v "ip6tables-$b")" "/run/bin-$b/ip6tables"
    ln -sf "$(command -v "ip6tables-$b-restore")" "/run/bin-$b/ip6tables-restore"
    FW_BIN_DIRS="/run/bin-$b"
    FW_TIMEOUT=""
    conf "port=153"

    # apply + verify
    check "[$b] apply --verify" fw apply --verify
    expect "[$b] state: ipv4 active" active state 's["families"]["ipv4"]["status"]'
    expect "[$b] state: ipv6 active" active state 's["families"]["ipv6"]["status"]'
    expect "[$b] state: backend" "$b" state 's["backend"]'
    for fam in iptables ip6tables; do
        expect "[$b] $fam nat OUTPUT: one jump"    1 jumps "$b" "$fam" nat OUTPUT BLOCKADS_DNS
        expect "[$b] $fam filter OUTPUT: one jump" 1 jumps "$b" "$fam" filter OUTPUT BLOCKADS_OUT
    done
    expect "[$b] user -> 192.0.2.1:53 redirected"         OK      as_uid 2 python3 -I /run/dnsprobe.py query 192.0.2.1 53
    expect "[$b] user -> [2001:db8::1]:53 tcp redirected"  OK      as_uid 2 python3 -I /run/dnsprobe.py query --proto tcp 2001:db8::1 53
    expect "[$b] daemon uid -> 192.0.2.1:53 not redirected" TIMEOUT as_uid 1 python3 -I /run/dnsprobe.py query 192.0.2.1 53
    expect "[$b] user DoT tcp/853 rejected"                REFUSED as_uid 2 python3 -I /run/dnsprobe.py query --proto tcp 192.0.2.1 853

    # idempotency and de-duplication
    local before after
    before="$(save_all "$b" | grep -v '^#' | sed 's/\[[0-9]*:[0-9]*\]//')"
    check "[$b] apply again" fw apply --verify
    after="$(save_all "$b" | grep -v '^#' | sed 's/\[[0-9]*:[0-9]*\]//')"
    if [[ "$before" == "$after" ]]; then report PASS "[$b] second apply changes nothing" ""; else report FAIL "[$b] second apply changes nothing" "$(diff <(echo "$before") <(echo "$after") | head -5 | tr '\n' '|')"; fi
    "iptables-$b" -t nat -A OUTPUT -j BLOCKADS_DNS; "iptables-$b" -t nat -A OUTPUT -j BLOCKADS_DNS
    "iptables-$b" -t nat -I OUTPUT 1 -d 203.0.113.7/32 -j RETURN
    check "[$b] apply with duplicate jumps" fw apply
    expect "[$b] duplicates removed" 1 jumps "$b" iptables nat OUTPUT BLOCKADS_DNS
    expect "[$b] admin rule kept" 1 bash -c "iptables-$b -t nat -S OUTPUT | grep -c 203.0.113.7"
    expect "[$b] warning: jump not first" 1 bash -c "grep -c 'not first' /run/blockads-fw/state.json"
    "iptables-$b" -t nat -D OUTPUT -d 203.0.113.7/32 -j RETURN

    # status
    expect "[$b] status --json shows live jumps" 1 bash -c "fw() { FW_BIN_DIRS=$FW_BIN_DIRS python3 -I /run/fw_run.py /run/blockads-fw-helper \"\$@\"; }; fw status --json | python3 -I -c 'import json,sys; print(json.load(sys.stdin)[\"live\"][\"jumps\"][\"ipv4\"][\"BLOCKADS_DNS\"])'"

    # revert
    "iptables-$b" -t nat -A OUTPUT -o lo -j BLOCKADS_DNS   # a non-exact jump
    check "[$b] revert" fw revert
    expect "[$b] no BLOCKADS_ left after revert" 0 left "$b"
    expect "[$b] probe fails fast after revert (v4)" REFUSED query 127.0.0.1 9
    expect "[$b] probe fails fast after revert (v6)" REFUSED query ::1 9
    check "[$b] revert on a clean state" fw revert

    # bridge chains (opt-in)
    conf "port=153" "bridge_interfaces=d0,br-+"
    check "[$b] apply with bridge_interfaces" fw apply --verify
    expect "[$b] bridge: v4 active" active state 's["bridge"]["families"]["ipv4"]["status"]'
    expect "[$b] bridge: v6 inactive (no [::]:154 listener)" inactive state 's["bridge"]["families"]["ipv6"]["status"]'
    expect "[$b] nat PREROUTING: one jump" 1 jumps "$b" iptables nat PREROUTING BLOCKADS_BRIDGE
    expect "[$b] filter INPUT: one jump"   1 jumps "$b" iptables filter INPUT BLOCKADS_IN
    expect "[$b] no v6 bridge chain" 0 bash -c "ip6tables-$b -t nat -S 2>/dev/null | grep -c BLOCKADS_BRIDGE"
    expect "[$b] direct query to :154 dropped (no DNAT)" TIMEOUT query 10.9.9.1 154
    conf "port=153"
    check "[$b] apply with bridge off" fw apply --verify
    expect "[$b] bridge chains removed" 0 bash -c "save_all() { for t in iptables ip6tables; do \$t-$b-save 2>/dev/null; done; }; save_all | grep -Ec 'BLOCKADS_(BRIDGE|IN)'"
    conf "port=153" "bridge_interfaces=d0"
    check "[$b] apply with bridge again" fw apply
    check "[$b] revert removes bridge chains" fw revert
    expect "[$b] nothing left" 0 left "$b"
    conf "port=153"

    # emergency script
    check "[$b] apply before emergency" fw apply --verify
    check "[$b] emergency script" sh /run/emergency.sh
    expect "[$b] nothing left after emergency" 0 left "$b"
    check "[$b] apply before emergency (non-exact jump)" fw apply
    "iptables-$b" -t nat -A OUTPUT -o lo -j BLOCKADS_DNS
    expect "[$b] emergency reports a non-exact jump" 1 bash -c "sh /run/emergency.sh >/dev/null 2>&1; echo \$?"
    check "[$b] python revert cleans it" fw revert
    expect "[$b] nothing left" 0 left "$b"

    # port not privileged: refuse, apply nothing
    sysctl -qw net.ipv4.ip_unprivileged_port_start=100
    expect "[$b] unprivileged port refused" 1 bash -c "FW_BIN_DIRS=$FW_BIN_DIRS python3 -I /run/fw_run.py /run/blockads-fw-helper apply --verify >/dev/null 2>&1; echo \$?"
    expect "[$b] nothing applied" 0 left "$b"
    sysctl -qw net.ipv4.ip_unprivileged_port_start=1024

    # fault injection: fail or hang on the N-th call
    make_fault_bin "$b"
    FW_BIN_DIRS="/run/fault-$b"
    echo 0 >"/run/fault-$b/count"
    fw apply --verify >/dev/null 2>&1
    local total; total=$(cat "/run/fault-$b/count")
    fw revert >/dev/null 2>&1
    local mode n rc bad=0 tried=0
    for mode in fail timeout; do
        [[ $mode == timeout ]] && FW_TIMEOUT=1
        echo "$mode" >"/run/fault-$b/mode"
        for n in $(seq 1 "$total"); do
            echo 0 >"/run/fault-$b/count"; echo "$n" >"/run/fault-$b/at"
            fw apply --verify >/dev/null 2>&1; rc=$?
            echo 0 >"/run/fault-$b/at"
            tried=$((tried + 1))
            if [[ $rc -eq 0 ]]; then
                [[ "$(query 127.0.0.1 9)" == OK* ]] || { bad=$((bad + 1)); echo "  $mode@$n: rc 0 but probe fails"; }
            elif [[ $rc -eq 1 ]]; then
                if [[ $(left "$b") -ne 0 ]] && ! grep -q '"left"' /run/blockads-fw/state.json; then
                    bad=$((bad + 1)); echo "  $mode@$n: rules left and not reported"
                fi
            else
                bad=$((bad + 1)); echo "  $mode@$n: rc $rc"
            fi
            fw revert >/dev/null 2>&1
            if [[ $(left "$b") -ne 0 ]]; then bad=$((bad + 1)); echo "  $mode@$n: revert left rules"; fi
        done
        FW_TIMEOUT=""
    done
    if [[ $bad -eq 0 ]]; then report PASS "[$b] fault on each of $total calls (fail, timeout)" "$tried runs"; else report FAIL "[$b] fault on each of $total calls" "$bad bad"; fi
    FW_BIN_DIRS="/run/bin-$b"
}

run_backend nft
run_backend legacy

# --- both backends: leftovers in the other one --------------------------------
echo "=== cross-backend ==="
if usable nft && usable legacy; then
    # A realistic /usr/sbin: plain names on nft, plus the -nft and -legacy names.
    mkdir -p /run/bin-both
    for t in iptables iptables-restore ip6tables ip6tables-restore; do
        ln -sf "$(readlink -f "/run/bin-nft/$t")" "/run/bin-both/$t"
    done
    for b in nft legacy; do
        for t in iptables ip6tables; do
            ln -sf "$(command -v "$t-$b")" "/run/bin-both/$t-$b"
            ln -sf "$(command -v "$t-$b-restore")" "/run/bin-both/$t-$b-restore"
        done
    done
    FW_BIN_DIRS="/run/bin-both"
    iptables-legacy -t nat -N BLOCKADS_DNS; iptables-legacy -t nat -A OUTPUT -j BLOCKADS_DNS
    check "apply on nft removes legacy leftovers" fw apply --verify
    expect "legacy clean" 0 left legacy
    iptables-legacy -t filter -N BLOCKADS_OUT; iptables-legacy -t filter -A OUTPUT -j BLOCKADS_OUT
    check "revert --all-backends" fw revert --all-backends
    expect "nft clean" 0 left nft
    expect "legacy clean" 0 left legacy
else
    report SKIP "cross-backend cleanup" "needs both backends"
fi

# --- IPv6 disabled ---------------------------------------------------------------
echo "=== IPv6 disabled ==="
FW_BIN_DIRS="/run/bin-nft"
sysctl -qw net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.lo.disable_ipv6=1 net.ipv6.conf.d0.disable_ipv6=1
check "apply with IPv6 disabled" fw apply --verify
expect "ipv4 active" active state 's["families"]["ipv4"]["status"]'
expect "ipv6 not applied" True state 's["families"]["ipv6"]["status"] in ("unavailable", "degraded")'
expect "no v6 rules" 0 bash -c "ip6tables-nft-save 2>/dev/null | grep -c BLOCKADS_"
expect "v4 still redirected" OK as_uid 2 python3 -I /run/dnsprobe.py query 192.0.2.1 53
check "revert with IPv6 disabled" fw revert
expect "nothing left" 0 left nft
sysctl -qw net.ipv6.conf.lo.disable_ipv6=0
# ::1 is back but nothing listens on it any more (the responder's v6 socket
# was bound before): IPv6 must be degraded, not applied blindly.
pkill -f 'dnsprobe.py serve --port 153' ; sleep 0.2
python3 -I /run/dnsprobe.py serve --port 153 127.0.0.1 >/run/serve4.log 2>&1 &
for _ in $(seq 50); do grep -q READY /run/serve4.log 2>/dev/null && break; sleep 0.1; done
check "apply without a [::1]:153 listener" fw apply --verify
expect "ipv6 degraded" degraded state 's["families"]["ipv6"]["status"]'
check "revert" fw revert

echo
echo "$PASSES passed, $FAILURES failed"
exit $(( FAILURES > 0 ))
