#!/usr/bin/env bash
# Interception checks: the iptables rule set behaves as blockads-fw relies on.
#
# Runs ONLY inside a throwaway user + network + mount namespace created by
# `unshare --map-auto --map-root-user`: it can never modify the host firewall,
# and everything disappears when the script exits.
#
# Inside the namespace:
#   uid 0  plays root / the root helper (blockads-fw) and the socket holder (PID 1)
#   uid 1  plays the 'blockads' daemon user (excluded from redirection)
#   uid 2  plays an ordinary desktop user
#
# Usage: tests/netns/interception.sh            (exit status 0 = all expectations met)
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ "${1:-}" != "--inner" ]]; then
    exec unshare --map-auto --map-root-user --net --mount --propagation private \
        -- bash "${BASH_SOURCE[0]}" --inner
fi

PORT=153          # privileged port held by systemd in production
PROBE_PORT=9      # discard port used for the interception probe
DAEMON_UID=1
USER_UID=2
FAILURES=0

# Private /run: legacy iptables needs a writable xtables.lock, and mapped
# non-zero uids cannot traverse the (mode 700) home directory.
mount -t tmpfs -o mode=755 tmpfs /run
install -m 644 "$HERE/dnsprobe.py" /run/dnsprobe.py

probe() { python3 -I /run/dnsprobe.py "$@"; }
as_uid() { local uid=$1; shift; setpriv --reuid="$uid" --regid="$uid" --clear-groups "$@"; }

report() {  # report STATUS NAME DETAIL
    printf '%-5s %-58s %s\n' "$1" "$2" "$3"
    [[ "$1" == FAIL ]] && FAILURES=$((FAILURES + 1))
    return 0
}

expect() {  # expect NAME EXPECTED_FIRST_WORD COMMAND...
    local name=$1 want=$2; shift 2
    local out; out="$("$@" 2>&1)"
    local got=${out%% *}
    if [[ "$got" == "$want" ]]; then report PASS "$name" "$out"; else report FAIL "$name" "want $want, got: $out"; fi
}

# --- network fixture ---------------------------------------------------------
ip link set lo up
ip link add d0 type dummy
ip addr add 10.9.9.1/24 dev d0
ip -6 addr add fd00:9::1/64 dev d0 nodad
ip link set d0 up
ip route add default dev d0
ip -6 route add default dev d0

# The "socket held by PID 1": a responder on the privileged port (uid 0).
# Background jobs must die with the script, or they would keep the namespace alive.
trap 'kill $(jobs -p) 2>/dev/null' EXIT
probe serve --port "$PORT" 127.0.0.1 ::1 >/run/serve.log 2>&1 &
for _ in $(seq 50); do grep -q READY /run/serve.log 2>/dev/null && break; sleep 0.1; done
grep -q READY /run/serve.log || { echo "responder failed: $(cat /run/serve.log)"; exit 1; }

# --- helpers implementing the planned apply/revert algorithm -----------------
render_v4() {
cat <<EOF
*nat
:BLOCKADS_DNS - [0:0]
-A BLOCKADS_DNS -d 127.0.0.1/32 -p udp -m udp --dport $PROBE_PORT -m comment --comment "blockads-linux probe; runtime-only, do not persist" -j REDIRECT --to-ports $PORT
-A BLOCKADS_DNS -d 127.0.0.1/32 -p tcp -m tcp --dport $PROBE_PORT -j REDIRECT --to-ports $PORT
-A BLOCKADS_DNS -m owner --uid-owner $DAEMON_UID -j RETURN
-A BLOCKADS_DNS -m addrtype --dst-type LOCAL -j RETURN
-A BLOCKADS_DNS -d 100.100.100.100/32 -j RETURN
-A BLOCKADS_DNS -p udp -m udp --dport 53 -j REDIRECT --to-ports $PORT
-A BLOCKADS_DNS -p tcp -m tcp --dport 53 -j REDIRECT --to-ports $PORT
${1:+-I OUTPUT 1 -j BLOCKADS_DNS}
COMMIT
*filter
:BLOCKADS_OUT - [0:0]
-A BLOCKADS_OUT -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN
-A BLOCKADS_OUT -m owner --uid-owner $DAEMON_UID -j RETURN
-A BLOCKADS_OUT -m addrtype --dst-type LOCAL -j RETURN
-A BLOCKADS_OUT -p tcp -m tcp --dport 853 -j REJECT --reject-with tcp-reset
-A BLOCKADS_OUT -p udp -m udp --dport 853 -j REJECT --reject-with icmp-port-unreachable
-A BLOCKADS_OUT -p udp -m multiport --dports 3478,5349,19302:19309 -j REJECT --reject-with icmp-port-unreachable
-A BLOCKADS_OUT -p tcp -m multiport --dports 3478,5349 -j REJECT --reject-with tcp-reset
${2:+-I OUTPUT 1 -j BLOCKADS_OUT}
COMMIT
EOF
}

render_v6() {
cat <<EOF
*nat
:BLOCKADS_DNS - [0:0]
-A BLOCKADS_DNS -d ::1/128 -p udp -m udp --dport $PROBE_PORT -m comment --comment "blockads-linux probe; runtime-only, do not persist" -j REDIRECT --to-ports $PORT
-A BLOCKADS_DNS -d ::1/128 -p tcp -m tcp --dport $PROBE_PORT -j REDIRECT --to-ports $PORT
-A BLOCKADS_DNS -m owner --uid-owner $DAEMON_UID -j RETURN
-A BLOCKADS_DNS -m addrtype --dst-type LOCAL -j RETURN
-A BLOCKADS_DNS -d fd7a:115c:a1e0::53/128 -j RETURN
-A BLOCKADS_DNS -p udp -m udp --dport 53 -j REDIRECT --to-ports $PORT
-A BLOCKADS_DNS -p tcp -m tcp --dport 53 -j REDIRECT --to-ports $PORT
${1:+-I OUTPUT 1 -j BLOCKADS_DNS}
COMMIT
*filter
:BLOCKADS_OUT - [0:0]
-A BLOCKADS_OUT -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN
-A BLOCKADS_OUT -m owner --uid-owner $DAEMON_UID -j RETURN
-A BLOCKADS_OUT -m addrtype --dst-type LOCAL -j RETURN
-A BLOCKADS_OUT -p tcp -m tcp --dport 853 -j REJECT --reject-with tcp-reset
-A BLOCKADS_OUT -p udp -m udp --dport 853 -j REJECT --reject-with icmp6-port-unreachable
${2:+-I OUTPUT 1 -j BLOCKADS_OUT}
COMMIT
EOF
}

count_jumps() {  # count_jumps IPT TABLE CHAIN
    "$1" -w 5 -t "$2" -S OUTPUT 2>/dev/null | grep -cx -- "-A OUTPUT -j $3"
}

apply_family() {  # apply_family IPT RESTORE RENDER_FN
    local ipt=$1 restore=$2 render=$3 dns_jump="" out_jump=""
    [[ $(count_jumps "$ipt" nat BLOCKADS_DNS) -eq 0 ]] && dns_jump=1
    [[ $(count_jumps "$ipt" filter BLOCKADS_OUT) -eq 0 ]] && out_jump=1
    "$render" "$dns_jump" "$out_jump" | "$restore" -w 5 --noflush
}

revert_family() {  # revert_family IPT
    local ipt=$1 table chain i
    for pair in nat:BLOCKADS_DNS filter:BLOCKADS_OUT; do
        table=${pair%%:*}; chain=${pair#*:}
        for i in $(seq 16); do
            "$ipt" -w 5 -t "$table" -C OUTPUT -j "$chain" 2>/dev/null || break
            "$ipt" -w 5 -t "$table" -D OUTPUT -j "$chain"
        done
        "$ipt" -w 5 -t "$table" -F "$chain" 2>/dev/null
        "$ipt" -w 5 -t "$table" -X "$chain" 2>/dev/null
    done
    return 0
}

# --- per-backend checks --------------------------------------------------------
run_backend() {
    local b=$1
    local ipt="iptables-$b" ip6t="ip6tables-$b" r4="iptables-$b-restore" r6="ip6tables-$b-restore"
    local save4="iptables-$b-save" save6="ip6tables-$b-save"
    echo "=== backend: $b ($($ipt -V 2>&1)) ==="
    if ! "$ipt" -w 5 -t nat -S OUTPUT >/dev/null 2>&1; then
        report SKIP "[$b] backend usable in a user namespace" "$($ipt -t nat -S OUTPUT 2>&1 | head -1)"
        return
    fi

    # S1: --noflush + chain re-declaration
    "$ipt" -w 5 -t nat -A OUTPUT -d 203.0.113.7/32 -j RETURN    # a pre-existing admin rule
    printf '*nat\n:BLOCKADS_DNS - [0:0]\n-A BLOCKADS_DNS -p udp --dport 53 -j RETURN\n-I OUTPUT 1 -j BLOCKADS_DNS\nCOMMIT\n' | "$r4" -w 5 --noflush
    printf '*nat\n:BLOCKADS_DNS - [0:0]\n-A BLOCKADS_DNS -p tcp --dport 53 -j RETURN\nCOMMIT\n' | "$r4" -w 5 --noflush
    local chain_dump; chain_dump="$("$ipt" -t nat -S BLOCKADS_DNS)"
    if [[ "$chain_dump" == $'-N BLOCKADS_DNS\n-A BLOCKADS_DNS -p tcp -m tcp --dport 53 -j RETURN' ]]; then
        report PASS "[$b] S1 re-declaring a chain flushes it atomically" "only the 2nd restore's rule remains"
    else
        report FAIL "[$b] S1 re-declaring a chain flushes it atomically" "$(echo "$chain_dump" | tr '\n' '|')"
    fi
    if "$ipt" -t nat -C OUTPUT -d 203.0.113.7/32 -j RETURN 2>/dev/null \
        && [[ $(count_jumps "$ipt" nat BLOCKADS_DNS) -eq 1 ]] \
        && "$ipt" -t nat -S OUTPUT | grep -qx -- '-P OUTPUT ACCEPT'; then
        report PASS "[$b] S1 built-in chain, policy and admin rule untouched" "1 jump, admin rule kept"
    else
        report FAIL "[$b] S1 built-in chain, policy and admin rule untouched" "$("$ipt" -t nat -S OUTPUT | tr '\n' '|')"
    fi
    "$ipt" -w 5 -t nat -D OUTPUT -d 203.0.113.7/32 -j RETURN
    revert_family "$ipt"

    # S2: does a failing table roll back the tables before it?
    printf '*nat\n:X_ATOMIC - [0:0]\n-A X_ATOMIC -j RETURN\nCOMMIT\n*filter\n-A NO_SUCH_CHAIN -j ACCEPT\nCOMMIT\n' \
        | "$r4" -w 5 --noflush >/dev/null 2>&1
    local rc=$?
    if "$ipt" -t nat -S X_ATOMIC >/dev/null 2>&1; then
        report INFO "[$b] S2 failure in a later table" "rc=$rc; EARLIER TABLE STAYS COMMITTED (per-table commit)"
        "$ipt" -t nat -F X_ATOMIC; "$ipt" -t nat -X X_ATOMIC
    else
        report INFO "[$b] S2 failure in a later table" "rc=$rc; whole input rolled back"
    fi

    # S3: -C matches comment/owner exactly
    "$ipt" -w 5 -t nat -N X_CHECK
    "$ipt" -w 5 -t nat -A X_CHECK -m owner --uid-owner 1 -m comment --comment c1 -j RETURN
    if "$ipt" -t nat -C X_CHECK -m owner --uid-owner 1 -m comment --comment c1 -j RETURN 2>/dev/null \
        && ! "$ipt" -t nat -C X_CHECK -m owner --uid-owner 1 -m comment --comment c2 -j RETURN 2>/dev/null \
        && ! "$ipt" -t nat -C X_CHECK -m owner --uid-owner 1 -j RETURN 2>/dev/null; then
        report PASS "[$b] S3 -C is exact for owner + comment" "same spec matches, other comment / none does not"
    else
        report FAIL "[$b] S3 -C is exact for owner + comment" ""
    fi
    "$ipt" -t nat -F X_CHECK; "$ipt" -t nat -X X_CHECK

    # S4: full transaction, applied twice (idempotency), then functional checks
    if apply_family "$ipt" "$r4" render_v4 && apply_family "$ipt" "$r4" render_v4; then
        report PASS "[$b] S4 v4 transaction applies (twice)" "$("$ipt" -t nat -S BLOCKADS_DNS | wc -l) nat lines"
    else
        report FAIL "[$b] S4 v4 transaction applies (twice)" ""
    fi
    if apply_family "$ip6t" "$r6" render_v6 && apply_family "$ip6t" "$r6" render_v6; then
        report PASS "[$b] S4 v6 transaction applies (twice)" "$("$ip6t" -t nat -S BLOCKADS_DNS | wc -l) nat lines"
    else
        report FAIL "[$b] S4 v6 transaction applies (twice)" ""
    fi
    if [[ $(count_jumps "$ipt" nat BLOCKADS_DNS) -eq 1 && $(count_jumps "$ipt" filter BLOCKADS_OUT) -eq 1 \
          && $(count_jumps "$ip6t" nat BLOCKADS_DNS) -eq 1 && $(count_jumps "$ip6t" filter BLOCKADS_OUT) -eq 1 ]]; then
        report PASS "[$b] S4 exactly one jump per chain after re-apply" ""
    else
        report FAIL "[$b] S4 exactly one jump per chain after re-apply" ""
    fi

    expect "[$b] S4 root probe 127.0.0.1:9 udp -> daemon"            OK      probe query 127.0.0.1 $PROBE_PORT
    expect "[$b] S4 root probe 127.0.0.1:9 tcp -> daemon"            OK      probe query --proto tcp 127.0.0.1 $PROBE_PORT
    expect "[$b] S4 daemon-uid probe still redirected"               OK      as_uid $DAEMON_UID python3 -I /run/dnsprobe.py query 127.0.0.1 $PROBE_PORT
    expect "[$b] S4 user -> 192.0.2.1:53 udp redirected"             OK      as_uid $USER_UID python3 -I /run/dnsprobe.py query 192.0.2.1 53
    expect "[$b] S4 user -> 192.0.2.1:53 tcp redirected"             OK      as_uid $USER_UID python3 -I /run/dnsprobe.py query --proto tcp 192.0.2.1 53
    expect "[$b] S4 user -> 10.9.9.1:53 (LOCAL) not redirected"      REFUSED as_uid $USER_UID python3 -I /run/dnsprobe.py query 10.9.9.1 53
    expect "[$b] S4 user -> 127.0.0.1:53 (LOCAL) not redirected"     REFUSED as_uid $USER_UID python3 -I /run/dnsprobe.py query 127.0.0.1 53
    expect "[$b] S4 daemon -> 192.0.2.1:53 not redirected"           TIMEOUT as_uid $DAEMON_UID python3 -I /run/dnsprobe.py query 192.0.2.1 53
    expect "[$b] S4 user -> 100.100.100.100:53 bypassed"             TIMEOUT as_uid $USER_UID python3 -I /run/dnsprobe.py query 100.100.100.100 53
    expect "[$b] S4 root probe [::1]:9 udp -> daemon"                OK      probe query ::1 $PROBE_PORT
    expect "[$b] S4 user -> [2001:db8::1]:53 udp redirected"         OK      as_uid $USER_UID python3 -I /run/dnsprobe.py query 2001:db8::1 53
    expect "[$b] S4 user -> [2001:db8::1]:53 tcp redirected"         OK      as_uid $USER_UID python3 -I /run/dnsprobe.py query --proto tcp 2001:db8::1 53
    expect "[$b] S4 user -> [fd00:9::1]:53 (LOCAL) not redirected"   REFUSED as_uid $USER_UID python3 -I /run/dnsprobe.py query fd00:9::1 53
    expect "[$b] S4 daemon -> [2001:db8::1]:53 not redirected"       TIMEOUT as_uid $DAEMON_UID python3 -I /run/dnsprobe.py query 2001:db8::1 53
    expect "[$b] S4 user DoT tcp/853 rejected fast"                  REFUSED as_uid $USER_UID python3 -I /run/dnsprobe.py query --proto tcp 192.0.2.1 853
    expect "[$b] S4 user DoQ udp/853 blocked locally (EPERM)"        BLOCKED as_uid $USER_UID python3 -I /run/dnsprobe.py query 192.0.2.1 853
    expect "[$b] S4 daemon tcp/853 allowed (times out on dummy)"     TIMEOUT as_uid $DAEMON_UID python3 -I /run/dnsprobe.py query --proto tcp 192.0.2.1 853
    expect "[$b] S4 user v6 DoT tcp/853 rejected fast"               REFUSED as_uid $USER_UID python3 -I /run/dnsprobe.py query --proto tcp 2001:db8::1 853

    # S5: revert leaves nothing behind; probe then fails fast (ICMP), not by timeout
    revert_family "$ipt"; revert_family "$ip6t"
    local left; left=$( { "$save4"; "$save6"; } 2>/dev/null | grep -c BLOCKADS_ )
    if [[ "$left" -eq 0 ]]; then report PASS "[$b] S5 revert leaves no BLOCKADS_ rules" ""; else report FAIL "[$b] S5 revert leaves no BLOCKADS_ rules" "$left lines left"; fi
    revert_family "$ipt" && report PASS "[$b] S5 revert is idempotent on a clean state" ""
    expect "[$b] S5 probe without rules fails fast (v4)"             REFUSED probe query 127.0.0.1 $PROBE_PORT
    expect "[$b] S5 probe without rules fails fast (v6)"             REFUSED probe query ::1 $PROBE_PORT
}

run_backend nft
run_backend legacy

# --- S6: why a privileged port (socket activation) ----------------------------
echo "=== privileged vs unprivileged port co-binding ==="
expect "S6 ordinary user cannot bind the privileged port"          EACCES  as_uid $USER_UID python3 -I /run/dnsprobe.py bind 127.0.0.1 $PORT
probe bind --reuseaddr --hold 3 127.0.0.1 15353 >/run/holder.log 2>&1 &
holder_pid=$!
sleep 0.3
as_uid $USER_UID python3 -I /run/dnsprobe.py bind --reuseaddr --hold 3 127.0.0.1 15353 >/run/attacker.log 2>&1 &
attacker_pid=$!
sleep 0.3
python3 -I -c 'import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendto(b"x"*12, ("127.0.0.1", 15353))'
wait "$holder_pid" "$attacker_pid"
report INFO "S6 unprivileged port 15353, SO_REUSEADDR by 'systemd' (uid 0)" "$(tr '\n' ' ' </run/holder.log)"
report INFO "S6 unprivileged port 15353, SO_REUSEADDR by attacker (uid 2)"  "$(tr '\n' ' ' </run/attacker.log)"

echo
if [[ $FAILURES -eq 0 ]]; then echo "ALL EXPECTATIONS MET"; else echo "$FAILURES FAILURE(S)"; fi
exit $(( FAILURES > 0 ))
