#!/usr/bin/env bash
# System-integration checks: the real units, bus policy, polkit files and
# launchers installed by tests/vm/install.sh, run under the machine's own
# systemd. Root, inside a disposable VM (tests/vm/run_system.sh) or CI runner,
# with the tree at /opt/blockads and tests/vm/provision.sh already run.
#
# Usage: system_checks.sh SECTION...
#   install    install.sh install; sysusers/tmpfiles/units/bus policy in place
#   start      enable --now; socket activation, sandbox identity, name owner,
#              firewall applied, DNS to any server is answered by the daemon
#   api        blockadsctl as root: block/test/unblock, DNS follows; updater
#   polkit     blockadsctl from alice's local session, active vs. inactive;
#              starting the units without a password; resolved FlushCaches
#   faults     kill -9, SIGSTOP (watchdog), nat flush, nft flush, code change
#   coexist    Docker restart, firewalld reload/restart, ufw reload: protection holds
#   porttaken  another program holds 127.0.0.1:153: no rules, DNS works; then recovers
#   bridge     opt-in bridge redirect: Docker/podman (default and user networks)
#              filtered, docker restart, LAN cannot reach :154 (with and without
#              BLOCKADS_IN), status line, off again leaves nothing
#   libvirt    libvirt's default network (virbr0 + dnsmasq) with a netns guest on the
#              bridge: dnsmasq path filtered with the redirect off; direct queries
#              with it on; libvirt network/daemon restarts
#   zones      firewalld zones on a test bridge: redirected guest DNS filtered in each,
#              port 154 closed to direct queries; firewall-cmd --reload
#   prereboot / afterboot   around a reboot (run_system.sh), with the rules saved by
#              netfilter-persistent / iptables.service while ours were applied
#   resolveddot  resolved DNSOverTLS opportunistic (filtered) and strict ("partial")
#   clock      clock set to 2001: clock_suspect, plain fallback, encrypted-only NTP rescue
#   suspend    S3 via rtcwake: resume seen, DNS and rules fine
#   captive    NM connectivity check -> PORTAL (fake portal in a netns): captive tier,
#              still filtered; "login" -> back to the configured upstreams
#   wireguard  NM WireGuard connection with ~corp.bt.test: split DNS to the VPN's
#              server, still filtered; down -> route gone
#   noipv6set / noipv6   around a reboot with ipv6.disable=1
#   networks   trust NM's primary connection (pause, network_dns), remove, leave it;
#              the DoH-lookup bypass warning
#   gui        the installed GUI (offscreen) from alice's active session against the
#              real daemon, polkit and systemd (tests/vm/gui_vm.py)
#   stop       stop leaves no BLOCKADS_ and DNS works
#   uninstall  install.sh uninstall while running; then files deleted while
#              running (a package manager that does not stop the service)
#
# Every line is PASS/FAIL/INFO/SKIP; exit status = number of FAILs (max 125).
set -u
SRC=/opt/blockads
VM=$SRC/tests/vm
LIB=/usr/lib/blockads-linux
FAILURES=0
. /etc/os-release
T0=$SECONDS

report() {
    printf '%-5s [%s] %-62s %s\n' "$1" "$ID${VERSION_ID:-}" "$2" "${3:-}"
    [[ $1 == FAIL ]] && FAILURES=$((FAILURES + 1))
    return 0
}
info() { report INFO "$1" "$2"; }
ok() {  # ok NAME DETAIL CONDITION...
    local name=$1 detail=$2; shift 2
    if "$@"; then report PASS "$name" "$detail"; else report FAIL "$name" "$detail"; fi
}
journal() {  # last lines of a unit's journal as INFO
    journalctl -u "$1" -n "${2:-8}" --no-pager -o cat 2>/dev/null | while IFS= read -r l; do info "journal $1" "$l"; done
}

fw_left() { { iptables-nft-save; ip6tables-nft-save; iptables-legacy-save; ip6tables-legacy-save; } 2>/dev/null | grep -c BLOCKADS_; }
jumps() { iptables -w 5 -t nat -S OUTPUT 2>/dev/null | grep -c -- '-j BLOCKADS_DNS'; }
svc() { systemctl show -p "$1" --value blockadsd.service; }
main_pid() { svc MainPID; }
restarts() { svc NRestarts; }

# q SERVER NAME [udp|tcp] -> "NOERROR 1.2.3.4" | "NXDOMAIN -" | "TIMEOUT" | "ERROR ..."
# Port 53 unless Q_PORT is set; QX is a command prefix (e.g. "ip netns exec NS").
q() {
    ${QX:-} python3 -I - "${Q_PORT:-53}" "$@" <<'EOF' 2>&1 | tail -1
import sys, dns.message, dns.query, dns.rcode, dns.exception
port, server, name = int(sys.argv[1]), sys.argv[2], sys.argv[3]
proto = sys.argv[4] if len(sys.argv) > 4 else "udp"
try:
    msg = dns.message.make_query(name, "A")
    r = (dns.query.tcp if proto == "tcp" else dns.query.udp)(msg, server, port=port, timeout=3)
except dns.exception.Timeout:
    print("TIMEOUT"); sys.exit()
except Exception as exc:
    print("ERROR", type(exc).__name__, exc); sys.exit()
addrs = [rd.to_text() for rr in r.answer for rd in rr if rr.rdtype == 1]
print(dns.rcode.to_text(r.rcode()), addrs[0] if addrs else "-")
EOF
}
# A server that does not exist: only the redirect can answer it.
NOWHERE=192.0.2.53
# A fresh name per run: resolved may hold a negative answer from an earlier run.
BLOCKED=blocked-bt-$RANDOM$RANDOM.example.com

waited() { [[ ${1:0:1} != ">" ]]; }  # waited "$t": the wait_for before it succeeded
now_ms() { local t=${EPOCHREALTIME/./}; echo $(( ${t:0:-3} )); }
wait_for() {  # wait_for SECONDS CONDITION... ; prints the elapsed seconds
    local limit=$(( $1 * 1000 )); shift
    local start; start=$(now_ms)
    while :; do
        local el=$(( $(now_ms) - start ))
        if "$@"; then printf '%d.%d' $((el / 1000)) $((el % 1000 / 100)); return 0; fi
        (( el > limit )) && { printf '>%d' $((limit / 1000)); return 1; }
        sleep 0.2
    done
}
restart_daemon() {  # restart without tripping StartLimitBurst=6/10min (many sections restart)
    systemctl reset-failed blockadsd.service 2>/dev/null
    systemctl restart blockadsd.service && wait_for 20 applied >/dev/null
}
is_active() { [[ $(systemctl is-active blockadsd.service) == active ]]; }
applied() { [[ $(jumps) -ge 1 ]] && python3 -I -c 'import json,sys; sys.exit(0 if json.load(open("/run/blockads-fw/state.json")).get("applied") else 1)' 2>/dev/null; }
reverted() { [[ $(fw_left) -eq 0 ]]; }
resolves_example() { [[ $(q 9.9.9.9 example.com) == "NOERROR "[0-9]* ]]; }
nowhere_answers() { [[ $(q $NOWHERE example.com) == NOERROR* ]]; }
restarted_since() { [[ $(restarts) -gt $1 ]] && is_active && applied; }

# --- alice's local session (polkit "active"/"inactive") ----------------------
# Autologin on tty1 gives alice a local seat0 session. Commands run *inside* it
# by moving the shell into the session's cgroup first: polkit resolves the
# subject (the bus name) to a PID, and logind maps the PID to the session.
SESSION=""
alice_session() {
    [[ -n $SESSION ]] && return 0
    mkdir -p /etc/systemd/system/getty@tty1.service.d
    cat >/etc/systemd/system/getty@tty1.service.d/autologin.conf <<'EOF'
[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin alice --noclear %I $TERM
EOF
    systemctl daemon-reload; chvt 1 2>/dev/null; systemctl restart getty@tty1.service
    local s
    for _ in $(seq 50); do
        for s in $(loginctl show-user alice -p Sessions --value 2>/dev/null); do
            [[ $(loginctl show-session "$s" -p TTY --value) == tty1 ]] && { SESSION=$s; return 0; }
        done
        sleep 0.2
    done
    return 1
}
in_session() {  # in_session CMD... : run as alice inside her tty1 session
    local scope uid; scope=$(loginctl show-session "$SESSION" -p Scope --value); uid=$(id -u alice)
    bash -c 'echo $$ >"$1"; shift; exec setpriv --reuid=alice --regid=alice --init-groups "$@"' _ \
        "/sys/fs/cgroup/user.slice/user-$uid.slice/$scope/cgroup.procs" "$@"
}
session_active() { [[ $(loginctl show-session "$SESSION" -p Active --value) == yes ]]; }
ctl_rc() { in_session blockadsctl --no-ask-password "$@" >/run/ctl.out 2>&1; echo $?; }

# --- sections ----------------------------------------------------------------
sec_install() {
    local out; out=$(bash "$VM/install.sh" install "$SRC" 2>&1 | tail -1)
    ok "install.sh install" "$out" [ "${out%% *}" = installed ]
    ok "sysusers created blockads" "$(id blockads 2>&1)" id blockads
    ok "tmpfiles: /etc/blockads-linux, /run/blockads-fw" "" test -d /etc/blockads-linux -a -d /run/blockads-fw
    out=$(systemd-analyze verify --man=no /usr/lib/systemd/system/blockadsd.service /usr/lib/systemd/system/blockads-update.service \
          /usr/lib/systemd/system/blockads-failsafe.service 2>&1)
    # verify also loads the distribution's units it pulls in (Ubuntu 26.04: xfs_scrub's removed
    # CPUAccounting=); only lines about ours count.
    local ours; ours=$(grep -i blockads <<<"$out" | head -3)
    ok "systemd-analyze verify" "${ours:-clean}" test -z "$ours"
    [[ -n $out && -z $ours ]] && info "systemd-analyze verify: other units" "$(head -2 <<<"$out" | tr '\n' ' ')"
    info "systemd-analyze security" "$(systemd-analyze security blockadsd.service 2>/dev/null | tail -1)"
    info "versions" "systemd $(systemctl --version | awk 'NR==1{print $2}'), python $(python3 -c 'import sys;print(sys.version.split()[0])'), $(iptables --version)"
}

sec_start() {
    systemctl enable blockadsd.socket blockadsd.service >/dev/null 2>&1
    systemctl start blockadsd.socket
    # Socket activation: the first query starts the daemon.
    local first; first=$(Q_PORT=153 q 127.0.0.1 example.com)
    ok "socket activation: first query answered" "$first" [ "${first%% *}" = NOERROR ]
    local t; t=$(wait_for 20 applied)
    ok "firewall applied after READY (ExecStartPost)" "${t}s" applied
    [[ $(systemctl is-active blockadsd.service) == active ]] || journal blockadsd.service 15
    local pid user; pid=$(main_pid); user=$(ps -o user= -p "$pid" 2>/dev/null)
    ok "daemon runs as blockads" "pid $pid user $user" [ "$user" = blockads ]
    ok "daemon has no capabilities" "$(grep CapEff /proc/$pid/status)" grep -q 'CapEff:[[:space:]]*0000000000000000' /proc/$pid/status
    local owner; owner=$(busctl --system status io.github.mateusbmp.BlockAds1 2>/dev/null | awk -F= '/^PID=/{print $2}')
    ok "owns io.github.mateusbmp.BlockAds1" "owner pid $owner" [ "$owner" = "$pid" ]
    local listen; listen=$(ss -Hlntup | awk '$5 ~ /:15[34]$/ {print $1, $5, $7}' | sort | tr '\n' ';')
    ok "only loopback :153 is listening, held by systemd" "$listen" \
        bash -c '! ss -Hlntup | awk '"'"'$5 ~ /:15[34]$/'"'"' | grep -v -e "127.0.0.1:153" -e "\[::1\]:153" | grep -q . && ss -Hlntup | grep ":153 " | grep -q systemd'
    local r; r=$(q $NOWHERE example.com)
    ok "query to a non-existent server is answered (UDP)" "$r" [ "${r%% *}" = NOERROR ]
    r=$(q $NOWHERE example.com tcp)
    ok "query to a non-existent server is answered (TCP)" "$r" [ "${r%% *}" = NOERROR ]
    r=$(getent ahostsv4 example.com | head -1)
    ok "system resolver works (getent)" "$r" test -n "$r"
    ok "apply left the emergency copy in /run/blockads-fw" "$(stat -c '%U %a' /run/blockads-fw/emergency.sh 2>&1)" \
        cmp -s /run/blockads-fw/emergency.sh $LIB/blockads-fw-emergency.sh
    info "blockads-fw status" "$($LIB/blockads-fw status | tr '\n' ' ')"
}

sec_api() {
    local out
    out=$(blockadsctl status 2>&1 | head -3 | tr '\n' ' ')
    ok "blockadsctl status (root)" "$out" blockadsctl status
    ok "blockadsctl block $BLOCKED" "" blockadsctl block $BLOCKED
    local r; r=$(q $NOWHERE $BLOCKED)
    ok "blocked domain -> 0.0.0.0 through the redirect" "$r" [ "$r" = "NOERROR 0.0.0.0" ]
    # resolved's cache is flushed shortly *after* the D-Bus reply (debounced).
    local t; t=$(wait_for 3 bash -c "[ \"\$(getent ahostsv4 $BLOCKED | awk 'NR==1{print \$1}')\" = 0.0.0.0 ]")
    r=$(getent ahostsv4 $BLOCKED | awk 'NR==1{print $1}')
    ok "getent -> 0.0.0.0 (system resolver path)" "$r after ${t}s" [ "$r" = 0.0.0.0 ]
    out=$(blockadsctl test $BLOCKED 2>&1 | tr '\n' ' ')
    info "blockadsctl test" "$out"
    ok "blockadsctl unblock" "" blockadsctl unblock $BLOCKED
    r=$(q $NOWHERE $BLOCKED)
    ok "unblocked domain no longer 0.0.0.0" "$r" [ "$r" != "NOERROR 0.0.0.0" ]
    # The daemon asks for a first update on an empty state dir; the .path unit runs it.
    systemctl enable --now blockads-update.path blockads-update.timer >/dev/null 2>&1
    blockadsctl filters update >/dev/null 2>&1
    local t; t=$(wait_for 120 bash -c '[ "$(systemctl show -p Result --value blockads-update.service)" = success ] && [ "$(systemctl show -p ExecMainExitTimestampMonotonic --value blockads-update.service)" != 0 ]')
    ok "blockads-update ran (path unit) and succeeded" "${t}s $(systemctl show -p Result --value blockads-update.service)" \
        [ "$(systemctl show -p Result --value blockads-update.service)" = success ]
    journal blockads-update.service 4
    r=$(q $NOWHERE doubleclick.net)
    info "doubleclick.net after the update" "$r"
}

sec_polkit() {
    if ! alice_session; then report SKIP "polkit: no local session for alice" "$(loginctl list-sessions --no-legend | tr '\n' ';')"; return; fi
    chvt 1; sleep 0.5
    info "alice session" "$SESSION $(loginctl show-session "$SESSION" -p TTY -p Seat -p Active -p Remote | tr '\n' ' ')"
    ok "alice: active session" "" session_active
    local rc
    rc=$(ctl_rc status); ok "active alice: status (view) allowed" "rc=$rc" [ "$rc" = 0 ]
    rc=$(ctl_rc log -n 1); ok "active alice: log (view-logs) allowed" "rc=$rc" [ "$rc" = 0 ]
    rc=$(ctl_rc block polkit-bt.example.com); ok "active alice: block (tighten) allowed, no prompt" "rc=$rc" [ "$rc" = 0 ]
    rc=$(ctl_rc pause 60); ok "active alice: pause (weaken) needs authentication" "rc=$rc $(head -c 120 /run/ctl.out)" [ "$rc" = 4 ]
    rc=$(ctl_rc unblock polkit-bt.example.com); ok "active alice: unblock (weaken) needs authentication" "rc=$rc" [ "$rc" = 4 ]
    # Starting the units: our polkit rule, no password.
    systemctl stop blockadsd.service
    in_session systemctl --no-ask-password start blockadsd.service >/run/ctl.out 2>&1; rc=$?
    ok "active alice: systemctl start blockadsd.service, no password" "rc=$rc $(head -c 120 /run/ctl.out)" [ "$rc" = 0 ]
    wait_for 20 applied >/dev/null
    in_session systemctl --no-ask-password stop blockadsd.service >/run/ctl.out 2>&1; rc=$?
    ok "active alice: systemctl stop still needs authentication" "rc=$rc" [ "$rc" != 0 ]
    systemctl start blockadsd.service; wait_for 20 applied >/dev/null

    chvt 2; sleep 1
    ok "alice: inactive after chvt 2" "" [ "$(loginctl show-session "$SESSION" -p Active --value)" = no ]
    rc=$(ctl_rc status); ok "inactive alice: status (view) allowed" "rc=$rc" [ "$rc" = 0 ]
    rc=$(ctl_rc log -n 1); ok "inactive alice: log (view-logs) needs authentication" "rc=$rc" [ "$rc" = 4 ]
    rc=$(ctl_rc block polkit2-bt.example.com); ok "inactive alice: block (tighten) needs authentication" "rc=$rc" [ "$rc" = 4 ]
    systemctl stop blockadsd.service
    in_session systemctl --no-ask-password start blockadsd.service >/run/ctl.out 2>&1; rc=$?
    ok "inactive alice: systemctl start needs authentication" "rc=$rc" [ "$rc" != 0 ]
    systemctl start blockadsd.service; wait_for 20 applied >/dev/null
    chvt 1
    blockadsctl unblock polkit-bt.example.com >/dev/null 2>&1

    if [[ $(systemctl is-active systemd-resolved) == active ]]; then
        local out; out=$(setpriv --reuid=blockads --regid=blockads --init-groups busctl --system call \
            org.freedesktop.resolve1 /org/freedesktop/resolve1 org.freedesktop.resolve1.Manager FlushCaches 2>&1)
        ok "resolved FlushCaches allowed for blockads (our rule)" "${out:-ok}" test -z "$out"
    else
        report SKIP "resolved FlushCaches" "systemd-resolved not running"
    fi
}

fault() {  # fault NAME SETTLE_LIMIT CMD... : run a fault, then check recovery
    # DNS must resolve within DNS_LIMIT seconds (default 5).
    local name=$1 limit=$2 dns_limit=${DNS_LIMIT:-5}; shift 2
    systemctl reset-failed blockadsd.service 2>/dev/null   # the start limit is 6 per 10 min
    local before; before=$(restarts)
    "$@"
    local t; t=$(wait_for "$dns_limit" resolves_example)
    ok "$name: DNS resolves within ${dns_limit}s" "${t}s" waited "$t"
    t=$(wait_for "$limit" restarted_since "$before")
    ok "$name: restarted and re-applied" "${t}s (NRestarts $before -> $(restarts))" restarted_since "$before"
    if ! restarted_since "$before"; then journal blockadsd.service 12; fi
    local r; r=$(q $NOWHERE example.com)
    ok "$name: redirect answers again" "$r" [ "${r%% *}" = NOERROR ]
}
f_kill9() {
    kill -9 "$(main_pid)"
    local t; t=$(wait_for 3 reverted)
    ok "kill -9: rules removed (ExecStopPost)" "${t}s" test "${t:0:1}" != ">"
}
f_sigstop() { kill -STOP "$(main_pid)"; }
f_natflush() { iptables -w 5 -t nat -F; ip6tables -w 5 -t nat -F; }
f_nftflush() { nft flush ruleset; }
f_codechange() { touch "$LIB/python/blockads_linux/__init__.py"; }

sec_faults() {
    is_active && applied || { report FAIL "faults: the service is not running and applied" ""; return; }
    fault "kill -9" 15 f_kill9
    # A hang cannot be told apart from slowness before the watchdog: DNS is
    # down until WatchdogSec=15s fires, then the revert un-redirects it.
    DNS_LIMIT=25 fault "SIGSTOP (watchdog 15s)" 60 f_sigstop
    fault "iptables -t nat -F" 90 f_natflush
    if $LIB/blockads-fw status 2>/dev/null | grep -q '^applied: yes (legacy)'; then
        # Legacy xtables (Fedora's default): the flush does not touch our rules.
        reload_fault "nft flush ruleset (legacy backend, rules untouched)" f_nftflush
    else
        fault "nft flush ruleset" 90 f_nftflush
    fi
    fault "code changed under the daemon (install check)" 100 f_codechange
}

sec_stop() {
    systemctl stop blockadsd.service blockadsd.socket
    ok "stop: no BLOCKADS_ left" "$(fw_left) lines" reverted
    t=$(wait_for 5 resolves_example); ok "stop: DNS resolves within 5s" "${t}s" waited "$t"
    systemctl start blockadsd.socket blockadsd.service
    wait_for 20 applied >/dev/null
}

sec_uninstall() {
    is_active && applied || restart_daemon
    local out; out=$(bash "$VM/install.sh" uninstall 2>&1 | tail -1)
    ok "install.sh uninstall while running" "$out" [ "$out" = uninstalled ]
    ok "uninstall: no BLOCKADS_ left" "$(fw_left) lines" reverted
    t=$(wait_for 5 resolves_example); ok "uninstall: DNS resolves within 5s" "${t}s" waited "$t"
    ok "uninstall: no files left" "$(ls -d $LIB /usr/bin/blockadsctl /usr/lib/systemd/system/blockads* 2>/dev/null | tr '\n' ' ')" \
        bash -c "! ls -d $LIB /usr/bin/blockadsctl /usr/lib/systemd/system/blockads* >/dev/null 2>&1"

    # Files deleted under a running, applied service (no prerm stop).
    bash "$VM/install.sh" install "$SRC" >/dev/null
    systemctl start blockadsd.socket blockadsd.service; wait_for 20 applied >/dev/null
    rm -rf "$LIB" /usr/lib/systemd/system/blockads* /usr/bin/blockadsctl
    # Wait for the stop hooks too: "deactivating" still runs ExecStopPost.
    local t; t=$(wait_for 120 bash -c '[[ $(systemctl is-active blockadsd.service) =~ ^(inactive|failed)$ ]]')
    info "files deleted while running: service" "$(systemctl is-active blockadsd.service) after ${t}s"
    t=$(wait_for 5 resolves_example); ok "files deleted while running: DNS resolves within 5s" "${t}s" waited "$t"
    ok "files deleted while running: no BLOCKADS_ left" "$(fw_left) lines" reverted
    reverted || { journal blockadsd.service 10; journal blockads-failsafe.service 4; }
    # Clean up whatever is left for the next section.
    systemctl stop blockadsd.service blockadsd.socket 2>/dev/null
    python3 -I "$SRC/helper/blockads-fw" revert --all-backends >/dev/null 2>&1
    bash "$VM/install.sh" install "$SRC" >/dev/null && bash "$VM/install.sh" uninstall >/dev/null
}

# --- coexistence: other firewall managers reloading under us ------------------
pkg_install() {  # pkg_install PKG... : best effort, from the distro's own repos
    case $ID in
        debian|ubuntu) DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends "$@" >/dev/null 2>&1 ;;
        fedora) dnf install -y -q "$@" >/dev/null 2>&1 ;;
        arch) pacman -S --noconfirm --needed --noprogressbar "$@" >/dev/null 2>&1 ;;
    esac
}
reapplied() { applied && [[ $(q $NOWHERE example.com) == NOERROR* ]]; }
reload_fault() {  # reload_fault NAME CMD... : protection must hold or come back within 45 s
    local name=$1; shift
    systemctl reset-failed blockadsd.service 2>/dev/null
    "$@" >/dev/null 2>&1
    local t; t=$(wait_for "${DNS_LIMIT:-5}" resolves_example)
    ok "$name: DNS resolves within ${DNS_LIMIT:-5}s" "${t}s" waited "$t"
    t=$(wait_for 45 reapplied)
    ok "$name: redirect in place within 45s" "${t}s, $(jumps) jump(s), NRestarts $(restarts)" reapplied
    ok "$name: exactly one OUTPUT jump" "$(jumps)" [ "$(jumps)" = 1 ]
    reapplied || journal blockadsd.service 10
}
docker_ready() {
    command -v docker >/dev/null || case $ID in
        fedora) pkg_install moby-engine ;; arch) pkg_install docker ;;
        *) pkg_install docker.io; command -v docker >/dev/null || pkg_install docker-cli ;; esac  # Debian 13: CLI split out
    systemctl start docker >/dev/null 2>&1 && docker info >/dev/null 2>&1
}

sec_coexist() {
    is_active && applied || restart_daemon
    if docker_ready; then
        info "docker" "$(docker --version)"
        reload_fault "systemctl restart docker" systemctl restart docker
    else report SKIP "docker restart" "docker not installable"; fi
    if command -v firewall-cmd >/dev/null || { [[ $ID == fedora ]] && pkg_install firewalld; }; then
        systemctl start firewalld >/dev/null 2>&1
        info "firewalld" "$(firewall-cmd --version 2>&1) backend=$(grep -E '^FirewallBackend' /etc/firewalld/firewalld.conf | cut -d= -f2)"
        reload_fault "firewall-cmd --reload" firewall-cmd --reload
        reload_fault "systemctl restart firewalld" systemctl restart firewalld
        # Leave firewalld as the distro ships it (enabled on Fedora); the bridge section uses it too.
    else report SKIP "firewalld reload" "not installed on $ID"; fi
    if [[ $ID == ubuntu || $ID == debian ]] && { command -v ufw >/dev/null || pkg_install ufw; }; then
        ufw allow 22/tcp >/dev/null; ufw --force enable >/dev/null
        reload_fault "ufw reload" ufw reload
        reload_fault "ufw disable + enable" bash -c 'ufw disable && ufw --force enable'
        ufw --force disable >/dev/null
    else report SKIP "ufw reload" "not on $ID"; fi
}

# --- port 153 taken by someone else -------------------------------------------
sec_porttaken() {
    systemctl stop blockadsd.service blockadsd.socket
    python3 -I -c '
import socket, time
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.bind(("127.0.0.1", 153))
t = socket.socket(); t.bind(("127.0.0.1", 153)); t.listen()
open("/run/bt-squatter.ready", "w").close(); time.sleep(120)' &
    local squatter=$!
    wait_for 5 test -e /run/bt-squatter.ready >/dev/null
    systemctl reset-failed blockadsd.service blockadsd.socket 2>/dev/null
    systemctl start blockadsd.socket >/run/start.out 2>&1; local rc=$?
    ok "port taken: blockadsd.socket fails to start" "rc=$rc $(systemctl is-active blockadsd.socket)" [ "$rc" != 0 ]
    systemctl start blockadsd.service >/dev/null 2>&1
    sleep 2
    ok "port taken: service not running" "$(systemctl is-active blockadsd.service)" bash -c '! systemctl is-active -q blockadsd.service'
    ok "port taken: no BLOCKADS_ applied" "$(fw_left) lines" reverted
    t=$(wait_for 5 resolves_example); ok "port taken: DNS resolves within 5s" "${t}s" waited "$t"
    kill "$squatter" 2>/dev/null; wait "$squatter" 2>/dev/null; rm -f /run/bt-squatter.ready
    systemctl reset-failed blockadsd.service blockadsd.socket 2>/dev/null
    systemctl start blockadsd.socket blockadsd.service
    local t; t=$(wait_for 20 applied)
    ok "port freed: service starts and applies" "${t}s" applied
}

# --- opt-in bridge redirect: containers -------------------------------------
# busybox nslookup through --dns NOWHERE: only our PREROUTING redirect can answer.
ctr_lookup() {  # ctr_lookup ENGINE NETWORK NAME -> first answer address or "-"
    timeout 40 "$1" run --rm --network "$2" --dns $NOWHERE docker.io/library/busybox:1.36 \
        nslookup -type=a "$3" $NOWHERE 2>&1 | awk '/^Address/ && $2 !~ /(#|:)53$/ {print $2; f=1; exit} END {if (!f) print "-"}'
}
set_bridge() {  # set_bridge JSON-LIST : the GUI's pkexec path, then the restart it asks for
    echo "{\"bridge_interfaces\": $1}" | $LIB/blockads-fw set-config >/run/setconfig.out 2>&1 || return 1
    restart_daemon
}
bridge_state() { python3 -I -c 'import json; b=json.load(open("/run/blockads-fw/state.json")).get("bridge") or {}; print(b.get("status","-"), ",".join(b.get("interfaces",[])))'; }
LAN_NS=btlan
lan_up() {
    ip netns del $LAN_NS 2>/dev/null
    ip netns add $LAN_NS && ip link add btlan0 type veth peer name eth0 netns $LAN_NS || return 1
    ip addr add 10.40.0.1/24 dev btlan0 && ip link set btlan0 up
    ip -n $LAN_NS addr add 10.40.0.2/24 dev eth0 && ip -n $LAN_NS link set eth0 up && ip -n $LAN_NS link set lo up
}
lan_down() { ip netns del $LAN_NS 2>/dev/null; ip link del btlan0 2>/dev/null; true; }
lan_q() { QX="ip netns exec $LAN_NS" Q_PORT=154 q 10.40.0.1 example.com "${1:-udp}"; }

sec_bridge() {
    is_active && applied || restart_daemon
    ok "bridge: set-config bridge_interfaces + restart" "$(tail -1 /run/setconfig.out 2>/dev/null)" \
        set_bridge '["docker0", "br-+", "podman+", "cni-podman+", "virbr+"]'
    ok "bridge: blockadsd-bridge.socket enabled and listening" "$(systemctl is-enabled blockadsd-bridge.socket)" \
        bash -c 'systemctl is-active -q blockadsd-bridge.socket && ss -Hlnu | grep -q ":154 "'
    info "bridge: helper state" "$(bridge_state)"
    blockadsctl block $BLOCKED >/dev/null
    local engines=() r
    if docker_ready; then engines+=(docker); else report SKIP "bridge: docker" "docker not installable or not starting"; fi
    { command -v podman >/dev/null || pkg_install podman; } && command -v podman >/dev/null && engines+=(podman)
    [[ ${#engines[@]} -gt 0 ]] || { report SKIP "bridge: containers" "neither docker nor podman installable"; }
    for e in "${engines[@]}"; do
        timeout 240 "$e" pull -q docker.io/library/busybox:1.36 >/dev/null 2>&1 \
            || { report SKIP "bridge: $e" "cannot pull busybox"; continue; }
        "$e" network rm btnet >/dev/null 2>&1; "$e" network create btnet >/dev/null 2>&1
        local net
        for net in bridge btnet; do
            [[ $e == podman && $net == bridge ]] && net=podman
            r=$(ctr_lookup "$e" $net $BLOCKED)
            ok "bridge: $e ($net) -> blocked domain 0.0.0.0" "$r" [ "$r" = 0.0.0.0 ]
            r=$(ctr_lookup "$e" $net example.com)
            ok "bridge: $e ($net) -> example.com answered" "$r" bash -c "[ '$r' != - ] && [ '$r' != 0.0.0.0 ]"
        done
    done
    info "bridge: helper state with containers" "$(bridge_state)"
    local st; st=$(blockadsctl status 2>&1 | grep '^Containers:')
    ok "bridge: blockadsctl status shows the bridge line" "$st" bash -c "[[ '$st' == *'Containers:   filtered ('* ]]"
    if [[ " ${engines[*]} " == *" docker "* ]]; then
        systemctl restart docker
        r=$(ctr_lookup docker bridge $BLOCKED)
        ok "bridge: after docker restart -> 0.0.0.0" "$r (jumps $(jumps))" [ "$r" = 0.0.0.0 ]
    fi
    if lan_up; then
        r=$(lan_q udp); ok "bridge: LAN -> host:154 (UDP) not answered" "$r" [ "$r" = TIMEOUT ]
        r=$(lan_q tcp); ok "bridge: LAN -> host:154 (TCP) refused" "$r" bash -c "[[ '$r' == ERROR* || '$r' == TIMEOUT ]]"
        iptables -w 5 -D INPUT -j BLOCKADS_IN 2>/dev/null; ip6tables -w 5 -D INPUT -j BLOCKADS_IN 2>/dev/null
        r=$(lan_q udp); ok "bridge: without BLOCKADS_IN, the ACL ignores the LAN" "$r" [ "$r" = TIMEOUT ]
        restart_daemon
        lan_down
    else report SKIP "bridge: LAN netns" "ip netns unavailable"; fi
    blockadsctl unblock $BLOCKED >/dev/null
    systemctl stop blockadsd.service blockadsd.socket
    ok "bridge: stop leaves no BLOCKADS_" "$(fw_left) lines" reverted
    systemctl start blockadsd.socket
    ok "bridge: set-config [] disables the socket" "$(systemctl is-enabled blockadsd-bridge.socket 2>&1)" \
        bash -c "echo '{\"bridge_interfaces\": []}' | $LIB/blockads-fw set-config && ! systemctl is-enabled -q blockadsd-bridge.socket"
    systemctl start blockadsd.service; wait_for 20 applied >/dev/null
    ok "bridge: off again, nothing on :154" "" bash -c '! ss -Hlnu | grep -q ":154 " && [ "$(iptables -t nat -S PREROUTING | grep -c BLOCKADS_BRIDGE)" = 0 ]'
    for e in "${engines[@]}"; do "$e" network rm btnet >/dev/null 2>&1; done
}

# --- libvirt guests and firewalld zones ------------------------------------------
# A "guest" is a netns whose veth is a member of the bridge: on the wire it is a
# VM's tap device, without needing nested KVM to boot one.
guest_up() {  # guest_up NS BRIDGE GUEST_CIDR GATEWAY
    guest_down "$1"
    ip netns add "$1" && ip link add "${1}h" type veth peer name eth0 netns "$1" || return 1
    ip link set "${1}h" master "$2" && ip link set "${1}h" up
    ip -n "$1" addr add "$3" dev eth0 && ip -n "$1" link set eth0 up && ip -n "$1" link set lo up &&
        ip -n "$1" route add default via "$4"
}
guest_blocked() { [ "$(guest_q "$1" $NOWHERE "$2")" = "NOERROR 0.0.0.0" ]; }
guest_down() { ip netns del "$1" 2>/dev/null; ip link del "${1}h" 2>/dev/null; true; }
guest_q() {  # guest_q NS SERVER NAME [udp|tcp] [PORT]
    QX="ip netns exec $1" Q_PORT=${5:-53} q "$2" "$3" "${4:-udp}"
}
BRIDGE_PATTERNS='["docker0", "br-+", "podman+", "cni-podman+", "virbr+", "btbr+"]'
virsh_net() { virsh -q -c network:///system "$@" 2>/dev/null || virsh -q -c qemu:///system "$@"; }

sec_libvirt() {
    case $ID in
        debian|ubuntu) pkg_install libvirt-daemon-system libvirt-clients dnsmasq-base ;;
        fedora) pkg_install libvirt-daemon-driver-network libvirt-daemon-config-network libvirt-client dnsmasq ;;
        arch) pkg_install libvirt dnsmasq ;;
    esac
    command -v virsh >/dev/null || { report FAIL "libvirt: install" "virsh not installable on $ID"; return; }
    systemctl start virtnetworkd.socket 2>/dev/null || systemctl start libvirtd 2>/dev/null
    systemctl start libvirtd 2>/dev/null
    if ! virsh_net net-info default >/dev/null 2>&1; then
        local xml; for xml in /usr/share/libvirt/networks/default.xml /etc/libvirt/qemu/networks/default.xml; do
            [[ -f $xml ]] && { virsh_net net-define "$xml" >/dev/null; break; }
        done
    fi
    virsh_net net-start default >/dev/null 2>&1
    local t; t=$(wait_for 20 ip -br addr show virbr0 up)
    ok "libvirt: default network up (virbr0, dnsmasq)" "$(ip -br -4 addr show virbr0 2>&1 | tr -s ' ') after ${t}s; libvirt $(virsh --version 2>&1)" \
        bash -c 'ip -4 addr show virbr0 | grep -q 192.168.122.1 && pgrep -f "dnsmasq.*default.conf" >/dev/null'
    ip -4 addr show virbr0 2>/dev/null | grep -q 192.168.122.1 || return
    info "libvirt: firewall backend" "$(grep -hE '^ *firewall_backend' /etc/libvirt/network.conf 2>/dev/null) $(nft list tables 2>/dev/null | grep -c libvirt) libvirt nft tables; firewalld $(systemctl is-active firewalld 2>&1) zone=$(firewall-cmd --get-zone-of-interface=virbr0 2>&1)"
    is_active && applied || restart_daemon
    guest_up btguest virbr0 192.168.122.250/24 192.168.122.1 || { report SKIP "libvirt: guest netns" "setup failed"; return; }
    local name=virt-bt-$RANDOM$RANDOM.example.com r
    blockadsctl block "$name" >/dev/null

    # 1. Through libvirt's dnsmasq (the guest's DHCP-given DNS): filtered with the redirect off,
    #    because dnsmasq's upstream queries leave the host through OUTPUT.
    set_bridge '[]'
    r=$(guest_q btguest 192.168.122.1 "$name")
    ok "libvirt: guest via dnsmasq, bridge redirect off -> blocked 0.0.0.0" "$r" [ "$r" = "NOERROR 0.0.0.0" ]
    r=$(guest_q btguest 192.168.122.1 "e$RANDOM.example.com")
    ok "libvirt: guest via dnsmasq -> other names resolve" "$r" [ "${r%% *}" = NOERROR -o "${r%% *}" = NXDOMAIN ]
    r=$(guest_q btguest $NOWHERE "$name")
    info "libvirt: guest direct to a server, redirect off (not filtered: documented)" "$r"

    # 2. A guest that ignores dnsmasq and asks a server directly: the opt-in redirect.
    ok "libvirt: bridge redirect on (virbr+)" "$(tail -1 /run/setconfig.out 2>/dev/null)" set_bridge "$BRIDGE_PATTERNS"
    r=$(guest_q btguest $NOWHERE "$name")
    ok "libvirt: guest direct, redirect on -> blocked 0.0.0.0" "$r" [ "$r" = "NOERROR 0.0.0.0" ]
    r=$(guest_q btguest $NOWHERE "$name" tcp)
    ok "libvirt: guest direct over TCP -> blocked 0.0.0.0" "$r" [ "$r" = "NOERROR 0.0.0.0" ]
    r=$(guest_q btguest $NOWHERE example.com)
    ok "libvirt: guest direct -> example.com answered" "$r" [ "${r%% *}" = NOERROR -a "$r" != "NOERROR 0.0.0.0" ]
    r=$(guest_q btguest 192.168.122.1 "$name" udp 154)
    ok "libvirt: guest -> host:154 directly is not answered (BLOCKADS_IN)" "$r" [ "$r" = TIMEOUT ]
    info "libvirt: helper state" "$(bridge_state)"

    # 3. libvirt rewrites its firewall rules on a restart of its network.
    virsh_net net-destroy default >/dev/null 2>&1; virsh_net net-start default >/dev/null 2>&1
    ip link set btguesth master virbr0 2>/dev/null; ip link set btguesth up
    t=$(wait_for 45 guest_blocked btguest "$name")
    ok "libvirt: after the network restart -> still 0.0.0.0" "${t}s (jumps $(jumps), PREROUTING first: $(iptables -w 5 -t nat -S PREROUTING | sed -n 2p))" waited "$t"
    systemctl restart libvirtd 2>/dev/null || systemctl restart virtnetworkd 2>/dev/null
    t=$(wait_for 45 guest_blocked btguest "$name")
    ok "libvirt: after a libvirt daemon restart -> still 0.0.0.0" "${t}s" waited "$t"

    blockadsctl unblock "$name" >/dev/null
    guest_down btguest
    set_bridge '[]'
    virsh_net net-destroy default >/dev/null 2>&1
    ok "libvirt: cleaned up, still applied" "" reapplied
}

sec_zones() {
    # Debian/Ubuntu start firewalld when it is installed: record the state before that.
    local was_active; was_active=$(systemctl is-active firewalld 2>/dev/null)
    command -v firewall-cmd >/dev/null || pkg_install firewalld
    command -v firewall-cmd >/dev/null || { report SKIP "firewalld zones" "firewalld not installable on $ID"; return; }
    systemctl start firewalld
    wait_for 30 bash -c '[ "$(firewall-cmd --state 2>/dev/null)" = running ]' >/dev/null
    info "zones: firewalld" "$(firewall-cmd --version 2>&1) backend=$(grep -E '^FirewallBackend' /etc/firewalld/firewalld.conf | cut -d= -f2) default=$(firewall-cmd --get-default-zone)"
    is_active && applied || restart_daemon
    # A test bridge with a guest, in each zone in turn.
    ip link del btbr0 2>/dev/null
    ip link add btbr0 type bridge && ip addr add 10.90.0.1/24 dev btbr0 && ip link set btbr0 up
    guest_up btzone btbr0 10.90.0.2/24 10.90.0.1 || { report SKIP "zones: guest" "setup failed"; return; }
    set_bridge "$BRIDGE_PATTERNS"
    local name=zone-bt-$RANDOM$RANDOM.example.com zone r t zones
    blockadsctl block "$name" >/dev/null
    zones=$(firewall-cmd --get-zones)
    for zone in public internal home work trusted libvirt docker external dmz block drop; do
        [[ " $zones " == *" $zone "* ]] || continue
        firewall-cmd -q --zone="$zone" --change-interface=btbr0
        t=$(wait_for 10 bash -c "[ \"\$(firewall-cmd --get-zone-of-interface=btbr0)\" = $zone ]")
        r=$(guest_q btzone $NOWHERE "$name")
        case $zone in
            block|drop)  # the user asked to refuse everything from this interface: either outcome is fine
                info "zones: $zone -> guest direct query (redirected)" "$r" ;;
            *)  ok "zones: $zone -> guest DNS redirected and filtered" "$r" [ "$r" = "NOERROR 0.0.0.0" ] ;;
        esac
        r=$(guest_q btzone 10.90.0.1 "$name" udp 154)
        ok "zones: $zone -> host:154 not answered directly" "$r" [ "$r" = TIMEOUT ]
    done
    firewall-cmd -q --zone="$(firewall-cmd --get-zone-of-interface=btbr0)" --remove-interface=btbr0 2>/dev/null
    reload_fault "zones: firewall-cmd --reload with the bridge redirect on" firewall-cmd --reload
    r=$(guest_q btzone $NOWHERE "$name")
    ok "zones: after the reload -> guest still filtered" "$r" [ "$r" = "NOERROR 0.0.0.0" ]
    blockadsctl unblock "$name" >/dev/null
    guest_down btzone; ip link del btbr0 2>/dev/null
    set_bridge '[]'
    [[ $was_active == active ]] || { systemctl stop firewalld; systemctl disable -q firewalld 2>/dev/null; }
    ok "zones: cleaned up, still applied" "" reapplied
}

# --- reboot (driven by run_system.sh: prereboot, reboot, afterboot) ----------------
# The units are enabled; the rules saved by the distro's persistence service
# while ours were applied come back at boot before blockadsd: they must not
# leave duplicates, and DNS must work throughout.
sec_prereboot() {
    is_active && applied || restart_daemon
    systemctl enable blockadsd.socket blockadsd.service >/dev/null 2>&1
    case $ID in
        debian|ubuntu)
            echo iptables-persistent iptables-persistent/autosave_v4 boolean false | debconf-set-selections
            echo iptables-persistent iptables-persistent/autosave_v6 boolean false | debconf-set-selections
            if pkg_install iptables-persistent; then
                netfilter-persistent save >/dev/null 2>&1
                ok "netfilter-persistent save with our rules applied" "$(grep -c BLOCKADS_ /etc/iptables/rules.v4) lines" \
                    grep -q BLOCKADS_ /etc/iptables/rules.v4
            else report SKIP "netfilter-persistent" "not installable"; fi ;;
        arch)
            iptables-save >/etc/iptables/iptables.rules && ip6tables-save >/etc/iptables/ip6tables.rules
            systemctl enable iptables.service ip6tables.service >/dev/null 2>&1
            ok "iptables.service rules saved with ours applied" "" grep -q BLOCKADS_ /etc/iptables/iptables.rules ;;
        *) info "saved rules" "no persistence service set up on $ID" ;;
    esac
    echo "$BLOCKED" >/var/tmp/bt-blocked
    blockadsctl block "$BLOCKED" >/dev/null
}
sec_afterboot() {
    local t; t=$(wait_for 60 applied)
    ok "after reboot: service active and applied" "${t}s $(systemctl is-active blockadsd.service)" applied
    ok "after reboot: exactly one OUTPUT jump" "$(jumps)" [ "$(jumps)" = 1 ]
    local dup; dup=$(iptables-save -t nat | grep -c '^:BLOCKADS_DNS')
    ok "after reboot: one BLOCKADS_DNS chain" "$dup" [ "$dup" = 1 ]
    local r; r=$(q $NOWHERE example.com)
    ok "after reboot: redirect answers" "$r" [ "${r%% *}" = NOERROR ]
    local name; name=$(cat /var/tmp/bt-blocked 2>/dev/null)
    r=$(q $NOWHERE "$name")
    ok "after reboot: custom rule kept" "$name $r" [ "$r" = "NOERROR 0.0.0.0" ]
    blockadsctl unblock "$name" >/dev/null 2>&1
    info "after reboot: boot order" "$(systemd-analyze critical-chain blockadsd.service 2>/dev/null | sed -n '4,6p' | tr -s ' ' | tr '\n' ';')"
    case $ID in
        debian|ubuntu) rm -f /etc/iptables/rules.v4 /etc/iptables/rules.v6 ;;
        arch) systemctl disable iptables.service ip6tables.service >/dev/null 2>&1
              : >/etc/iptables/iptables.rules; : >/etc/iptables/ip6tables.rules ;;
    esac
}

# --- systemd-resolved DoT -----------------------------------------------------
fw_partial() { python3 -I -c 'import json,sys; sys.exit(0 if json.load(open("/run/blockads-fw/state.json")).get("partial") else 1)' 2>/dev/null; }
getent_a() { getent ahostsv4 "$1" | awk 'NR==1{print $1}'; }
not_partial() { ! fw_partial; }
getent_is() { [ "$(getent_a "$1")" = "$2" ]; }
getent_any() { [ -n "$(getent_a "$1")" ]; }
resolved_dot() {  # resolved_dot MODE|"" : global DNSOverTLS, then restart resolved and blockadsd (apply reads it)
    if [[ -n $1 ]]; then
        mkdir -p /etc/systemd/resolved.conf.d
        printf '[Resolve]\nDNS=9.9.9.9#dns.quad9.net\nDNSOverTLS=%s\n' "$1" >/etc/systemd/resolved.conf.d/bt-dot.conf
    else rm -f /etc/systemd/resolved.conf.d/bt-dot.conf; fi
    systemctl restart systemd-resolved
    restart_daemon
    resolvectl flush-caches 2>/dev/null; true
}
bypass_dot_is() { [ "$(ctl_json "d.get('bypass', {}).get('resolved_dot')")" = "$1" ]; }
not() { ! "$@"; }
sec_resolveddot() {
    [[ $(systemctl is-active systemd-resolved) == active ]] || { report SKIP "resolved DoT" "systemd-resolved not running on $ID"; return; }
    is_active && applied || restart_daemon
    local name=dot-bt-$RANDOM$RANDOM.example.com r t
    blockadsctl block "$name" >/dev/null

    resolved_dot opportunistic
    ok "resolved DoT opportunistic: not partial (853 rejected for resolved too)" "" not_partial
    t=$(wait_for 15 getent_is "$name" 0.0.0.0)
    ok "resolved DoT opportunistic: getent blocked name -> 0.0.0.0 (fell back to :53, filtered)" "$(getent_a "$name") after ${t}s" [ "$(getent_a "$name")" = 0.0.0.0 ]
    info "resolved DoT opportunistic: resolvectl" "$(resolvectl status 2>/dev/null | grep -iE 'DNSOverTLS|Current DNS' | head -3 | tr -s ' ' | tr '\n' ';')"

    resolved_dot yes
    ok "resolved DoT strict: status partial (resolved's 853 exempt)" "$($LIB/blockads-fw status | grep partial)" fw_partial
    t=$(wait_for 10 bypass_dot_is yes)
    ok "resolved DoT strict: GetStatus bypass.resolved_dot = yes (warning)" "${t}s" bypass_dot_is yes
    ok "resolved DoT strict: blockadsctl status warns" "" bash -c 'blockadsctl status | grep -q "DNSOverTLS=yes"'
    t=$(wait_for 15 getent_any example.com)
    ok "resolved DoT strict: getent example.com works" "${t}s" test -n "$(getent_a example.com)"
    info "resolved DoT strict: blocked name through resolved (documented bypass)" "$(getent_a "$name")"
    r=$(q $NOWHERE "$name")
    ok "resolved DoT strict: other clients still filtered" "$r" [ "$r" = "NOERROR 0.0.0.0" ]

    resolved_dot ""
    ok "resolved DoT off again: not partial" "" not_partial
    ok "resolved DoT off again: no bypass warning" "$(ctl_json "d['bypass'].get('resolved_dot')")" not bypass_dot_is yes
    blockadsctl unblock "$name" >/dev/null
}

# --- clock set to 2001 (TLS "not yet valid") ----------------------------------
ctl_json() { blockadsctl status --json 2>/dev/null | python3 -I -c "import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1], {'d': d}))" "$1"; }
clock_suspect_is() { [ "$(ctl_json 'd["upstream"]["clock_suspect"]')" = "$1" ]; }
sec_clock() {
    is_active && applied || restart_daemon
    # Bash's $SECONDS follows the wall clock (it would jump back with the date); uptime does not.
    uptime_s() { local u; read -r u _ </proc/uptime; echo "${u%.*}"; }
    local real=$EPOCHSECONDS t0; t0=$(uptime_s); local r t
    timedatectl set-ntp false 2>/dev/null
    date -s '2001-06-01 12:00:00' >/dev/null
    blockadsctl block "clock-bt.example.com" >/dev/null
    r=$(q $NOWHERE "fresh-$RANDOM$RANDOM.example.com")
    info "clock 2001: first uncached query" "$r"
    t=$(wait_for 15 clock_suspect_is True)
    ok "clock 2001: status reports clock_suspect" "${t}s" clock_suspect_is True
    r=$(q $NOWHERE "fresh2-$RANDOM.example.com")
    ok "clock 2001: names still resolve (plain fallback)" "$r" bash -c "[[ '$r' == NOERROR* || '$r' == NXDOMAIN* ]]"
    r=$(q $NOWHERE example.com)
    ok "clock 2001: example.com resolves" "$r" [ "${r%% *}" = NOERROR ]
    r=$(q $NOWHERE clock-bt.example.com)
    ok "clock 2001: blocked name still 0.0.0.0" "$r" [ "$r" = "NOERROR 0.0.0.0" ]
    info "clock 2001: status line" "$(blockadsctl status 2>&1 | grep -E 'Warning|Last answer' | tr '\n' ';')"

    blockadsctl feature encrypted_only on >/dev/null 2>&1
    sleep 1
    r=$(q $NOWHERE "enc-$RANDOM$RANDOM.example.com")
    ok "clock 2001 + encrypted only: ordinary names fail (no plain DNS)" "$r" bash -c "[[ '$r' == SERVFAIL* || '$r' == TIMEOUT ]]"
    r=$(q $NOWHERE pool.ntp.org)
    ok "clock 2001 + encrypted only: NTP names resolve (clock rescue)" "$r" [ "${r%% *}" = NOERROR ]
    blockadsctl feature encrypted_only off >/dev/null 2>&1
    blockadsctl unblock clock-bt.example.com >/dev/null

    date -s "@$((real + $(uptime_s) - t0))" >/dev/null
    timedatectl set-ntp true 2>/dev/null
    ok "clock restored" "$(date -u +%FT%TZ)" [ "$(date +%Y)" -ge 2026 ]
    ok "clock restored: still active and applied" "" bash -c "systemctl is-active -q blockadsd.service && [ -s /run/blockads-fw/state.json ]"
    q $NOWHERE "after-$RANDOM.example.com" >/dev/null
    t=$(wait_for 30 clock_suspect_is False)
    info "clock restored: clock_suspect" "$(ctl_json 'd["upstream"]["clock_suspect"]') (${t}s)"
}

# --- suspend / resume (qemu S3, woken by the RTC) -------------------------------
sec_suspend() {
    is_active && applied || restart_daemon
    grep -qw mem /sys/power/state || { report SKIP "suspend" "no S3 (mem) in /sys/power/state"; return; }
    command -v rtcwake >/dev/null || { report SKIP "suspend" "rtcwake missing"; return; }
    local since; since=$(date '+%F %T')
    # Through logind (PrepareForSleep, as a laptop lid does), woken by an RTC alarm.
    # `rtcwake -m mem` alone writes /sys/power/state directly and logind never knows.
    rtcwake -m no -s 10 >/run/rtcwake.out 2>&1 && systemctl suspend; local rc=$?
    ok "suspend: systemctl suspend with an RTC wake alarm" "rc=$rc $(tail -1 /run/rtcwake.out)" [ "$rc" = 0 ]
    wait_for 40 bash -c "journalctl -b --since '$since' -o cat | grep -q -e 'PM: suspend exit' -e 'System returned from sleep'" >/dev/null
    info "suspend: kernel" "$(journalctl -k --since "$since" -o cat | grep -m2 -e 'PM: suspend entry' -e 'PM: suspend exit' | tr '\n' ';')"
    local t; t=$(wait_for 15 bash -c "journalctl -u blockadsd.service --since '$since' -o cat | grep -q 'resume: upstream policy reloaded'")
    ok "suspend: daemon saw the resume (logind PrepareForSleep)" "${t}s" \
        bash -c "journalctl -u blockadsd.service --since '$since' -o cat | grep -q 'resume: upstream policy reloaded'"
    t=$(wait_for 5 resolves_example)
    ok "suspend: DNS resolves after resume" "${t}s" resolves_example
    ok "suspend: still applied, redirect answers" "NRestarts $(restarts)" reapplied
}

# --- booted with ipv6.disable=1 (run_system.sh reboots between the two) -------------
sec_noipv6set() {
    local arg=ipv6.disable=1
    if command -v grubby >/dev/null; then grubby --update-kernel=ALL --args=$arg
    elif [[ -d /etc/default/grub.d ]] && command -v update-grub >/dev/null; then
        echo "GRUB_CMDLINE_LINUX_DEFAULT=\"\$GRUB_CMDLINE_LINUX_DEFAULT $arg\"" >/etc/default/grub.d/99-bt-noipv6.cfg && update-grub 2>/dev/null
    elif [[ -f /etc/default/grub ]] && command -v grub-mkconfig >/dev/null; then
        sed -i "s/^GRUB_CMDLINE_LINUX_DEFAULT=\"/&$arg /" /etc/default/grub && grub-mkconfig -o /boot/grub/grub.cfg 2>/dev/null
    else report SKIP "ipv6.disable=1" "no known boot loader config"; return; fi
    ok "ipv6.disable=1 added to the kernel command line" "" true
}
sec_noipv6() {
    if [[ -d /proc/sys/net/ipv6 ]]; then report SKIP "ipv6.disable=1 boot" "IPv6 still present: $(cat /proc/cmdline)"; return; fi
    local t; t=$(wait_for 60 applied)
    ok "no IPv6: service active and applied" "${t}s" applied
    ok "no IPv6: blockadsd-ipv6.socket skipped by its condition" "$(systemctl is-active blockadsd-ipv6.socket)" \
        bash -c '! systemctl is-active -q blockadsd-ipv6.socket'
    local fam; fam=$(python3 -I -c 'import json; f=json.load(open("/run/blockads-fw/state.json"))["families"]; print(f["ipv4"]["status"], f.get("ipv6",{}).get("status"))')
    ok "no IPv6: ipv4 active, ipv6 not applied" "$fam" bash -c "[[ '$fam' == 'active '* && '$fam' != *' active' ]]"
    local r; r=$(q $NOWHERE example.com)
    ok "no IPv6: redirect answers" "$r" [ "${r%% *}" = NOERROR ]
    ok "no IPv6: blockadsctl status" "$(blockadsctl status 2>&1 | grep Interception)" blockadsctl status
    local before; before=$(restarts)
    sleep 20
    ok "no IPv6: no restarts from the health checks over 20s" "NRestarts $before -> $(restarts)" [ "$(restarts)" = "$before" ]
    info "no IPv6: blockads-fw status" "$($LIB/blockads-fw status | tr '\n' ' ')"
    # Undo for a kept VM; takes effect on the next boot.
    if command -v grubby >/dev/null; then grubby --update-kernel=ALL --remove-args=ipv6.disable=1
    elif [[ -f /etc/default/grub.d/99-bt-noipv6.cfg ]]; then rm -f /etc/default/grub.d/99-bt-noipv6.cfg; update-grub 2>/dev/null
    else sed -i 's/ipv6.disable=1 //' /etc/default/grub; grub-mkconfig -o /boot/grub/grub.cfg 2>/dev/null; fi
}

# --- NetworkManager simulations: captive portal, WireGuard split DNS ------------
# A peer lives in its own netns behind a veth; NM manages our end.
nm_ready() {
    command -v nmcli >/dev/null || return 1
    systemctl start NetworkManager 2>/dev/null
    local _; for _ in $(seq 25); do nmcli -t general status >/dev/null 2>&1 && return 0; sleep 0.2; done
    return 1
}
peer_ns() {  # peer_ns NS HOST_IF HOST_CIDR PEER_CIDR : veth to a fresh netns; our end left for NM
    ip netns del "$1" 2>/dev/null; ip link del "$2" 2>/dev/null
    ip netns add "$1" && ip link add "$2" type veth peer name eth0 netns "$1" || return 1
    ip -n "$1" addr add "$4" dev eth0 && ip -n "$1" link set eth0 up && ip -n "$1" link set lo up
}
corp_answers() { [ "$(q $NOWHERE "h$RANDOM$RANDOM.corp.bt.test")" = "NOERROR 10.60.0.99" ]; }
corp_gone() { ! corp_answers; }
nm_manage() {  # nm_manage IFACE... : Ubuntu's NM leaves every device unmanaged unless netplan lists it
    local base=/usr/lib/NetworkManager/conf.d/10-globally-managed-devices.conf value i
    [[ -f $base ]] || return 0
    value=$(sed -n 's/^unmanaged-devices=//p' "$base")
    for i in "$@"; do value+=",except:interface-name:$i"; done
    printf '[keyfile]\nunmanaged-devices=%s\n' "$value" >/etc/NetworkManager/conf.d/99-bt-managed.conf
}
status_upstream() { ctl_json "d['upstream'].get('$1')"; }
captive_is() { [ "$(status_upstream captive)" = "$1" ]; }

sec_captive() {
    nm_ready || { report SKIP "captive portal" "NetworkManager not available"; return; }
    is_active && applied || restart_daemon
    peer_ns btisp btwan0 10.50.0.2/24 10.50.0.1/24 || { report SKIP "captive portal" "netns setup failed"; return; }
    mkdir -p /run/btportal && echo portal >/run/btportal/mode
    # The portal: DNS answers its own name; HTTP redirects until "logged in".
    # Like most portals, its DNS answers every name with the portal's address.
    ip netns exec btisp python3 -I "$VM/fakedns.py" 10.50.0.1 53 '*=10.50.0.1' >/dev/null 2>&1 &
    local dns_pid=$!
    ip netns exec btisp python3 -I -c '
import http.server
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        online = open("/run/btportal/mode").read().strip() == "online"
        if online:
            self.send_response(200); self.end_headers(); self.wfile.write(b"blockads online")
        else:
            self.send_response(302); self.send_header("Location", "http://portal.bt.test/login"); self.end_headers()
    def log_message(self, *a): pass
http.server.HTTPServer(("10.50.0.1", 80), H).serve_forever()' &
    local http_pid=$!
    printf '[connectivity]\nenabled=true\nuri=http://10.50.0.1/check\nresponse=blockads online\ninterval=5\n' \
        >/etc/NetworkManager/conf.d/99-bt-connectivity.conf
    nm_manage btwan0 btwg
    systemctl restart NetworkManager; nm_ready
    nmcli connection delete btwan >/dev/null 2>&1
    nmcli device set btwan0 managed yes 2>/dev/null
    nmcli connection add type ethernet ifname btwan0 con-name btwan ipv4.method manual ipv4.addresses 10.50.0.2/24 \
        ipv4.gateway 10.50.0.1 ipv4.route-metric 20000 ipv4.dns 10.50.0.1 ipv6.method disabled >/dev/null &&
        nmcli connection up btwan >/dev/null 2>&1
    nmcli networking connectivity check >/dev/null 2>&1
    local t; t=$(wait_for 30 captive_is True)
    info "captive: NM connectivity" "$(nmcli -t -f CONNECTIVITY general) (device btwan0: $(nmcli -g GENERAL.IP4-CONNECTIVITY device show btwan0 2>/dev/null))"
    ok "captive: daemon reports a captive portal" "${t}s" captive_is True
    info "captive: upstream tiers" "$(ctl_json "[t['name'] for t in d['upstream'].get('tiers', [])]")"
    local r; r=$(q $NOWHERE example.com)
    ok "captive: example.com resolves" "$r" [ "${r%% *}" = NOERROR ]
    blockadsctl block captive-bt.example.com >/dev/null
    r=$(q $NOWHERE captive-bt.example.com)
    ok "captive: blocked name still 0.0.0.0" "$r" [ "$r" = "NOERROR 0.0.0.0" ]
    r=$(q $NOWHERE portal.bt.test)
    info "captive: portal.bt.test (network DNS)" "$r"
    # Leave the portal network. ("Logging in" cannot be simulated where NM also
    # manages the main NIC: its check against the fake URI always fails.)
    nmcli connection delete btwan >/dev/null 2>&1
    rm -f /etc/NetworkManager/conf.d/99-bt-connectivity.conf; systemctl restart NetworkManager
    t=$(wait_for 30 captive_is False)
    ok "captive: portal network gone -> back to the configured upstreams" "${t}s ($(nmcli -t -f CONNECTIVITY general 2>&1))" captive_is False
    ok "captive: still applied, no restart" "NRestarts $(restarts)" reapplied
    blockadsctl unblock captive-bt.example.com >/dev/null
    kill $dns_pid $http_pid 2>/dev/null; wait $dns_pid $http_pid 2>/dev/null
    ip netns del btisp 2>/dev/null; ip link del btwan0 2>/dev/null; true
}

split_has() { [ "$(ctl_json "any(x['domain'] == '$1' and x['vpn'] for x in d['network']['split_dns'])")" = True ]; }
sec_wireguard() {
    nm_ready || { report SKIP "WireGuard split DNS" "NetworkManager not available"; return; }
    command -v wg >/dev/null || pkg_install wireguard-tools
    command -v wg >/dev/null && modprobe wireguard 2>/dev/null || { report SKIP "WireGuard split DNS" "no wg / module"; return; }
    is_active && applied || restart_daemon
    peer_ns btvpn btvpnu0 10.70.0.1/24 10.70.0.2/24 || { report SKIP "WireGuard" "netns setup failed"; return; }
    nmcli device set btvpnu0 managed no 2>/dev/null
    ip addr add 10.70.0.1/24 dev btvpnu0; ip link set btvpnu0 up
    local hk pk; hk=$(wg genkey); pk=$(wg genkey)
    # The VPN server and its DNS, inside the netns.
    ip -n btvpn link add wg0 type wireguard
    ip netns exec btvpn wg set wg0 private-key <(echo "$pk") listen-port 51820 \
        peer "$(echo "$hk" | wg pubkey)" allowed-ips 10.60.0.2/32
    ip -n btvpn addr add 10.60.0.1/24 dev wg0; ip -n btvpn link set wg0 up
    ip netns exec btvpn python3 -I "$VM/fakedns.py" 10.60.0.1 53 corp.bt.test=10.60.0.99 >/dev/null 2>&1 &
    local dns_pid=$!
    mkdir -p /run/btwg
    cat >/run/btwg/btwg.conf <<EOF
[Interface]
PrivateKey = $hk
Address = 10.60.0.2/24
DNS = 10.60.0.1

[Peer]
PublicKey = $(echo "$pk" | wg pubkey)
AllowedIPs = 10.60.0.0/24
Endpoint = 10.70.0.2:51820
EOF
    nmcli connection delete btwg >/dev/null 2>&1
    nm_manage btwan0 btwg; [[ -f /etc/NetworkManager/conf.d/99-bt-managed.conf ]] && { systemctl restart NetworkManager; nm_ready; }
    nmcli connection import type wireguard file /run/btwg/btwg.conf >/dev/null &&
        nmcli connection modify btwg ipv4.dns-search '~corp.bt.test' ipv4.never-default yes ipv6.method disabled &&
        nmcli connection up btwg >/dev/null 2>&1
    ok "wireguard: NM connection up" "$(nmcli -g GENERAL.STATE connection show btwg 2>&1)" \
        bash -c '[ "$(nmcli -g GENERAL.STATE connection show btwg)" = activated ]'
    local t r
    t=$(wait_for 20 corp_answers)
    info "wireguard: upstream tiers" "$(ctl_json "[t['name'] for t in d['upstream'].get('tiers', [])]") routes=$(ctl_json "d['upstream'].get('routes')")"
    r=$(q $NOWHERE host.corp.bt.test)
    ok "wireguard: split DNS name answered by the VPN's server" "$r after ${t}s" [ "$r" = "NOERROR 10.60.0.99" ]
    ok "wireguard: GetStatus network.split_dns lists corp.bt.test (Networks page)" \
        "$(ctl_json "[(x['domain'], x['interface'], x['vpn']) for x in d['network']['split_dns']]")" split_has corp.bt.test
    blockadsctl block ads.corp.bt.test >/dev/null
    r=$(q $NOWHERE ads.corp.bt.test)
    ok "wireguard: VPN names are still filtered" "$r" [ "$r" = "NOERROR 0.0.0.0" ]
    r=$(q $NOWHERE example.com)
    ok "wireguard: other names still resolve" "$r" [ "${r%% *}" = NOERROR ]
    blockadsctl unblock ads.corp.bt.test >/dev/null
    nmcli connection down btwg >/dev/null 2>&1
    t=$(wait_for 15 corp_gone)
    ok "wireguard: down -> the VPN route is gone" "${t}s" corp_gone
    nmcli connection delete btwg >/dev/null 2>&1
    kill $dns_pid 2>/dev/null; wait $dns_pid 2>/dev/null
    ip netns del btvpn 2>/dev/null; ip link del btvpnu0 2>/dev/null; rm -rf /run/btwg
    rm -f /etc/NetworkManager/conf.d/99-bt-managed.conf; systemctl restart NetworkManager; true
}

# --- trusted networks and bypass warnings --------------------------------------
net_json() { ctl_json "(d.get('network') or {}).get('$1', '')"; }
protection_is() { [ "$(ctl_json "d['protection']['state']")" = "$1" ]; }
first_tier_is() { [ "$(ctl_json "(d['upstream'].get('tiers') or [{}])[0].get('name')")" = "$1" ]; }
not_first_tier() { ! first_tier_is "$1"; }
active_tier_is() { [ "$(ctl_json "(d['upstream'].get('active') or {}).get('tier')")" = "$1" ]; }
has_primary() { [ -n "$(net_json uuid)" ]; }
doh_seen() { [ "$(ctl_json "d.get('bypass', {}).get('doh_lookups', 0) > 0")" = True ]; }
networks_cleanup() {
    local u; for u in $(blockadsctl networks list --json 2>/dev/null | python3 -I -c 'import json,sys; print(" ".join(n["uuid"] for n in json.load(sys.stdin)))'); do
        blockadsctl networks remove "$u" >/dev/null 2>&1
    done
    nmcli connection delete bthome >/dev/null 2>&1
    [[ -n ${HOME_DNS_PID:-} ]] && { kill "$HOME_DNS_PID" 2>/dev/null; wait "$HOME_DNS_PID" 2>/dev/null; }
    ip netns del bthome 2>/dev/null; ip link del bthome0 2>/dev/null
    if [[ -f /etc/NetworkManager/conf.d/99-bt-managed.conf ]]; then
        rm -f /etc/NetworkManager/conf.d/99-bt-managed.conf; systemctl restart NetworkManager
    fi
    true
}
sec_networks() {
    nm_ready || { report SKIP "trusted networks" "NetworkManager not available"; return; }
    is_active && applied || restart_daemon
    local kind=main uuid t r name=trusted-bt-$RANDOM$RANDOM.example.com
    HOME_DNS_PID=""
    if ! has_primary; then
        # NetworkManager owns no default route here (ifupdown, networkd): a veth "home" network
        # with a high-metric gateway becomes its primary connection, while the VM's traffic
        # keeps using the main NIC. Its DNS answers every name with 10.80.0.53.
        kind=veth
        peer_ns bthome bthome0 10.80.0.2/24 10.80.0.1/24 || { report SKIP "trusted networks" "netns setup failed"; return; }
        ip netns exec bthome python3 -I "$VM/fakedns.py" 10.80.0.1 53 '*=10.80.0.53' >/dev/null 2>&1 &
        HOME_DNS_PID=$!
        nm_manage bthome0; [[ -f /etc/NetworkManager/conf.d/99-bt-managed.conf ]] && { systemctl restart NetworkManager; nm_ready; }
        nmcli connection delete bthome >/dev/null 2>&1
        nmcli device set bthome0 managed yes 2>/dev/null
        nmcli connection add type ethernet ifname bthome0 con-name bthome ipv4.method manual ipv4.addresses 10.80.0.2/24 \
            ipv4.gateway 10.80.0.1 ipv4.route-metric 20000 ipv4.dns 10.80.0.1 ipv6.method disabled >/dev/null &&
            nmcli connection up bthome >/dev/null 2>&1
        wait_for 20 has_primary >/dev/null
    fi
    uuid=$(net_json uuid)
    info "networks: primary connection ($kind)" "$(net_json name) type=$(net_json type) source=$(net_json source)"
    ok "networks: daemon reports NM's primary connection" "uuid=$uuid nm=$(nmcli -t -g UUID connection show --active 2>/dev/null | tr '\n' ' ')" has_primary
    [[ -n $uuid ]] || { networks_cleanup; return; }
    blockadsctl block "$name" >/dev/null

    # pause mode
    blockadsctl networks add --mode pause >/dev/null
    t=$(wait_for 10 protection_is trusted)
    ok "networks: pause mode -> protection state trusted" "${t}s" protection_is trusted
    r=$(q $NOWHERE "$name")
    ok "networks: pause mode -> blocked name answered unfiltered" "$r" [ "${r%% *}" != ERROR -a "$r" != "NOERROR 0.0.0.0" -a "$r" != TIMEOUT ]
    ok "networks: blockadsctl status says so" "$(blockadsctl status | grep -E '^(Protection|Network):' | tr '\n' ' ')" \
        bash -c 'blockadsctl status | grep -q "paused on a trusted network"'
    ok "networks: still applied (no restart, rules kept)" "NRestarts $(restarts)" applied

    # network_dns mode (replaces the entry)
    blockadsctl networks add --mode network_dns >/dev/null
    t=$(wait_for 10 first_tier_is trusted)
    ok "networks: network_dns mode -> 'trusted' tier first" "${t}s tiers=$(ctl_json "[x['name'] for x in d['upstream'].get('tiers', [])]")" first_tier_is trusted
    ok "networks: network_dns mode -> protection active" "" protection_is active
    r=$(q $NOWHERE "$name")
    ok "networks: network_dns mode -> blocked name still 0.0.0.0" "$r" [ "$r" = "NOERROR 0.0.0.0" ]
    r=$(q $NOWHERE "n$RANDOM$RANDOM.example.com")
    # The network DNS is every default-route link's servers (the main NIC's first), so
    # which one answers varies; the tier of the last answer tells.
    ok "networks: network_dns mode -> answered by the network's DNS (tier trusted)" \
        "$r from $(ctl_json "(d['upstream'].get('active') or {}).get('label')"); trusted tier: $(ctl_json "d['upstream']['tiers'][0]['upstreams']")" \
        active_tier_is trusted

    # untrusted again
    blockadsctl networks remove "$uuid" >/dev/null
    t=$(wait_for 10 not_first_tier trusted)
    ok "networks: removed -> configured upstreams again" "${t}s" not_first_tier trusted

    # leaving a trusted network (only where the test network can go away safely)
    if [[ $kind == veth ]]; then
        blockadsctl networks add "$uuid" --name bthome --mode pause >/dev/null
        wait_for 10 protection_is trusted >/dev/null
        nmcli connection down bthome >/dev/null 2>&1
        t=$(wait_for 15 protection_is active)
        ok "networks: leaving the trusted network -> filtering again" "${t}s" protection_is active
        r=$(q $NOWHERE "$name")
        ok "networks: blocked name 0.0.0.0 after leaving" "$r" [ "$r" = "NOERROR 0.0.0.0" ]
        blockadsctl networks remove "$uuid" >/dev/null
    fi
    blockadsctl unblock "$name" >/dev/null

    # browser DoH bypass warning: a lookup of a DoH server while the DoH block is off
    q $NOWHERE dns.google >/dev/null
    t=$(wait_for 5 doh_seen)
    ok "networks: DoH server lookup counted (bypass warning)" "${t}s" doh_seen
    ok "networks: blockadsctl status warns about DoH" "" bash -c 'blockadsctl status | grep -q "DNS-over-HTTPS server was looked up"'
    networks_cleanup
    ok "networks: cleaned up, still applied" "" reapplied
}

# --- the GUI against the installed daemon -------------------------------------
gui_run() {  # gui_run PHASE : gui_vm.py as alice in her session; its PASS/FAIL lines count here
    local out rc
    out=$(in_session env -i HOME=/home/alice USER=alice PATH=/usr/bin:/bin LANG=C.UTF-8 QT_QPA_PLATFORM=offscreen \
          XDG_RUNTIME_DIR=/run/user/$(id -u alice) DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$(id -u alice)/bus \
          timeout 300 python3 -I "$VM/gui_vm.py" "$1" 2>&1); rc=$?
    echo "$out" | grep -E '^(PASS|FAIL|INFO|SKIP) ' | sed "s/^\(....\) *\[gui\]/\1  [$ID${VERSION_ID:+$VERSION_ID}] gui:/"
    FAILURES=$((FAILURES + $(echo "$out" | grep -c '^FAIL')))
    if [[ $rc -ne 0 ]] && ! echo "$out" | grep -q '^FAIL'; then
        report FAIL "gui $1: script failed" "rc=$rc $(echo "$out" | tail -3 | tr '\n' ' ' | cut -c1-300)"
    fi
}
sec_gui() {
    case $ID in
        debian|ubuntu) pkg_install python3-pyqt6 qt6-qpa-plugins ;;
        fedora) pkg_install python3-pyqt6 ;;
        arch) pkg_install python-pyqt6 ;;
    esac
    if ! python3 -I -c 'import PyQt6.QtWidgets, PyQt6.QtDBus' 2>/dev/null; then
        report FAIL "gui: PyQt6 from the distribution" "not installable"; return
    fi
    info "gui: PyQt6" "$(python3 -I -c 'from PyQt6.QtCore import PYQT_VERSION_STR as p, QT_VERSION_STR as q; print(p, "Qt", q)')"
    if ! alice_session; then report SKIP "gui: no local session for alice" ""; return; fi
    chvt 1; sleep 0.5
    is_active || { systemctl start blockadsd.service; wait_for 20 applied >/dev/null; }
    gui_run main
    blockadsctl unblock gui-bt.example.com >/dev/null 2>&1
    systemctl stop blockadsd.service
    gui_run start
    wait_for 20 applied >/dev/null
    ok "gui: after the GUI's start the redirect is applied" "" applied
}

for s in "$@"; do
    echo "--- $s ($((SECONDS - T0))s)"
    "sec_$s"
done
exit $(( FAILURES > 125 ? 125 : FAILURES ))
