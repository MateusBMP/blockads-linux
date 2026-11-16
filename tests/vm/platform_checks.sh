#!/usr/bin/env bash
# Platform checks that need a real (disposable) machine: run as root inside a VM
# created by tests/vm/vm.sh, with the repository copied to /opt/blockads and
# tests/vm/provision.sh already run. tests/vm/run_platform.sh drives it.
#
# Usage: platform_checks.sh SECTION...
#   interception tests/netns/interception.sh on this distro's iptables (nft + legacy)
#   unit      the unit suite with the distro's Python and packages
#   sni       httpx sni_hostname over HTTP/2 (live, Quad9) + dev daemon via DoH
#   sandbox   socket-activated daemon under the planned hardening, + gated directives
#   freebind  [::1]:153 with FreeBind=yes while IPv6 is disabled by sysctl
#   nm        NetworkManager D-Bus readable by a system user
#   polkit    CheckAuthorization from user 'blockads' (inside the sandbox)
#   pinned    conntrack-pinned DNS flows across apply/revert
#   nftflush  `nft flush ruleset` vs our nft / legacy rules
#   docker | firewalld | ufw   coexistence
#
# Every line is PASS/FAIL/INFO/SKIP; exit status = number of FAILs (max 125).
set -u
SRC=/opt/blockads
VM=$SRC/tests/vm
PROBE="python3 -I $SRC/tests/netns/dnsprobe.py"
export PYTHONPATH=$SRC/src
FAILURES=0
. /etc/os-release

report() {
    printf '%-5s [%s] %-58s %s\n' "$1" "$ID${VERSION_ID:-}" "$2" "${3:-}"
    [[ $1 == FAIL ]] && FAILURES=$((FAILURES + 1))
    return 0
}
expect() {  # expect NAME WANT_FIRST_WORD CMD...
    local name=$1 want=$2; shift 2
    local out; out="$("$@" 2>&1 | tail -1)"
    if [[ ${out%% *} == "$want" ]]; then report PASS "$name" "$out"; else report FAIL "$name" "want $want, got: $out"; fi
}
info() { report INFO "$1" "$2"; }

# --- firewall stand-in for blockads-fw: the interception rule set, real netns ---
DAEMON_UID=$(id -u blockads)
PORT=153
PROBE_PORT=9
fw_render() {  # fw_render 4|6 WITH_DNS_JUMP WITH_OUT_JUMP
    local lo=127.0.0.1/32 bypass="-d 100.100.100.100/32 -j RETURN" icmp=icmp-port-unreachable
    [[ $1 == 6 ]] && { lo=::1/128; bypass="-d fd7a:115c:a1e0::53/128 -j RETURN"; icmp=icmp6-port-unreachable; }
    cat <<EOF
*nat
:BLOCKADS_DNS - [0:0]
-A BLOCKADS_DNS -d $lo -p udp -m udp --dport $PROBE_PORT -m comment --comment "blockads-linux probe; runtime-only, do not persist" -j REDIRECT --to-ports $PORT
-A BLOCKADS_DNS -d $lo -p tcp -m tcp --dport $PROBE_PORT -j REDIRECT --to-ports $PORT
-A BLOCKADS_DNS -m owner --uid-owner $DAEMON_UID -j RETURN
-A BLOCKADS_DNS -m addrtype --dst-type LOCAL -j RETURN
-A BLOCKADS_DNS $bypass
-A BLOCKADS_DNS -p udp -m udp --dport 53 -j REDIRECT --to-ports $PORT
-A BLOCKADS_DNS -p tcp -m tcp --dport 53 -j REDIRECT --to-ports $PORT
${2:+-I OUTPUT 1 -j BLOCKADS_DNS}
COMMIT
EOF
    cat <<EOF
*filter
:BLOCKADS_OUT - [0:0]
-A BLOCKADS_OUT -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN
-A BLOCKADS_OUT -m owner --uid-owner $DAEMON_UID -j RETURN
-A BLOCKADS_OUT -m addrtype --dst-type LOCAL -j RETURN
-A BLOCKADS_OUT -p tcp -m tcp --dport 853 -j REJECT --reject-with tcp-reset
-A BLOCKADS_OUT -p udp -m udp --dport 853 -j REJECT --reject-with $icmp
${3:+-I OUTPUT 1 -j BLOCKADS_OUT}
COMMIT
EOF
}
fw_jumps() { "$1" -w 5 -t "$2" -S OUTPUT 2>/dev/null | grep -cx -- "-A OUTPUT -j $3"; }
fw_apply() {  # fw_apply nft|legacy  (one restore per table and family)
    local b=$1 fam ipt rc=0
    for fam in 4 6; do
        ipt=iptables-$b; [[ $fam == 6 ]] && ipt=ip6tables-$b
        local dj="" oj=""
        [[ $(fw_jumps "$ipt" nat BLOCKADS_DNS) -eq 0 ]] && dj=1
        [[ $(fw_jumps "$ipt" filter BLOCKADS_OUT) -eq 0 ]] && oj=1
        fw_render $fam "$dj" "$oj" | awk '/^\*nat/,/^COMMIT/' | "$ipt-restore" -w 5 --noflush || rc=1
        fw_render $fam "$dj" "$oj" | awk '/^\*filter/,/^COMMIT/' | "$ipt-restore" -w 5 --noflush || rc=1
    done
    return $rc
}
fw_revert() {  # fw_revert nft|legacy
    local b=$1 ipt pair table chain
    for ipt in iptables-$b ip6tables-$b; do
        for pair in nat:BLOCKADS_DNS filter:BLOCKADS_OUT; do
            table=${pair%%:*}; chain=${pair#*:}
            for _ in $(seq 16); do
                "$ipt" -w 5 -t "$table" -C OUTPUT -j "$chain" 2>/dev/null || break
                "$ipt" -w 5 -t "$table" -D OUTPUT -j "$chain"
            done
            "$ipt" -w 5 -t "$table" -F "$chain" 2>/dev/null
            "$ipt" -w 5 -t "$table" -X "$chain" 2>/dev/null
        done
    done
    return 0
}
fw_left() { { iptables-nft-save; ip6tables-nft-save; iptables-legacy-save; ip6tables-legacy-save; } 2>/dev/null | grep -c BLOCKADS_; }

RESPONDER_PID=""
start_local_responder() {  # the "daemon" on 127.0.0.1/::1:153, tag=local
    $PROBE serve --tag local --port $PORT 127.0.0.1 ::1 >/run/local-responder.log 2>&1 &
    RESPONDER_PID=$!
    for _ in $(seq 50); do grep -q READY /run/local-responder.log 2>/dev/null && return 0; sleep 0.1; done
    return 1
}
stop_local_responder() { [[ -n $RESPONDER_PID ]] && kill "$RESPONDER_PID" 2>/dev/null; wait "$RESPONDER_PID" 2>/dev/null; RESPONDER_PID=""; }

FAR_UP=""
far_up() {  # a "remote" resolver at 192.0.2.1 / 2001:db8::1 in its own netns, tag=far
    [[ -n $FAR_UP ]] && return 0
    ip netns add far
    ip link add vfar type veth peer name veth0 netns far
    ip addr add 192.0.2.2/24 dev vfar; ip -6 addr add 2001:db8::2/64 dev vfar nodad; ip link set vfar up
    ip -n far addr add 192.0.2.1/24 dev veth0; ip -n far -6 addr add 2001:db8::1/64 dev veth0 nodad
    ip -n far link set veth0 up; ip -n far link set lo up
    ip netns exec far $PROBE serve --tag far --port 53 192.0.2.1 2001:db8::1 >/run/far.log 2>&1 &
    for _ in $(seq 50); do grep -q READY /run/far.log 2>/dev/null && break; sleep 0.1; done
    FAR_UP=1
}
far_down() { [[ -n $FAR_UP ]] || return 0; ip netns pids far | xargs -r kill; ip netns del far; ip link del vfar 2>/dev/null; FAR_UP=""; }
remove_units() {  # the spike units of write_units; in /etc they would shadow the real ones
    local u had=""
    for u in blockadsd.service blockadsd.socket blockadsd-ipv6.socket; do
        [[ -e /etc/systemd/system/$u ]] || continue
        had=1
        systemctl stop "$u" 2>/dev/null
        rm -f "/etc/systemd/system/$u"
    done
    [[ -n $had ]] && { systemctl daemon-reload; systemctl reset-failed 2>/dev/null; }
    return 0
}
# On a CI runner tests/vm/system_checks.sh runs next on the same machine.
cleanup() { stop_local_responder; far_down; fw_revert nft; fw_revert legacy; remove_units; }
trap cleanup EXIT

# systemd-run with output to a file: --pipe hands the SSH session's pipes to the
# service, which SELinux (Fedora) denies to dbus-broker.
sandboxed() {
    rm -f /run/sandboxed.out
    systemd-run --wait --quiet -p StandardOutput=truncate:/run/sandboxed.out -p StandardError=inherit "$@" \
        >/dev/null 2>/run/sandboxed.err || cat /run/sandboxed.err
    cat /run/sandboxed.out 2>/dev/null
}
as_alice() { setpriv --reuid=alice --regid=alice --init-groups "$@"; }

# --- sections -------------------------------------------------------------------
sec_interception() {
    local log=/run/interception.log
    bash "$SRC/tests/netns/interception.sh" >"$log" 2>&1; local rc=$?
    grep -E '^=== backend' "$log" | while read -r line; do info "interception backend" "${line#=== backend: }"; done
    grep -E '^(FAIL|SKIP)' "$log" | while read -r line; do info "interception line" "$line"; done
    grep -E '^INFO +\[.*S2' "$log" | while read -r line; do info "interception S2" "${line##*  }"; done
    local pass; pass=$(grep -c '^PASS' "$log")
    if [[ $rc -eq 0 ]]; then report PASS "interception.sh" "$pass checks passed"; else report FAIL "interception.sh" "rc=$rc, $pass passed; see $log"; fi
    if [[ $rc -ne 0 && $pass -eq 0 ]]; then  # it never got going: show why (the log stays on the machine)
        head -5 "$log" | while IFS= read -r line; do info "interception log" "$line"; done
        info "interception: /etc/subuid" "$(head -3 /etc/subuid 2>&1 | tr '\n' ' ')"
        info "interception: unshare" "$(unshare --version 2>&1 | head -1); $(unshare --map-auto --map-root-user --net true 2>&1 && echo map-auto ok)"
        info "interception: userns sysctls" "$(sysctl -n kernel.apparmor_restrict_unprivileged_userns user.max_user_namespaces 2>&1 | tr '\n' ' ')"
    fi
    grep -q '^SKIP.*legacy' "$log" && report FAIL "legacy backend exercised" "skipped" || true
}

sec_unit() {
    cd "$SRC" || return
    local out; out=$(python3 -m pytest -q -p no:cacheprovider -p no:asyncio tests/unit 2>&1 | tail -15)
    local last; last=$(echo "$out" | tail -1)
    if echo "$last" | grep -q 'passed' && ! echo "$last" | grep -qE 'failed|error'; then
        report PASS "unit tests, distro Python $(python3 -V | cut -d' ' -f2)" "$last"
    else
        # The failing tests' names in the FAIL line itself: only FAIL lines become CI annotations.
        local names; names=$(echo "$out" | grep -E '^(FAILED|ERROR) ' | awk '{print $2}' | sed 's|^tests/unit/||' | head -5 | tr '\n' ' ')
        report FAIL "unit tests, distro Python $(python3 -V | cut -d' ' -f2)" "$last${names:+ -- $names}"
        echo "$out" | grep -E '^(FAILED|ERROR)' | head -20 | while read -r l; do info "unit" "$l"; done
    fi
    cd - >/dev/null
}

sec_sni() {
    local out
    out=$(python3 -I - <<'EOF' 2>&1
import dns.message, httpx, httpcore
q = dns.message.make_query("example.com", "A").to_wire()
hdr = {"Host": "dns.quad9.net", "Content-Type": "application/dns-message", "Accept": "application/dns-message"}
def ask(sni):
    with httpx.Client(http2=True, timeout=5) as c:
        r = c.post("https://9.9.9.9/dns-query", content=q, headers=hdr, extensions={"sni_hostname": sni})
        return r.http_version, r.status_code, r.headers.get("content-type")
print("versions", httpx.__version__, httpcore.__version__)
print("good", *ask("dns.quad9.net"))
try:
    print("wrong", *ask("wrong.example"))
except Exception as e:
    print("wrong-rejected", type(e).__name__, str(e)[:80])
EOF
)
    info "sni httpx/httpcore" "$(echo "$out" | grep '^versions' | cut -d' ' -f2-)"
    if echo "$out" | grep -q '^good HTTP/2 200 application/dns-message'; then
        report PASS "sni_hostname over HTTP/2 to a bootstrap IP" "$(echo "$out" | grep '^good')"
    else report FAIL "sni_hostname over HTTP/2 to a bootstrap IP" "$(echo "$out" | tr '\n' '|')"; fi
    # Raw httpx: httpcore < 0.17 ignores sni_hostname (library behaviour, recorded only).
    info "raw httpx, wrong sni_hostname" "$(echo "$out" | grep '^wrong' | cut -c1-90)"
    # Our DohUpstream pins the name in its SSL context, so a wrong name must fail on every version.
    out=$(python3 -I -c '
import asyncio, sys
sys.path.insert(0, "'$SRC'/src")
from blockads_linux.daemon.upstream.doh import DohUpstream
from blockads_linux.daemon.upstream.base import Question, UpstreamError
async def main():
    q = Question.make("example.com", 1)
    for name in ("dns.quad9.net", "wrong.example"):
        u = DohUpstream(f"https://{name}/dns-query", "9.9.9.9")
        try:
            r = await u.exchange(q)
            print(name, "ANSWERED", len(r.answer))
        except UpstreamError as e:
            print(name, "REJECTED", e)
        await u.close()
asyncio.run(main())' 2>&1)
    if echo "$out" | grep -q '^dns.quad9.net ANSWERED' && echo "$out" | grep -q '^wrong.example REJECTED.*certificate'; then
        report PASS "doh.py: right name answers, wrong name rejected" "$(echo "$out" | tr '\n' '|' | cut -c1-120)"
    else report FAIL "doh.py: right name answers, wrong name rejected" "$(echo "$out" | tr '\n' '|' | cut -c1-200)"; fi

    # Our own DoH upstream (doh.py) end to end through the dev daemon.
    python3 -m blockads_linux.daemon --dev --listen 127.0.0.1:5300 \
        --upstream 'https://9.9.9.9/dns-query#dns.quad9.net' --fallback none >/run/dev-daemon.log 2>&1 &
    local pid=$!
    sleep 2
    out=$(python3 -I -c '
import dns.message, dns.query
r = dns.query.udp(dns.message.make_query("example.com", "A"), "127.0.0.1", port=5300, timeout=5)
print(dns.rcode.to_text(r.rcode()), len(r.answer))' 2>&1)
    kill $pid; wait $pid 2>/dev/null
    if [[ $out == "NOERROR "[1-9]* ]]; then report PASS "dev daemon resolves via doh.py (Quad9)" "$out"
    else report FAIL "dev daemon resolves via doh.py (Quad9)" "$out $(tail -3 /run/dev-daemon.log | tr '\n' '|')"; fi
}

HARDENING='NoNewPrivileges=yes
CapabilityBoundingSet=
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
PrivateIPC=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged
UMask=0077
LimitCORE=0
MemoryMax=512M
TasksMax=64'

write_units() {  # write_units EXTRA_DIRECTIVES
    cat >/etc/systemd/system/blockadsd.socket <<EOF
[Unit]
Description=blockadsd DNS socket (IPv4)
[Socket]
ListenDatagram=127.0.0.1:153
ListenStream=127.0.0.1:153
FileDescriptorName=dns-v4
Service=blockadsd.service
[Install]
WantedBy=sockets.target
EOF
    cat >/etc/systemd/system/blockadsd-ipv6.socket <<EOF
[Unit]
Description=blockadsd DNS socket (IPv6)
ConditionPathExists=/proc/sys/net/ipv6
[Socket]
ListenDatagram=[::1]:153
ListenStream=[::1]:153
BindIPv6Only=ipv6-only
FreeBind=yes
FileDescriptorName=dns-v6
Service=blockadsd.service
[Install]
WantedBy=sockets.target
EOF
    cat >/etc/systemd/system/blockadsd.service <<EOF
[Unit]
Requires=blockadsd.socket
Wants=blockadsd-ipv6.socket
After=blockadsd.socket blockadsd-ipv6.socket
[Service]
Type=notify
User=blockads
Environment=PYTHONPATH=$SRC/src
ExecStart=/usr/bin/python3 -m blockads_linux.daemon --upstream quad9
StateDirectory=blockads-linux
StateDirectoryMode=0700
CacheDirectory=blockads-linux
RuntimeDirectory=blockads-linux
$HARDENING
$1
EOF
    systemctl daemon-reload
}

dig_local() {  # dig_local ADDR -> "NOERROR n" via dnspython
    python3 -I -c '
import sys, dns.message, dns.query, dns.rcode
r = dns.query.udp(dns.message.make_query("example.com", "A"), sys.argv[1], port=153, timeout=6)
t = dns.query.tcp(dns.message.make_query("example.org", "AAAA"), sys.argv[1], port=153, timeout=6)
print(dns.rcode.to_text(r.rcode()), len(r.answer), "tcp", dns.rcode.to_text(t.rcode()))' "$1" 2>&1 | tail -1
}

sandbox_run() {  # sandbox_run LABEL EXTRA -> PASS/FAIL on v4+v6 resolution
    local label=$1 extra=$2
    systemctl stop blockadsd.service blockadsd.socket blockadsd-ipv6.socket 2>/dev/null
    systemctl reset-failed blockadsd.service 2>/dev/null
    write_units "$extra"
    systemctl start blockadsd.socket blockadsd-ipv6.socket
    local v4 v6; v4=$(dig_local 127.0.0.1); v6=$(dig_local ::1)
    local state; state=$(systemctl is-active blockadsd.service)
    if [[ $v4 == "NOERROR "[1-9]*" tcp NOERROR" && $v6 == "NOERROR "[1-9]*" tcp NOERROR" && $state == active ]]; then
        report PASS "sandbox: $label" "v4 [$v4] v6 [$v6]"
    else
        report FAIL "sandbox: $label" "state=$state v4 [$v4] v6 [$v6]"
        journalctl -u blockadsd.service -n 8 --no-pager -o cat | while read -r l; do info "journal" "$l"; done
    fi
}

SYSTEMD_VER=$(systemctl --version | awk 'NR==1{print $2}')
sec_sandbox() {
    info "systemd" "$SYSTEMD_VER"
    sandbox_run "base hardening" ""
    journalctl -u blockadsd.service --no-pager -o cat | grep -i 'socket\|listen\|fd' | tail -3 | while read -r l; do info "journal" "$l"; done
    local d
    for d in "ProcSubset=pid" "PrivateUsers=yes" "SocketBindDeny=any" "RestartSteps=5
RestartMaxDelaySec=30s"; do
        sandbox_run "gated + ${d//$'\n'/ }" "$d"
    done
    sandbox_run "all gated directives together" "ProcSubset=pid
PrivateUsers=yes
SocketBindDeny=any"
    local score; score=$(systemd-analyze security blockadsd.service 2>/dev/null | tail -1)
    info "systemd-analyze security" "$score"

    # Runtime probe (imports, sqlite3 WAL in StateDirectory, TLS, system bus) under the same sandbox.
    local props=() line
    while IFS= read -r line; do [[ -n $line ]] && props+=(-p "$line"); done <<<"$HARDENING
ProcSubset=pid
PrivateUsers=yes
SocketBindDeny=any"
    sandboxed -p User=blockads -p StateDirectory=blockads-probe "${props[@]}" \
        -E PYTHONPATH=$SRC/src /usr/bin/python3 -I "$VM/runtime_probe.py" 2>&1 \
        | while read -r st key rest; do report "$st" "sandboxed runtime: $key" "$rest"; done
}

sec_freebind() {
    sandbox_run "baseline before disabling IPv6" ""
    sysctl -qw net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1 net.ipv6.conf.lo.disable_ipv6=1
    systemctl stop blockadsd.service blockadsd.socket blockadsd-ipv6.socket
    systemctl start blockadsd.socket blockadsd-ipv6.socket
    local s6; s6=$(systemctl is-active blockadsd-ipv6.socket)
    local v4; v4=$(dig_local 127.0.0.1)
    if [[ $s6 == active && $v4 == "NOERROR "* ]]; then report PASS "FreeBind: ipv6 socket starts with IPv6 disabled" "ipv6.socket=$s6 v4 [$v4]"
    else report FAIL "FreeBind: ipv6 socket starts with IPv6 disabled" "ipv6.socket=$s6 v4 [$v4] $(journalctl -u blockadsd-ipv6.socket -n2 -o cat --no-pager | tr '\n' '|')"; fi
    sysctl -qw net.ipv6.conf.all.disable_ipv6=0 net.ipv6.conf.default.disable_ipv6=0 net.ipv6.conf.lo.disable_ipv6=0
    sleep 1
    local v6; v6=$(dig_local ::1)
    if [[ $v6 == "NOERROR "* ]]; then report PASS "FreeBind: [::1]:153 serves once IPv6 is re-enabled" "$v6"
    else report FAIL "FreeBind: [::1]:153 serves once IPv6 is re-enabled" "$v6"; fi
    # Without FreeBind, for comparison.
    sed -i '/^FreeBind=/d' /etc/systemd/system/blockadsd-ipv6.socket; systemctl daemon-reload
    systemctl stop blockadsd.service blockadsd.socket blockadsd-ipv6.socket
    sysctl -qw net.ipv6.conf.lo.disable_ipv6=1 net.ipv6.conf.all.disable_ipv6=1
    systemctl start blockadsd-ipv6.socket 2>/dev/null
    info "without FreeBind, IPv6 disabled: ipv6.socket" "$(systemctl is-active blockadsd-ipv6.socket)"
    sysctl -qw net.ipv6.conf.all.disable_ipv6=0 net.ipv6.conf.lo.disable_ipv6=0 net.ipv6.conf.default.disable_ipv6=0
    systemctl stop blockadsd.service blockadsd.socket blockadsd-ipv6.socket; systemctl reset-failed 2>/dev/null
}

sec_nm() {
    systemctl start NetworkManager 2>/dev/null; sleep 2
    info "NetworkManager" "$(NetworkManager --version 2>/dev/null) $(systemctl is-active NetworkManager)"
    local who out
    for who in blockads alice; do
        out=$(setpriv --reuid="$who" --regid="$who" --init-groups busctl --system get-property \
              org.freedesktop.NetworkManager /org/freedesktop/NetworkManager/DnsManager \
              org.freedesktop.NetworkManager.DnsManager Configuration 2>&1 | head -c 120)
        if [[ $out == aa* ]]; then report PASS "NM DnsManager.Configuration readable by $who" "$out"
        else report FAIL "NM DnsManager.Configuration readable by $who" "$out"; fi
    done
    for p in Connectivity Metered NetworkingEnabled; do
        out=$(setpriv --reuid=blockads --regid=blockads --init-groups busctl --system get-property \
              org.freedesktop.NetworkManager /org/freedesktop/NetworkManager org.freedesktop.NetworkManager $p 2>&1)
        [[ $p == Metered ]] && out=$(setpriv --reuid=blockads --regid=blockads --init-groups busctl --system get-property \
              org.freedesktop.NetworkManager /org/freedesktop/NetworkManager org.freedesktop.NetworkManager PrimaryConnectionType 2>&1)
        [[ $out == *Error* || $out == *denied* ]] && report FAIL "NM $p readable by blockads" "$out" || report PASS "NM ${p/Metered/PrimaryConnectionType} readable by blockads" "$out"
    done
    out=$(setpriv --reuid=blockads --regid=blockads --init-groups busctl --system call org.freedesktop.resolve1 \
          /org/freedesktop/resolve1 org.freedesktop.DBus.Properties Get ss org.freedesktop.resolve1.Manager DNS 2>&1 | head -c 100)
    info "resolved Manager.DNS as blockads" "$out"
}

sec_polkit() {
    systemctl start polkit 2>/dev/null
    info "polkit" "$(pkcheck --version 2>/dev/null || ls /usr/lib/polkit-1/polkitd /usr/libexec/polkitd 2>/dev/null)"
    cat >/usr/share/polkit-1/actions/io.github.mateusbmp.blockads.vmtest.policy <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE policyconfig PUBLIC "-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/PolicyKit/1/policyconfig.dtd">
<policyconfig>
  <action id="io.github.mateusbmp.blockads.vmtest.unowned">
    <description>test</description><message>test</message>
    <defaults><allow_any>auth_admin_keep</allow_any><allow_inactive>auth_admin_keep</allow_inactive><allow_active>auth_admin_keep</allow_active></defaults>
  </action>
  <action id="io.github.mateusbmp.blockads.vmtest.owned">
    <description>test</description><message>test</message>
    <defaults><allow_any>auth_admin_keep</allow_any><allow_inactive>auth_admin_keep</allow_inactive><allow_active>auth_admin_keep</allow_active></defaults>
    <annotate key="org.freedesktop.policykit.owner">unix-user:blockads</annotate>
  </action>
  <action id="io.github.mateusbmp.blockads.vmtest.owned-yes">
    <description>test</description><message>test</message>
    <defaults><allow_any>yes</allow_any><allow_inactive>yes</allow_inactive><allow_active>yes</allow_active></defaults>
    <annotate key="org.freedesktop.policykit.owner">unix-user:blockads</annotate>
  </action>
</policyconfig>
EOF
    sleep 2
    as_alice python3 -I "$VM/polkit_probe.py" hold 40 >/run/alice-bus.txt 2>&1 &
    local hold=$!
    for _ in $(seq 30); do [[ -s /run/alice-bus.txt ]] && break; sleep 0.2; done
    local name; name=$(head -1 /run/alice-bus.txt)
    local props=() line
    while IFS= read -r line; do [[ -n $line ]] && props+=(-p "$line"); done <<<"$HARDENING
ProcSubset=pid
PrivateUsers=yes"
    local a out
    for a in unowned owned owned-yes; do
        out=$(sandboxed -p User=blockads "${props[@]}" \
              /usr/bin/python3 -I "$VM/polkit_probe.py" check "$name" "io.github.mateusbmp.blockads.vmtest.$a" 2>&1 | tail -1)
        case $a in
            unowned)   [[ $out == ERROR* ]] && report PASS "polkit: unowned action, blockads checks alice -> refused" "$out" \
                                            || report FAIL "polkit: unowned action, blockads checks alice -> refused" "$out" ;;
            owned)     [[ $out == CHALLENGE ]] && report PASS "polkit: owner annotation, auth_admin_keep -> CHALLENGE" "$out" \
                                               || report FAIL "polkit: owner annotation, auth_admin_keep -> CHALLENGE" "$out" ;;
            owned-yes) [[ $out == AUTHORIZED ]] && report PASS "polkit: owner annotation, yes -> AUTHORIZED" "$out" \
                                                || report FAIL "polkit: owner annotation, yes -> AUTHORIZED" "$out" ;;
        esac
    done
    kill $hold 2>/dev/null; wait $hold 2>/dev/null
    rm -f /usr/share/polkit-1/actions/io.github.mateusbmp.blockads.vmtest.policy
}

sec_pinned() {
    far_up; start_local_responder
    local b=nft out
    out=$(python3 -I "$VM/pinned_probe.py" 192.0.2.1 \
        "before:" \
        "after-apply:$(declare -f fw_apply fw_render fw_jumps); DAEMON_UID=$DAEMON_UID PORT=$PORT PROBE_PORT=$PROBE_PORT fw_apply $b" \
        "after-conntrack-D:conntrack -D -p udp --orig-port-dst 53" \
        "after-revert:$(declare -f fw_revert); fw_revert $b" \
        "after-conntrack-D:conntrack -D -p udp --orig-port-dst 53" 2>&1)
    info "pinned flow sequence (nft)" "$(echo "$out" | tr '\n' ' ')"
    local s=($out)
    [[ ${s[1]} == far ]]   && report PASS "pinned: baseline reaches the remote resolver" "${s[1]}" || report FAIL "pinned: baseline" "${s[1]}"
    if [[ ${s[3]} == far ]]; then report INFO "pinned: after apply, existing flow still bypasses (pinned)" "${s[3]} -> apply must delete DNS conntrack entries"
    else report INFO "pinned: after apply, existing flow" "${s[3]}"; fi
    [[ ${s[5]} == local ]] && report PASS "pinned: conntrack -D after apply re-routes to the daemon" "${s[5]}" || report FAIL "pinned: conntrack -D after apply" "${s[5]}"
    if [[ ${s[7]} == local ]]; then report INFO "pinned: after revert, flow still redirected (pinned)" "${s[7]} -> revert must delete DNS conntrack entries"
    else report INFO "pinned: after revert, existing flow" "${s[7]}"; fi
    [[ ${s[9]} == far ]] && report PASS "pinned: conntrack -D after revert restores direct DNS" "${s[9]}" || report FAIL "pinned: conntrack -D after revert" "${s[9]}"
    # Fresh flows are never affected:
    fw_apply nft
    expect "fresh flow after apply is redirected" OK $PROBE query 192.0.2.1 53
    info "fresh flow responder" "$($PROBE query 192.0.2.1 53)"
    fw_revert nft
    stop_local_responder
}

sec_nftflush() {
    start_local_responder
    fw_apply nft
    expect "nft rules: probe redirected" OK $PROBE query 127.0.0.1 $PROBE_PORT
    nft flush ruleset
    expect "after nft flush ruleset: probe fails fast (detectable)" REFUSED $PROBE query 127.0.0.1 $PROBE_PORT
    info "after flush, BLOCKADS_ lines left" "$(fw_left)"
    fw_revert nft
    fw_apply nft && report PASS "re-apply after nft flush ruleset" "" || report FAIL "re-apply after nft flush ruleset" ""
    fw_revert nft
    if iptables-legacy -t nat -S >/dev/null 2>&1; then
        fw_apply legacy
        expect "legacy rules: probe redirected" OK $PROBE query 127.0.0.1 $PROBE_PORT
        nft flush ruleset
        local out; out=$($PROBE query 127.0.0.1 $PROBE_PORT)
        info "legacy rules after nft flush ruleset" "$out (legacy is outside nftables)"
        fw_revert legacy
    else report SKIP "legacy vs nft flush" "no legacy backend"; fi
    stop_local_responder
}

coexist_check() {  # coexist_check LABEL BACKEND
    local jd jo
    jd=$(fw_jumps "iptables-$2" nat BLOCKADS_DNS); jo=$(fw_jumps "iptables-$2" filter BLOCKADS_OUT)
    local p; p=$($PROBE query 127.0.0.1 $PROBE_PORT); local u; u=$(setpriv --reuid=alice --regid=alice --init-groups $PROBE query 192.0.2.1 53)
    if [[ $jd -eq 1 && $jo -eq 1 && $p == OK* && $u == "OK"*local* ]]; then report PASS "$1" "jumps $jd/$jo probe [$p] user->192.0.2.1 [$u]"
    else report FAIL "$1" "jumps $jd/$jo probe [$p] user->192.0.2.1 [$u]"; fi
}

sec_docker() {
    . /etc/os-release
    if ! command -v docker >/dev/null; then
        case $ID in debian|ubuntu) DEBIAN_FRONTEND=noninteractive apt-get install -y -qq docker.io >/dev/null 2>&1 ;;
                    fedora) dnf install -y -q moby-engine >/dev/null 2>&1 ;;
                    arch) pacman -S --noconfirm --needed --noprogressbar docker >/dev/null 2>&1 ;; esac
    fi
    systemctl start docker || { report SKIP docker "not installable"; return; }
    info "docker" "$(docker --version) iptables -> $(readlink -f "$(command -v iptables)")"
    # Pull while DNS still works (the test responder answers every name with TXT).
    local pulled=""; timeout 180 docker pull -q busybox:1.36 >/dev/null 2>&1 && pulled=1
    far_up; start_local_responder
    fw_apply nft
    coexist_check "docker running, rules applied after" nft
    systemctl restart docker; sleep 2
    coexist_check "after systemctl restart docker" nft
    info "nat OUTPUT order" "$(iptables-nft -t nat -S OUTPUT | grep -- '-A' | tr '\n' '|')"
    fw_revert nft; systemctl stop docker docker.socket
    fw_apply nft; systemctl start docker; sleep 2
    coexist_check "docker started after our rules" nft
    info "nat OUTPUT order" "$(iptables-nft -t nat -S OUTPUT | grep -- '-A' | tr '\n' '|')"
    # Container DNS: does it pass through our OUTPUT redirect?
    if [[ -n $pulled ]]; then
        local out; out=$(timeout 20 docker run --rm --dns 192.0.2.1 busybox:1.36 nslookup -type=txt x.probe.blockads-linux.invalid 2>&1 | grep -o 'tag=[a-z]*' | head -1)
        info "container (bridge, --dns 192.0.2.1) answered by" "${out:-nothing} (local = redirected by OUTPUT, far = bypass via FORWARD)"
        out=$(timeout 20 docker run --rm busybox:1.36 cat /etc/resolv.conf | grep nameserver | tr '\n' ' ')
        info "container default resolv.conf" "$out"
    else info "container DNS" "busybox pull failed; skipped"; fi
    fw_revert nft
    systemctl stop docker docker.socket
    stop_local_responder
}

sec_firewalld() {
    command -v firewall-cmd >/dev/null || { report SKIP firewalld "not installed"; return; }
    systemctl start firewalld
    info "firewalld" "$(firewall-cmd --version) backend=$(grep -E '^FirewallBackend' /etc/firewalld/firewalld.conf | cut -d= -f2)"
    far_up; start_local_responder
    fw_apply nft
    coexist_check "firewalld running, rules applied" nft
    firewall-cmd --reload >/dev/null
    coexist_check "after firewall-cmd --reload" nft
    systemctl restart firewalld
    coexist_check "after systemctl restart firewalld" nft
    if grep -q '^FirewallBackend' /etc/firewalld/firewalld.conf; then
        sed -i 's/^FirewallBackend=.*/FirewallBackend=iptables/' /etc/firewalld/firewalld.conf
        if systemctl restart firewalld && [[ $(firewall-cmd --state 2>/dev/null) == running ]]; then
            fw_apply nft
            coexist_check "firewalld iptables backend, after restart + re-apply" nft
            firewall-cmd --reload >/dev/null
            local jd; jd=$(fw_jumps iptables-nft nat BLOCKADS_DNS)
            info "firewalld iptables backend: jumps after --reload" "$jd (0 = flushed; probe must detect)"
            info "probe after that reload" "$($PROBE query 127.0.0.1 $PROBE_PORT)"
        else info "firewalld iptables backend" "not available on this version"; fi
        sed -i 's/^FirewallBackend=.*/FirewallBackend=nftables/' /etc/firewalld/firewalld.conf
    fi
    fw_revert nft; systemctl stop firewalld
    stop_local_responder
}

sec_ufw() {
    command -v ufw >/dev/null || DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ufw >/dev/null 2>&1
    command -v ufw >/dev/null || { report SKIP ufw "not installable"; return; }
    ufw allow 22/tcp >/dev/null; ufw --force enable >/dev/null
    info "ufw" "$(ufw version | head -1) iptables -> $(readlink -f "$(command -v iptables)")"
    far_up; start_local_responder
    fw_apply nft
    coexist_check "ufw enabled, rules applied" nft
    ufw reload >/dev/null
    coexist_check "after ufw reload" nft
    ufw --force disable >/dev/null
    coexist_check "after ufw disable" nft
    ufw --force enable >/dev/null
    coexist_check "after ufw enable" nft
    systemctl restart ufw
    coexist_check "after systemctl restart ufw" nft
    fw_revert nft; ufw --force disable >/dev/null
    stop_local_responder
}

for s in "$@"; do
    echo "--- $s"
    "sec_$s"
done
[[ $(fw_left) -eq 0 ]] || report FAIL "no BLOCKADS_ rules left at the end" "$(fw_left)"
exit $(( FAILURES > 125 ? 125 : FAILURES ))
