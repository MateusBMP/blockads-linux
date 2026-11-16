#!/bin/sh
# blockads-fw-emergency.sh: last-resort removal of every blockads-linux
# iptables rule, without Python.
#
#   sudo sh /usr/lib/blockads-linux/blockads-fw-emergency.sh
#
# For each iptables binary present (default, -nft, -legacy; IPv4 and IPv6) it
# deletes our exact jumps from the built-in chains, flushes and deletes our
# chains, then re-checks. Legacy tables are touched only when the kernel lists
# them, so this never loads legacy modules. Never evaluates iptables output.
#
# Exit status: 0 clean, 1 something is left (systemd then runs OnFailure).
PATH=/usr/sbin:/usr/bin
LC_ALL=C
export PATH LC_ALL
umask 022

# table:built-in:chain (current chains plus historical ones)
HOOKS="nat:OUTPUT:BLOCKADS_DNS filter:OUTPUT:BLOCKADS_OUT nat:PREROUTING:BLOCKADS_BRIDGE filter:INPUT:BLOCKADS_IN"
PROC_NET=/proc/net
LEFT=0

find_bin() {
    for dir in /usr/sbin /usr/bin; do
        if [ -x "$dir/$1" ]; then echo "$dir/$1"; return 0; fi
    done
    return 1
}

usable() {  # usable BIN FAMILY: skip legacy when the kernel has no legacy tables
    case "$(basename "$(readlink -f "$1")")" in
        *legacy*)
            if [ "$2" = 4 ]; then names="$PROC_NET/ip_tables_names"; else names="$PROC_NET/ip6_tables_names"; fi
            # Not `[ -s ]`: files in /proc report size 0.
            grep -q . "$names" 2>/dev/null || return 1
            ;;
    esac
    "$1" -w 5 -t filter -S OUTPUT >/dev/null 2>&1
}

clean() {  # clean BIN
    ipt=$1
    for hook in $HOOKS; do
        table=${hook%%:*}; rest=${hook#*:}; builtin=${rest%%:*}; chain=${rest#*:}
        i=0
        while [ $i -lt 16 ] && "$ipt" -w 5 -t "$table" -D "$builtin" -j "$chain" >/dev/null 2>&1; do
            i=$((i + 1))
        done
        "$ipt" -w 5 -t "$table" -F "$chain" >/dev/null 2>&1
        "$ipt" -w 5 -t "$table" -X "$chain" >/dev/null 2>&1
        if "$ipt" -w 5 -t "$table" -S "$builtin" 2>/dev/null | grep -Eq -- "-[jg] $chain( |\$)"; then
            echo "blockads-fw-emergency: $ipt $table $builtin still jumps to $chain" >&2
            LEFT=1
        fi
        if "$ipt" -w 5 -t "$table" -S "$chain" >/dev/null 2>&1; then
            echo "blockads-fw-emergency: $ipt $table $chain still exists" >&2
            LEFT=1
        fi
    done
}

seen=""
for name in iptables iptables-nft iptables-legacy ip6tables ip6tables-nft ip6tables-legacy; do
    bin=$(find_bin "$name") || continue
    case $name in ip6*) family=6 ;; *) family=4 ;; esac
    real=$(readlink -f "$bin")
    # The same backend and family once only (iptables usually is iptables-nft).
    case "$real" in *nft*) key="nft$family" ;; *legacy*) key="legacy$family" ;; *) key="$real$family" ;; esac
    case " $seen " in *" $key "*) continue ;; esac
    seen="$seen $key"
    usable "$bin" "$family" || continue
    clean "$bin"
done

exit $LEFT
