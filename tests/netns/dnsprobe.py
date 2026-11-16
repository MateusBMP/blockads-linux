#!/usr/bin/env python3
"""Tiny DNS responder/client for the rootless network-namespace tests.

serve  -- answer every query with TXT "blockads-linux:<first label>" (plus
          "tag=<TAG>" with --tag) on UDP and TCP for each given address.
          Prints READY once all sockets are bound.
query  -- send one TXT query for "<nonce>.probe.blockads-linux.invalid" over a
          *connected* socket (so ICMP port-unreachable surfaces immediately as
          ECONNREFUSED) and print one of: OK, MISMATCH, TIMEOUT, REFUSED, ERROR.
bind   -- try to bind a UDP socket (optionally with SO_REUSEADDR) and report
          BOUND or the errno name; with --hold, keep it open and report what
          it receives.

Only used inside throwaway namespaces created by tests/netns/*.sh.
"""

from __future__ import annotations

import argparse
import errno
import secrets
import socket
import struct
import sys
import threading
import time

import dns.message
import dns.rrset


def _family(host: str) -> int:
    return socket.AF_INET6 if ":" in host else socket.AF_INET


TAG = ""


def _answer(wire: bytes) -> bytes:
    query = dns.message.from_wire(wire)
    response = dns.message.make_response(query)
    name = query.question[0].name
    label = name.labels[0].decode("ascii", "replace") if name.labels else ""
    response.answer.append(
        dns.rrset.from_text(name, 1, "IN", "TXT", f'"blockads-linux:{label}"',
                            *([f'"tag={TAG}"'] if TAG else []))
    )
    return response.to_wire()


def _serve_udp(sock: socket.socket) -> None:
    while True:
        data, peer = sock.recvfrom(4096)
        try:
            sock.sendto(_answer(data), peer)
        except Exception:  # noqa: BLE001 - test helper, keep serving
            pass


def _recv_exact(conn: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("short read")
        buf += chunk
    return buf


def _serve_tcp(sock: socket.socket) -> None:
    while True:
        conn, _ = sock.accept()
        with conn:
            try:
                (length,) = struct.unpack("!H", _recv_exact(conn, 2))
                reply = _answer(_recv_exact(conn, length))
                conn.sendall(struct.pack("!H", len(reply)) + reply)
            except Exception:  # noqa: BLE001
                pass


def cmd_serve(args: argparse.Namespace) -> int:
    global TAG
    TAG = args.tag
    for host in args.addr:
        fam = _family(host)
        udp = socket.socket(fam, socket.SOCK_DGRAM)
        udp.bind((host, args.port))
        tcp = socket.socket(fam, socket.SOCK_STREAM)
        tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp.bind((host, args.port))
        tcp.listen(16)
        threading.Thread(target=_serve_udp, args=(udp,), daemon=True).start()
        threading.Thread(target=_serve_tcp, args=(tcp,), daemon=True).start()
    print("READY", flush=True)
    while True:
        time.sleep(3600)


def cmd_query(args: argparse.Namespace) -> int:
    nonce = secrets.token_hex(16)
    query = dns.message.make_query(f"{nonce}.probe.blockads-linux.invalid", "TXT")
    wire = query.to_wire()
    fam = _family(args.host)
    kind = socket.SOCK_DGRAM if args.proto == "udp" else socket.SOCK_STREAM
    start = time.monotonic()
    try:
        with socket.socket(fam, kind) as sock:
            sock.settimeout(args.timeout)
            sock.connect((args.host, args.port))
            if args.proto == "udp":
                sock.send(wire)
                data = sock.recv(4096)
            else:
                sock.sendall(struct.pack("!H", len(wire)) + wire)
                (length,) = struct.unpack("!H", _recv_exact(sock, 2))
                data = _recv_exact(sock, length)
    except socket.timeout:
        print(f"TIMEOUT {time.monotonic() - start:.2f}s")
        return 2
    except ConnectionRefusedError:
        print(f"REFUSED {time.monotonic() - start:.2f}s")
        return 3
    except PermissionError:
        # A local netfilter REJECT/DROP in OUTPUT makes send() fail with EPERM.
        print(f"BLOCKED {time.monotonic() - start:.2f}s")
        return 5
    except OSError as exc:
        print(f"ERROR {errno.errorcode.get(exc.errno, exc.errno)}")
        return 4
    response = dns.message.from_wire(data)
    texts = [
        b"".join(rdata.strings).decode("ascii", "replace")
        for rrset in response.answer
        for rdata in rrset
    ]
    if f"blockads-linux:{nonce}" in texts:
        tags = " ".join(t for t in texts if t.startswith("tag="))
        print(f"OK {time.monotonic() - start:.2f}s {tags}".rstrip())
        return 0
    print(f"MISMATCH {texts!r}")
    return 1


def cmd_bind(args: argparse.Namespace) -> int:
    sock = socket.socket(_family(args.host), socket.SOCK_DGRAM)
    if args.reuseaddr:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((args.host, args.port))
    except OSError as exc:
        print(errno.errorcode.get(exc.errno, str(exc.errno)), flush=True)
        return 1
    print("BOUND", flush=True)
    if args.hold:
        sock.settimeout(args.hold)
        try:
            data, _ = sock.recvfrom(4096)
            print(f"RECEIVED {len(data)} bytes", flush=True)
        except socket.timeout:
            print("NOTHING", flush=True)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)
    serve = sub.add_parser("serve")
    serve.add_argument("--port", type=int, required=True)
    serve.add_argument("--tag", default="", help="extra TXT string tag=TAG, to tell responders apart")
    serve.add_argument("addr", nargs="+")
    query = sub.add_parser("query")
    query.add_argument("--proto", choices=("udp", "tcp"), default="udp")
    query.add_argument("--timeout", type=float, default=1.0)
    query.add_argument("host")
    query.add_argument("port", type=int)
    bind = sub.add_parser("bind")
    bind.add_argument("--reuseaddr", action="store_true")
    bind.add_argument("--hold", type=float, default=0.0)
    bind.add_argument("host")
    bind.add_argument("port", type=int)
    args = parser.parse_args()
    return {"serve": cmd_serve, "query": cmd_query, "bind": cmd_bind}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
