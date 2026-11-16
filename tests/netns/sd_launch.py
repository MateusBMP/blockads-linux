#!/usr/bin/env python3
"""Play systemd's part for the self-healing namespace test (tests/netns/self_healing.sh).

launch -- as root, bind UDP+TCP 127.0.0.1:PORT (``dns-v4``) and [::1]:PORT
          (``dns-v6``), like blockadsd.socket / blockadsd-ipv6.socket, then
          drop to UID and exec COMMAND with LISTEN_FDS/LISTEN_FDNAMES/LISTEN_PID
          (exec keeps the PID, so LISTEN_PID is ours). With --bridge-port, also
          0.0.0.0:BRIDGE and [::]:BRIDGE (``dns-bridge``), like
          blockadsd-bridge.socket.
sink   -- bind a NOTIFY_SOCKET datagram socket and append every message, one
          per line, to a file (READY=1, WATCHDOG=1, STOPPING=1 ...).

Only used inside throwaway namespaces.
"""

from __future__ import annotations

import argparse
import os
import socket
import sys


def cmd_launch(args: argparse.Namespace) -> int:
    fds, names = [], []
    binds = [(socket.AF_INET, "127.0.0.1", args.port, "dns-v4"), (socket.AF_INET6, "::1", args.port, "dns-v6")]
    if args.bridge_port:
        binds += [(socket.AF_INET, "0.0.0.0", args.bridge_port, "dns-bridge"),
                  (socket.AF_INET6, "::", args.bridge_port, "dns-bridge")]
    for family, host, port, name in binds:
        for kind in (socket.SOCK_DGRAM, socket.SOCK_STREAM):
            sock = socket.socket(family, kind)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if family == socket.AF_INET6:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            sock.bind((host, port))
            if kind == socket.SOCK_STREAM:
                sock.listen(128)
            fds.append(sock.detach())
            names.append(name)
    for index, fd in enumerate(fds):
        target = 3 + index
        if fd != target:
            os.dup2(fd, target, inheritable=True)
            os.close(fd)
        else:
            os.set_inheritable(fd, True)
    env = dict(os.environ, LISTEN_FDS=str(len(fds)), LISTEN_FDNAMES=":".join(names), LISTEN_PID=str(os.getpid()))
    command = ["setpriv", f"--reuid={args.uid}", f"--regid={args.uid}", "--clear-groups", *args.command]
    os.execvpe(command[0], command, env)


def cmd_sink(args: argparse.Namespace) -> int:
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
        sock.bind(args.socket)
        os.chmod(args.socket, 0o777)
        with open(args.log, "a", buffering=1) as out:
            print("SINK-READY", file=out)
            while True:
                data = sock.recv(4096)
                for line in data.decode(errors="replace").splitlines():
                    print(line, file=out)


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)
    launch = sub.add_parser("launch")
    launch.add_argument("--port", type=int, required=True)
    launch.add_argument("--uid", type=int, required=True)
    launch.add_argument("--bridge-port", type=int, default=0)
    launch.add_argument("command", nargs=argparse.REMAINDER)
    sink = sub.add_parser("sink")
    sink.add_argument("socket")
    sink.add_argument("log")
    args = parser.parse_args()
    if args.cmd == "launch":
        if args.command[:1] == ["--"]:
            args.command = args.command[1:]
        return cmd_launch(args)
    return cmd_sink(args)


if __name__ == "__main__":
    sys.exit(main())
