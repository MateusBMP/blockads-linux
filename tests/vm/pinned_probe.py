"""Conntrack-pinned DNS flows across apply/revert (tests/vm/platform_checks.sh).

Keeps ONE connected UDP socket (fixed 5-tuple) to HOST:53 and, for each STEP,
runs the step's shell command (empty = none) and then sends a query on that
same socket, printing which responder answered (its tag=...).

    python3 pinned_probe.py HOST 'label:command' ...
"""

from __future__ import annotations

import secrets
import socket
import subprocess
import sys

import dns.message


def main() -> int:
    host = sys.argv[1]
    fam = socket.AF_INET6 if ":" in host else socket.AF_INET
    sock = socket.socket(fam, socket.SOCK_DGRAM)
    sock.settimeout(1.0)
    sock.connect((host, 53))
    for step in sys.argv[2:]:
        label, _, command = step.partition(":")
        if command:
            subprocess.run(["bash", "-c", command], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        nonce = secrets.token_hex(8)
        sock.send(dns.message.make_query(f"{nonce}.probe.blockads-linux.invalid", "TXT").to_wire())
        try:
            reply = dns.message.from_wire(sock.recv(4096))
            tags = [b"".join(r.strings).decode() for rr in reply.answer for r in rr]
            got = next((t[4:] for t in tags if t.startswith("tag=")), "untagged")
        except socket.timeout:
            got = "TIMEOUT"
        except ConnectionRefusedError:
            got = "REFUSED"
        print(f"{label} {got}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
