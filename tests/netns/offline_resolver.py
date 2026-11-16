"""Body of offline_resolver.sh; runs inside the network namespace (loopback only)."""

import os
import random
import secrets
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

import dns.message  # noqa: E402
import dns.query  # noqa: E402
import dns.rcode  # noqa: E402

PORT = 5300
FAILURES = 0


def report(ok, name, detail=""):
    global FAILURES
    print(f"{'PASS' if ok else 'FAIL':<5} {name:<52} {detail}")
    FAILURES += 0 if ok else 1


def ask(name, rdtype="A", tcp=False, timeout=6):
    query = dns.message.make_query(name, rdtype)
    started = time.monotonic()
    send = dns.query.tcp if tcp else dns.query.udp
    reply = send(query, "127.0.0.1", port=PORT, timeout=timeout)
    rdata = [r.to_text() for rrset in reply.answer for r in rrset]
    return dns.rcode.to_text(reply.rcode()), rdata, time.monotonic() - started


def main():
    with tempfile.TemporaryDirectory() as tmp:
        hosts = Path(tmp, "hosts.txt")
        hosts.write_text("0.0.0.0 doubleclick.net\n")
        env = dict(os.environ, PYTHONPATH=str(ROOT / "src"))
        daemon = subprocess.Popen(
            [sys.executable, "-m", "blockads_linux.daemon", "--dev", "--listen", f"127.0.0.1:{PORT}",
             "--list", str(hosts)],
            env=env, stderr=subprocess.PIPE, text=True,
        )
        try:
            for line in daemon.stderr:
                if "serving DNS on tcp" in line:
                    break
            rcode, rdata, _ = ask("doubleclick.net")
            report(rcode == "NOERROR" and rdata == ["0.0.0.0"], "blocked name answered offline", f"{rcode} {rdata}")
            rcode, rdata, elapsed = ask("example.com")
            report(rcode == "SERVFAIL" and elapsed < 1.0, "forwarded name fails fast (no route)",
                   f"{rcode} in {elapsed * 1000:.0f} ms")
            rcode, rdata, elapsed = ask("example.org", tcp=True)
            report(rcode == "SERVFAIL" and elapsed < 1.0, "same over TCP", f"{rcode} in {elapsed * 1000:.0f} ms")
            nonce = secrets.token_hex(16)
            rcode, rdata, _ = ask(f"{nonce}.probe.blockads-linux.invalid", "TXT")
            report(rdata == [f'"blockads-linux:{nonce}"'], "health probe answered offline", f"{rdata}")
            rng = random.Random(1)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as junk:
                for _ in range(300):
                    junk.sendto(bytes(rng.randrange(256) for _ in range(rng.randrange(1, 120))), ("127.0.0.1", PORT))
            rcode, rdata, _ = ask("doubleclick.net", "AAAA")
            report(rdata == ["::"], "still serving after 300 garbage datagrams", f"{rcode} {rdata}")
            daemon.send_signal(signal.SIGTERM)
            code = daemon.wait(timeout=10)
            report(code == 0, "SIGTERM stops the daemon cleanly", f"exit status {code}")
        finally:
            if daemon.poll() is None:
                daemon.kill()
                daemon.wait()
    print("all checks passed" if FAILURES == 0 else f"{FAILURES} check(s) FAILED")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())
