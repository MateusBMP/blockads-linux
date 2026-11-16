"""A tiny authoritative-looking DNS server for the VM network simulations.

Usage: python3 -I fakedns.py ADDRESS PORT SUFFIX=IP...

Answers A queries for names under SUFFIX (or the name itself) with IP, the
longest suffix winning; everything else gets NXDOMAIN. UDP and TCP. Used as
the "VPN" DNS server and the captive portal's DNS inside a network namespace.
"""

import socketserver
import sys
import threading

import dns.message
import dns.rcode
import dns.rdatatype
import dns.rrset


def answer(wire: bytes, rules: list[tuple[str, str]]) -> bytes:
    query = dns.message.from_wire(wire)
    reply = dns.message.make_response(query)
    question = query.question[0]
    name = question.name.to_text(omit_final_dot=True).lower()
    for suffix, ip in rules:
        if name == suffix or name.endswith("." + suffix) or suffix == "*":
            if question.rdtype == dns.rdatatype.A:
                reply.answer.append(dns.rrset.from_text(question.name, 30, "IN", "A", ip))
            break
    else:
        reply.set_rcode(dns.rcode.NXDOMAIN)
    return reply.to_wire()


def main() -> None:
    address, port = sys.argv[1], int(sys.argv[2])
    rules = sorted((tuple(arg.lower().split("=", 1)) for arg in sys.argv[3:]),
                   key=lambda rule: (rule[0] == "*", -len(rule[0])))

    class Udp(socketserver.BaseRequestHandler):
        def handle(self):
            data, sock = self.request
            try:
                sock.sendto(answer(data, rules), self.client_address)
            except Exception:  # noqa: BLE001 - a test server never dies on bad input
                pass

    class Tcp(socketserver.StreamRequestHandler):
        def handle(self):
            try:
                size = int.from_bytes(self.rfile.read(2), "big")
                out = answer(self.rfile.read(size), rules)
                self.wfile.write(len(out).to_bytes(2, "big") + out)
            except Exception:  # noqa: BLE001
                pass

    socketserver.UDPServer.allow_reuse_address = True
    socketserver.TCPServer.allow_reuse_address = True
    udp = socketserver.ThreadingUDPServer((address, port), Udp)
    tcp = socketserver.ThreadingTCPServer((address, port), Tcp)
    threading.Thread(target=tcp.serve_forever, daemon=True).start()
    print(f"fakedns on {address}:{port}", flush=True)
    udp.serve_forever()


if __name__ == "__main__":
    main()
