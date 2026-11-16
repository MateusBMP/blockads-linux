"""Fake DNS upstreams on loopback (UDP, TCP, TLS) and a throwaway test CA.

A handler receives the parsed query (and the raw wire) and returns what to
send back: a ``dns.message.Message``, raw ``bytes``, a list of either (several
UDP datagrams / TCP messages), or ``None`` for silence.
"""

import asyncio
import datetime
import ipaddress
import ssl

import dns.message
import dns.rrset


def answer(query, *records, rcode=None, flags=0, ttl=300):
    """A reply to ``query`` with ``(type, value)`` or ``(owner, type, value)`` records."""
    reply = dns.message.make_response(query)
    reply.flags |= flags
    if rcode is not None:
        reply.set_rcode(rcode)
    for record in records:
        owner = query.question[0].name
        if len(record) == 3:
            owner, record = record[0], record[1:]
        reply.answer.append(dns.rrset.from_text(owner, ttl, "IN", *record))
    return reply


def default_handler(query, wire):
    rdtype = query.question[0].rdtype
    if rdtype == 1:
        return answer(query, ("A", "192.0.2.1"))
    if rdtype == 28:
        return answer(query, ("AAAA", "2001:db8::1"))
    return answer(query)


def _to_wires(result):
    if result is None:
        return []
    if not isinstance(result, list):
        result = [result]
    # max_size: make_response() limits to_wire() to the requester's EDNS size by default.
    return [item.to_wire(max_size=65535) if isinstance(item, dns.message.Message) else item for item in result]


class UdpServer:
    def __init__(self, handler=default_handler):
        self.handler = handler
        self.queries = []  # (message, wire, client address)
        self.transport = None

    async def start(self, host="127.0.0.1", port=0):
        loop = asyncio.get_running_loop()
        server = self

        class Protocol(asyncio.DatagramProtocol):
            def datagram_received(self, data, addr):
                loop.create_task(server._answer(data, addr))

        self.transport, _ = await loop.create_datagram_endpoint(Protocol, local_addr=(host, port))
        return self

    async def _answer(self, data, addr):
        message = dns.message.from_wire(data)
        self.queries.append((message, data, addr))
        result = self.handler(message, data)
        if asyncio.iscoroutine(result):
            result = await result
        for wire in _to_wires(result):
            self.transport.sendto(wire, addr)

    @property
    def port(self):
        return self.transport.get_extra_info("sockname")[1]

    def close(self):
        self.transport.close()


class StreamServer:
    """TCP (or TLS, with ``ssl_context``) DNS server.

    ``reverse`` answers each batch of pipelined queries in reverse order;
    ``close_after`` closes a connection after that many replies.
    """

    def __init__(self, handler=default_handler, *, ssl_context=None, reverse=False, close_after=None):
        self.handler = handler
        self.ssl_context = ssl_context
        self.reverse = reverse
        self.close_after = close_after
        self.queries = []
        self.connections = 0
        self.server = None

    async def start(self, host="127.0.0.1", port=0):
        self.server = await asyncio.start_server(self._serve, host, port, ssl=self.ssl_context)
        return self

    @property
    def port(self):
        return self.server.sockets[0].getsockname()[1]

    async def _serve(self, reader, writer):
        self.connections += 1
        replies = 0
        try:
            while True:
                batch = [await self._read(reader)]
                if self.reverse:  # collect whatever else is already buffered
                    await asyncio.sleep(0.05)
                    while len(reader._buffer) >= 2:  # noqa: SLF001 - test helper
                        batch.append(await self._read(reader))
                    batch.reverse()
                for data in batch:
                    message = dns.message.from_wire(data)
                    self.queries.append((message, data, None))
                    result = self.handler(message, data)
                    if asyncio.iscoroutine(result):
                        result = await result
                    for wire in _to_wires(result):
                        writer.write(len(wire).to_bytes(2, "big") + wire)
                    await writer.drain()
                    replies += 1
                    if self.close_after is not None and replies >= self.close_after:
                        return
        except (asyncio.IncompleteReadError, ConnectionError, ssl.SSLError):
            pass
        finally:
            writer.close()

    @staticmethod
    async def _read(reader):
        size = int.from_bytes(await reader.readexactly(2), "big")
        return await reader.readexactly(size)

    def close(self):
        self.server.close()


def make_test_ca(directory, names=("dns.test",), ips=("127.0.0.1", "::1"), valid=(-1, 24)):
    """Write a CA and a server certificate signed by it; returns their paths.

    ``valid`` is the server certificate's validity window in hours relative
    to now, e.g. ``(24, 48)`` for "not yet valid" or ``(-48, -24)`` for "expired".

    Needs the ``cryptography`` package (tests using it are skipped without it).
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "blockads-linux test CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=7)).not_valid_after(now + datetime.timedelta(days=7))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    key = ec.generate_private_key(ec.SECP256R1())
    alt_names = [x509.DNSName(n) for n in names] + [x509.IPAddress(ipaddress.ip_address(i)) for i in ips]
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])]))
        .issuer_name(ca_name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now + datetime.timedelta(hours=valid[0]))
        .not_valid_after(now + datetime.timedelta(hours=valid[1]))
        .add_extension(x509.SubjectAlternativeName(alt_names), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    pem = serialization.Encoding.PEM
    ca_path, cert_path, key_path = directory / "ca.pem", directory / "server.pem", directory / "server.key"
    ca_path.write_bytes(ca_cert.public_bytes(pem))
    cert_path.write_bytes(cert.public_bytes(pem))
    key_path.write_bytes(key.private_bytes(pem, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return ca_path, cert_path, key_path


def server_tls_context(cert_path, key_path, alpn=()):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    if alpn:
        context.set_alpn_protocols(list(alpn))
    return context


class DohServer:
    """Minimal DoH server: HTTP/2 over TLS (ALPN h2), built on the h2 library.

    ``respond(query, request)`` may return ``(status, headers, body)`` to
    override the reply; by default the handler's answer is sent as
    ``200 application/dns-message``. ``request`` holds the request headers
    and body, and every request is recorded in ``requests``.
    """

    def __init__(self, ssl_context, handler=default_handler, respond=None, delay=0.0):
        self.ssl_context = ssl_context
        self.handler = handler
        self.respond = respond
        self.delay = delay
        self.requests = []
        self.connections = 0
        self.server = None

    async def start(self, host="127.0.0.1"):
        self.server = await asyncio.start_server(self._serve, host, 0, ssl=self.ssl_context)
        return self

    @property
    def port(self):
        return self.server.sockets[0].getsockname()[1]

    def close(self):
        self.server.close()

    async def _serve(self, reader, writer):
        import h2.config
        import h2.connection
        import h2.events

        self.connections += 1
        conn = h2.connection.H2Connection(h2.config.H2Configuration(client_side=False, header_encoding="utf-8"))
        conn.initiate_connection()
        writer.write(conn.data_to_send())
        streams, outgoing, tasks = {}, {}, set()

        def flush():
            for stream_id, data in list(outgoing.items()):
                size = min(len(data), conn.local_flow_control_window(stream_id), conn.max_outbound_frame_size)
                while size > 0:
                    conn.send_data(stream_id, data[:size])
                    data = data[size:]
                    size = min(len(data), conn.local_flow_control_window(stream_id), conn.max_outbound_frame_size)
                if data:
                    outgoing[stream_id] = data
                else:
                    del outgoing[stream_id]
                    conn.end_stream(stream_id)
            writer.write(conn.data_to_send())

        async def reply(stream_id, request):
            if self.delay:
                await asyncio.sleep(self.delay)
            query = dns.message.from_wire(request["body"]) if request["body"] else None
            override = self.respond(query, request) if self.respond else None
            if override is None:
                wires = _to_wires(self.handler(query, request["body"]))
                override = (200, {"content-type": "application/dns-message"}, wires[0] if wires else b"")
            status, headers, body = override
            response_headers = [(":status", str(status)), ("content-length", str(len(body)))]
            response_headers += list(headers.items())
            conn.send_headers(stream_id, response_headers)
            outgoing[stream_id] = body
            flush()
            await writer.drain()

        try:
            while True:
                data = await reader.read(65535)
                if not data:
                    break
                for event in conn.receive_data(data):
                    if isinstance(event, h2.events.RequestReceived):
                        streams[event.stream_id] = {"headers": dict(event.headers), "body": b""}
                    elif isinstance(event, h2.events.DataReceived):
                        streams[event.stream_id]["body"] += event.data
                        conn.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                    elif isinstance(event, h2.events.StreamEnded):
                        request = streams.pop(event.stream_id)
                        self.requests.append(request)
                        task = asyncio.get_running_loop().create_task(reply(event.stream_id, request))
                        tasks.add(task)
                        task.add_done_callback(tasks.discard)
                    elif isinstance(event, h2.events.WindowUpdated):
                        flush()
                    elif isinstance(event, h2.events.ConnectionTerminated):
                        return
                writer.write(conn.data_to_send())
                await writer.drain()
        except (ConnectionError, ssl.SSLError, asyncio.IncompleteReadError):
            pass
        finally:
            for task in tasks:
                task.cancel()
            writer.close()
