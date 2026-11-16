"""DNS Stamps (``sdns://``): decoding and encoding.

Format: https://dnscrypt.info/stamps-specifications. A stamp is
``"sdns://" + base64url(protocol byte || fields)`` without padding; ``LP`` is
a one-byte length prefix, ``VLP`` a set of LP items in which every item but
the last has the length's high bit set.

Port of the parsing done by blockads-android ``tunnel/internal/dns/stamp.go``
(revision fc95d66a, which wraps go-dnsstamps). The encoder mirrors
go-dnsstamps' ``String()``, including dropping the protocol's default port, so
upstream's round-trip vectors can be ported. Only plain DNS, DoT and DoH
stamps can become upstreams here; DNSCrypt, DoQ and ODoH decode but are
reported as unsupported by :func:`stamp_to_spec`.
"""

from __future__ import annotations

import base64
import binascii
import enum
import ipaddress
from dataclasses import dataclass

PREFIX = "sdns://"
MAX_STAMP_LENGTH = 4096


class StampError(ValueError):
    """Malformed or unsupported stamp."""


class Proto(enum.IntEnum):
    PLAIN = 0x00
    DNSCRYPT = 0x01
    DOH = 0x02
    DOT = 0x03
    DOQ = 0x04
    ODOH_TARGET = 0x05
    DNSCRYPT_RELAY = 0x81
    ODOH_RELAY = 0x85


PROP_DNSSEC = 1 << 0
PROP_NO_LOG = 1 << 1
PROP_NO_FILTER = 1 << 2

DEFAULT_PORTS = {Proto.PLAIN: 53, Proto.DNSCRYPT: 443, Proto.DOH: 443, Proto.DOT: 853, Proto.DOQ: 853,
                 Proto.ODOH_TARGET: 443, Proto.DNSCRYPT_RELAY: 443, Proto.ODOH_RELAY: 443}


@dataclass(frozen=True, slots=True)
class Stamp:
    proto: Proto
    props: int = 0
    server_addr: str = ""  # "ip", "ip:port" or "[ipv6]:port"
    hashes: tuple[bytes, ...] = ()
    provider_name: str = ""  # hostname[:port] (DoH, DoT, DoQ, ODoH) or DNSCrypt provider name
    path: str = ""
    bootstrap_ips: tuple[str, ...] = ()
    public_key: bytes = b""

    @property
    def dnssec(self) -> bool:
        return bool(self.props & PROP_DNSSEC)

    @property
    def no_log(self) -> bool:
        return bool(self.props & PROP_NO_LOG)

    @property
    def no_filter(self) -> bool:
        return bool(self.props & PROP_NO_FILTER)

    @property
    def address(self) -> str:
        """The server IP without port (upstream strips it the same way)."""
        return split_host_port(self.server_addr, 0)[0] if self.server_addr else ""

    @property
    def port(self) -> int:
        port_source = self.server_addr or self.provider_name
        return split_host_port(port_source, DEFAULT_PORTS[self.proto])[1] if port_source else DEFAULT_PORTS[self.proto]

    @property
    def hostname(self) -> str:
        return split_host_port(self.provider_name, 0)[0] if self.provider_name else ""

    @property
    def url(self) -> str:
        """Endpoint as upstream's ``StampInfo.URL`` presents it."""
        if self.proto in (Proto.DOH, Proto.ODOH_TARGET):
            path = self.path or "/dns-query"
            if not path.startswith("/"):
                path = "/" + path
            return f"https://{self.provider_name or self.server_addr}{path}"
        if self.proto == Proto.DOQ:
            return f"quic://{self.provider_name or self.server_addr}"
        if self.proto == Proto.DOT:
            return self.provider_name or self.server_addr
        return self.server_addr

    def to_string(self) -> str:
        out = bytearray([self.proto])
        if self.proto in (Proto.DNSCRYPT_RELAY,):
            out += _lp(self.server_addr.encode())
            return _encode(out)
        out += self.props.to_bytes(8, "little")
        default = DEFAULT_PORTS[self.proto]
        if self.proto == Proto.ODOH_TARGET:
            out += _lp(self.provider_name.encode()) + _lp(self.path.encode())
            return _encode(out)
        out += _lp(_strip_default_port(self.server_addr, default).encode())
        if self.proto == Proto.PLAIN:
            return _encode(out)
        if self.proto == Proto.DNSCRYPT:
            out += _lp(self.public_key) + _lp(self.provider_name.encode())
            return _encode(out)
        out += _vlp(self.hashes) + _lp(_strip_default_port(self.provider_name, default).encode())
        if self.proto in (Proto.DOH, Proto.ODOH_RELAY):
            out += _lp(self.path.encode())
        if self.bootstrap_ips:
            out += _vlp(tuple(ip.encode() for ip in self.bootstrap_ips))
        return _encode(out)


def split_host_port(text: str, default_port: int) -> tuple[str, int]:
    """``"1.2.3.4:53"`` / ``"[::1]:53"`` / ``"host"`` -> (host, port)."""
    if text.startswith("["):
        end = text.find("]")
        if end < 0:
            raise StampError(f"bad address: {text!r}")
        host, rest = text[1:end], text[end + 1 :]
        if rest and not rest.startswith(":"):
            raise StampError(f"bad address: {text!r}")
        port_text = rest[1:]
    elif text.count(":") == 1:
        host, port_text = text.split(":")
    else:
        host, port_text = text, ""  # a bare IPv6 address has several colons
    if not port_text:
        return host, default_port
    if not port_text.isdigit() or not 0 < int(port_text) < 65536:
        raise StampError(f"bad port in {text!r}")
    return host, int(port_text)


def _strip_default_port(text: str, default: int) -> str:
    suffix = f":{default}"
    return text[: -len(suffix)] if text.endswith(suffix) else text


def _encode(data: bytes | bytearray) -> str:
    return PREFIX + base64.urlsafe_b64encode(bytes(data)).decode("ascii").rstrip("=")


def _lp(data: bytes) -> bytes:
    if len(data) > 255:
        raise StampError("field too long")
    return bytes([len(data)]) + data


def _vlp(items: tuple[bytes, ...]) -> bytes:
    if not items:
        return b"\x00"
    out = bytearray()
    for index, item in enumerate(items):
        if len(item) > 127:
            raise StampError("set item too long")
        out.append(len(item) | (0x80 if index < len(items) - 1 else 0))
        out += item
    return bytes(out)


class _Reader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def take(self, size: int) -> bytes:
        if self.pos + size > len(self.data):
            raise StampError("stamp is truncated")
        chunk = self.data[self.pos : self.pos + size]
        self.pos += size
        return chunk

    def lp(self) -> bytes:
        return self.take(self.take(1)[0])

    def vlp(self) -> tuple[bytes, ...]:
        items = []
        while True:
            head = self.take(1)[0]
            items.append(self.take(head & 0x7F))
            if not head & 0x80:
                break
        return tuple(items) if items != [b""] else ()

    @property
    def done(self) -> bool:
        return self.pos == len(self.data)


def _text(data: bytes) -> str:
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        raise StampError("non-ASCII text field") from None
    if any(ord(ch) < 0x21 or ord(ch) == 0x7F for ch in text):
        raise StampError("control character or space in a text field")
    return text


def parse_stamp(text: str) -> Stamp:
    if not isinstance(text, str) or not text.startswith(PREFIX) or len(text) > MAX_STAMP_LENGTH:
        raise StampError("not an sdns:// stamp")
    body = text[len(PREFIX) :]
    # Check the alphabet first: b64decode silently skips characters outside it.
    if not body or any(ch not in _B64URL for ch in body):
        raise StampError("stamp is not valid base64url")
    try:
        data = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
    except (binascii.Error, ValueError):
        raise StampError("stamp is not valid base64url") from None
    reader = _Reader(data)
    try:
        proto = Proto(reader.take(1)[0])
    except ValueError:
        raise StampError("unknown stamp protocol") from None
    if proto == Proto.DNSCRYPT_RELAY:
        stamp = Stamp(proto, server_addr=_text(reader.lp()))
    else:
        props = int.from_bytes(reader.take(8), "little")
        if proto == Proto.ODOH_TARGET:
            stamp = Stamp(proto, props, provider_name=_text(reader.lp()), path=_text(reader.lp()))
        else:
            addr = _text(reader.lp())
            if proto == Proto.PLAIN:
                stamp = Stamp(proto, props, server_addr=addr)
            elif proto == Proto.DNSCRYPT:
                stamp = Stamp(proto, props, server_addr=addr, public_key=reader.lp(), provider_name=_text(reader.lp()))
            else:
                hashes = reader.vlp()
                name = _text(reader.lp())
                path = _text(reader.lp()) if proto in (Proto.DOH, Proto.ODOH_RELAY) else ""
                bootstrap = tuple(_text(ip) for ip in reader.vlp()) if not reader.done else ()
                stamp = Stamp(proto, props, addr, hashes, name, path, bootstrap)
    if not reader.done:
        raise StampError("trailing data in stamp")
    if stamp.server_addr:
        host, _port = split_host_port(stamp.server_addr, DEFAULT_PORTS[proto])
        try:
            ipaddress.ip_address(host)
        except ValueError:
            raise StampError(f"server address is not an IP: {host!r}") from None
    return stamp


_B64URL = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
