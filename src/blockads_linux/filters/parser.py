"""Filter-list line parser.

A line-by-line port of blockads-android's DNS rule extraction
(``tunnel/internal/trie/parser.go: parseDomainLine`` and the line handling in
``compiler.go: CompileFilterList``, upstream revision fc95d66a), so that a
list yields exactly the same blocked domains as on Android.

Documented deviations ("@@ exceptions"):

* ``@@`` exception lines are not discarded. Their remainder is parsed with the
  same rules and returned as an EXCEPTION, which the matcher applies only to the
  list that declares it.
* ``$important`` on a block rule is reported, so that a same-list exception does
  not cancel it (AdGuard semantics). Upstream ignores ``$important`` because it
  drops exceptions altogether.
* Lines longer than :data:`MAX_LINE_LENGTH` are skipped. Upstream's scanner
  aborts the whole compilation on such a line.

The helpers below reproduce Go's ``strings.TrimSpace``/``strings.Fields``
(``unicode.IsSpace``) and ``strings.ToLower`` (simple case mapping), which
differ from Python's built-ins on a few code points.
"""

from __future__ import annotations

import enum
import ipaddress
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass

#: Upstream's bufio.Scanner limit; longer lines are skipped here.
MAX_LINE_LENGTH = 1024 * 1024

# unicode.IsSpace: Latin-1 spaces plus the White_Space property.
_GO_SPACE = (
    "\t\n\v\f\r \x85\xa0 "
    "           "
    "    　"
)
_GO_FIELDS_SPLIT = re.compile("[" + re.escape(_GO_SPACE) + "]+")

_COSMETIC_MARKERS = ("##", "#@#", "#?#", "#$#", "#%#")
_ALLOWED_OPTIONS = frozenset(
    {"", "important", "empty", "mp4", "all", "popup", "document", "doc", "dns", "cname", "network"}
)
_ALLOWED_OPTION_PREFIXES = ("dnstype", "ctag", "denyallow")
_REJECTED_NAMES = frozenset({"", "localhost", "localhost.localdomain", "local", "broadcasthost"})
_LABEL_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-_")
_DIGITS = frozenset("0123456789")
_DIGITS_AND_DOT = frozenset("0123456789.")


def go_trim_space(text: str) -> str:
    """Equivalent of Go's ``strings.TrimSpace``."""
    return text.strip(_GO_SPACE)


def go_to_lower(text: str) -> str:
    """Equivalent of Go's ``strings.ToLower`` (simple case mapping).

    Python's ``str.lower`` applies the full mapping, which turns U+0130 into
    "i" + U+0307; Go maps it to plain "i". No other lowercase mapping differs
    in a way that can produce ASCII.
    """
    return text.replace("İ", "i").lower()


def go_fields(text: str) -> list[str]:
    """Equivalent of Go's ``strings.Fields``."""
    trimmed = go_trim_space(text)
    return _GO_FIELDS_SPLIT.split(trimmed) if trimmed else []


def _is_ipv4_literal(domain: str) -> bool:
    """Mirror of the upstream check: digits/dots only and a valid IP address."""
    if domain[0] not in _DIGITS or not set(domain) <= _DIGITS_AND_DOT:
        return False
    try:
        ipaddress.IPv4Address(domain)  # rejects leading zeros, like Go >= 1.17
    except ValueError:
        return False
    return True


def _options_allowed(options: str) -> tuple[bool, bool]:
    """Return (all options allowed, has $important)."""
    important = False
    for raw in options.split(","):
        opt = go_trim_space(raw)
        if opt in _ALLOWED_OPTIONS or opt.startswith(_ALLOWED_OPTION_PREFIXES):
            important = important or opt == "important"
            continue
        return False, False
    return True, important


def _parse(line: str) -> tuple[str, bool]:
    """Port of ``parseDomainLine``; also reports ``$important``."""
    line = go_trim_space(line)
    if not line or line[0] in "#!":
        return "", False
    if line.startswith("@@"):
        return "", False
    if any(marker in line for marker in _COSMETIC_MARKERS):
        return "", False

    # Wildcard domain format: *.example.com (HaGeZi wildcard, OISD domainswild)
    line = line.removeprefix("*.")

    # dnsmasq format: server=/domain.com/ or address=/domain.com/0.0.0.0
    if line.startswith(("server=/", "address=/")):
        clean = line.removeprefix("server=/").removeprefix("address=/")
        slash = clean.find("/")
        if slash != -1:
            line = clean[:slash]

    is_abp = line.startswith("||")
    if not is_abp and any(ch in line for ch in "$/\\*"):
        return "", False

    domain = ""
    important = False
    if is_abp:
        domain = line[2:].removeprefix("*.").removeprefix("*")
        # Wildcards (*, ?) or paths (/) make it a URL-level rule.
        if any(ch in domain for ch in "/*?"):
            return "", False
        dollar = domain.find("$")
        if dollar != -1:
            allowed, important = _options_allowed(domain[dollar + 1 :])
            if not allowed:
                return "", False
            domain = domain[:dollar]
        caret = domain.find("^")
        if caret != -1:
            domain = domain[:caret]
    elif line.startswith(("0.0.0.0 ", "127.0.0.1 ")):
        fields = go_fields(line)
        if len(fields) >= 2:
            domain = fields[1]
        hash_idx = domain.find("#")
        if hash_idx != -1:
            domain = domain[:hash_idx]
    elif " " not in line and "\t" not in line and "." in line:
        domain = line

    domain = go_trim_space(go_to_lower(domain))
    if domain in _REJECTED_NAMES:
        return "", False
    if "." not in domain and not is_abp:
        return "", False
    if _is_ipv4_literal(domain):
        return "", False

    labels = domain.split(".")
    if len(labels) < 2 and not is_abp:
        return "", False
    for label in labels:
        if not label or not set(label) <= _LABEL_CHARS:
            return "", False
        if label[0] in "-_" or label[-1] in "-_":
            return "", False
    return domain, important


def parse_domain_line(line: str) -> str:
    """Exact port of upstream ``parseDomainLine``: the blocked domain, or ""."""
    return _parse(line)[0]


class RuleKind(enum.Enum):
    BLOCK = "block"
    EXCEPTION = "exception"


@dataclass(frozen=True, slots=True)
class ListRule:
    kind: RuleKind
    domain: str
    important: bool = False


def parse_list_line(raw_line: str) -> ListRule | None:
    """Classify one filter-list line for DNS filtering.

    Block rules are exactly what upstream compiles. ``@@`` lines become
    list-scoped exceptions (our extension) using the same domain rules.
    """
    line = go_trim_space(raw_line)
    if len(line) > MAX_LINE_LENGTH:
        return None
    if line.startswith("@@"):
        domain, _ = _parse(line[2:])
        return ListRule(RuleKind.EXCEPTION, domain) if domain else None
    domain, important = _parse(line)
    return ListRule(RuleKind.BLOCK, domain, important) if domain else None


def iter_list_rules(lines: Iterable[str]) -> Iterator[ListRule]:
    """Yield the DNS rules of a filter list, line by line (not de-duplicated)."""
    for line in lines:
        rule = parse_list_line(line)
        if rule is not None:
            yield rule


def iter_binary_lines(stream: Iterable[bytes]) -> Iterator[str]:
    """Decode lines from a binary stream (e.g. an open file) like Go's ``bufio.ScanLines``.

    Streaming: memory use does not grow with list size. A trailing ``\\r`` is
    dropped; invalid UTF-8 becomes U+FFFD, which no rule accepts (as in Go).
    """
    for raw in stream:
        yield raw.removesuffix(b"\n").removesuffix(b"\r").decode("utf-8", errors="replace")
