"""Compiled filter-list artifacts (``<sha256>.bkf``).

A compiled list is a flat, memory-mappable file of sorted 64-bit domain hashes,
so the DNS daemon never parses list text (that happens in the sandboxed updater)
and needs about 8 bytes of shared page cache per rule.

Layout (all integers little-endian)::

    offset size  field
    0      4     magic  b"BKAF"
    4      2     format version (1)
    6      1     min_labels        fewest labels in a block rule (0 if none)
    7      1     max_labels        most labels in a block rule (capped at 255)
    8      4     block_count       sorted unique u64 hashes of blocked domains
    12     4     important_count   subset of block hashes marked $important
    16     4     exception_count   list-scoped @@ exception hashes
    20     4     prefilter_log2    k: the prefilter has 2**k bits (0 = none)
    24     32    SHA-256 of the downloaded source list
    56     8     compiled-at, Unix seconds
    64     ...   block hashes, important hashes, exception hashes (u64 each),
                 then the block prefilter bitmap (2**k / 8 bytes)

The prefilter is a one-hash-function bitmap indexed by the top k bits of each
block hash (k is about log2(block_count) + 3, i.e. ~1 byte per rule and a ~7%
false-positive rate). A clear bit proves a miss without a binary search; a set
bit is always confirmed against the exact sorted array, so the prefilter never
changes results, only speed.

The file name is the SHA-256 of the whole file (content addressing). It is
verified on load, so a truncated or tampered file is rejected.
"""

from __future__ import annotations

import hashlib
import mmap
import os
import struct
import sys
import tempfile
from array import array
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

from .parser import ListRule, RuleKind

MAGIC = b"BKAF"
VERSION = 1
HEADER = struct.Struct("<4sHBBIIII32sQ")
HEADER_SIZE = 64
assert HEADER.size == HEADER_SIZE
SUFFIX = ".bkf"
#: Upper bound on rules accepted from one list (raw adds, before de-duplication).
DEFAULT_MAX_ENTRIES = 10_000_000
_MIN_PREFILTER_LOG2 = 10
_MAX_PREFILTER_LOG2 = 28  # 32 MiB bitmap: enough for the 10M-entry cap


def prefilter_log2_for(count: int) -> int:
    """Bitmap size (log2 of bits) for ``count`` block entries; 0 when empty."""
    if count == 0:
        return 0
    return max(_MIN_PREFILTER_LOG2, min(_MAX_PREFILTER_LOG2, (count - 1).bit_length() + 3))


def build_prefilter(block: Sequence[int], log2: int) -> bytes:
    bitmap = bytearray((1 << log2) // 8 if log2 else 0)
    shift = 64 - log2
    for value in block:
        bit = value >> shift
        bitmap[bit >> 3] |= 1 << (bit & 7)
    return bytes(bitmap)


class ArtifactError(ValueError):
    """An artifact is malformed, truncated, or does not match its name."""


def domain_hash(domain: str) -> int:
    """Stable 64-bit hash of a normalized (lowercase, no trailing dot) domain."""
    digest = hashlib.blake2b(domain.encode("utf-8", "surrogateescape"), digest_size=8).digest()
    return int.from_bytes(digest, "little")


@dataclass(frozen=True, slots=True)
class ArtifactInfo:
    name: str  # "<sha256>.bkf"
    sha256: str
    block_count: int
    important_count: int
    exception_count: int
    source_sha256: str
    compiled_at: int
    min_labels: int = 0
    max_labels: int = 0

    @property
    def rule_count(self) -> int:
        return self.block_count


def _sorted_unique(values: array) -> array:
    out = array("Q")
    previous = None
    for value in sorted(values):
        if value != previous:
            out.append(value)
            previous = value
    return out


class TooManyRules(ArtifactError):
    """A list exceeded the entry limit (protects the updater's memory)."""


class ArtifactBuilder:
    """Accumulates parsed rules and writes a content-addressed artifact."""

    def __init__(self, max_entries: int = DEFAULT_MAX_ENTRIES) -> None:
        self._max = max_entries
        self._count = 0
        self._block = array("Q")
        self._important = array("Q")
        self._exception = array("Q")
        self._min_labels = 255
        self._max_labels = 0

    @property
    def raw_count(self) -> int:
        return self._count

    def add(self, rule: ListRule) -> None:
        self._count += 1
        if self._count > self._max:
            raise TooManyRules(f"more than {self._max} rules")
        value = domain_hash(rule.domain)
        if rule.kind is RuleKind.EXCEPTION:
            self._exception.append(value)
        else:
            self._block.append(value)
            labels = min(255, rule.domain.count(".") + 1)
            self._min_labels = min(self._min_labels, labels)
            self._max_labels = max(self._max_labels, labels)
            if rule.important:
                self._important.append(value)

    def add_rules(self, rules: Iterable[ListRule]) -> None:
        for rule in rules:
            self.add(rule)

    def write(self, directory: Path, *, source_sha256: bytes, compiled_at: int) -> ArtifactInfo:
        """Write ``<sha256>.bkf`` into ``directory`` atomically and return its info."""
        if len(source_sha256) != 32:
            raise ValueError("source_sha256 must be 32 bytes")
        block = _sorted_unique(self._block)
        important = _sorted_unique(self._important)
        exception = _sorted_unique(self._exception)
        if not block and not exception:
            raise ArtifactError("no valid rules found in filter list")
        prefilter_log2 = prefilter_log2_for(len(block))
        prefilter = build_prefilter(block, prefilter_log2)
        min_labels, max_labels = (self._min_labels, self._max_labels) if block else (0, 0)
        header = HEADER.pack(
            MAGIC, VERSION, min_labels, max_labels, len(block), len(important), len(exception), prefilter_log2,
            source_sha256, compiled_at,
        )
        directory.mkdir(parents=True, exist_ok=True)
        digest = hashlib.sha256(header)
        fd, tmp_name = tempfile.mkstemp(prefix=".tmp-", suffix=SUFFIX, dir=directory)
        try:
            with os.fdopen(fd, "wb") as out:
                out.write(header)
                for section in (block, important, exception):
                    data = _to_little_endian_bytes(section)
                    digest.update(data)
                    out.write(data)
                digest.update(prefilter)
                out.write(prefilter)
                out.flush()
                os.fsync(out.fileno())
            sha = digest.hexdigest()
            final = directory / f"{sha}{SUFFIX}"
            os.replace(tmp_name, final)
            _fsync_dir(directory)
        except BaseException:
            Path(tmp_name).unlink(missing_ok=True)
            raise
        return ArtifactInfo(
            name=final.name,
            sha256=sha,
            block_count=len(block),
            important_count=len(important),
            exception_count=len(exception),
            source_sha256=source_sha256.hex(),
            compiled_at=compiled_at,
            min_labels=min_labels,
            max_labels=max_labels,
        )


def _to_little_endian_bytes(values: array) -> bytes:
    if sys.byteorder == "little":
        return values.tobytes()
    swapped = array("Q", values)
    swapped.byteswap()
    return swapped.tobytes()


def _fsync_dir(directory: Path) -> None:
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def u64_view(buffer: memoryview, little_endian_host: bool = sys.byteorder == "little") -> Sequence[int]:
    """View little-endian u64 data as a sequence of ints (zero-copy on LE hosts)."""
    if little_endian_host:
        return buffer.cast("Q")
    values = array("Q")
    values.frombytes(buffer.tobytes())
    values.byteswap()
    return values


class LoadedArtifact:
    """A memory-mapped, verified artifact. Read-only and safe to share."""

    __slots__ = ("info", "block", "important", "exception", "prefilter", "prefilter_shift", "_mm")

    def __init__(self, info: ArtifactInfo, block: Sequence[int], important: Sequence[int],
                 exception: Sequence[int], prefilter: Sequence[int], prefilter_log2: int,
                 mm: mmap.mmap | None) -> None:
        self.info = info
        self.block = block
        self.important = important
        self.exception = exception
        self.prefilter = prefilter  # bytes-like: indexing yields ints
        self.prefilter_shift = 64 - prefilter_log2
        self._mm = mm

    def may_contain_block(self, value: int) -> bool:
        """Prefilter check: False proves ``value`` is not a block hash."""
        if not self.prefilter:
            return False
        bit = value >> self.prefilter_shift
        return bool(self.prefilter[bit >> 3] >> (bit & 7) & 1)

    @classmethod
    def open(cls, path: Path, *, verify_name: bool = True) -> "LoadedArtifact":
        with open(path, "rb") as handle:
            size = os.fstat(handle.fileno()).st_size
            if size < HEADER_SIZE:
                raise ArtifactError(f"{path.name}: truncated header")
            mm = mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            return cls._from_buffer(mm, path.name, verify_name)
        except BaseException:
            mm.close()
            raise

    @classmethod
    def _from_buffer(cls, mm: mmap.mmap, name: str, verify_name: bool) -> "LoadedArtifact":
        (magic, version, min_labels, max_labels, n_block, n_important, n_exception, prefilter_log2,
         source, compiled_at) = (
            HEADER.unpack_from(mm, 0)
        )
        if magic != MAGIC:
            raise ArtifactError(f"{name}: bad magic")
        if version != VERSION:
            raise ArtifactError(f"{name}: unsupported version {version}")
        if (n_block == 0) != (min_labels == 0 and max_labels == 0) or min_labels > max_labels:
            raise ArtifactError(f"{name}: inconsistent label range")
        if n_important > n_block:
            raise ArtifactError(f"{name}: more important entries than block entries")
        if prefilter_log2 != prefilter_log2_for(n_block):
            raise ArtifactError(f"{name}: unexpected prefilter size 2**{prefilter_log2}")
        prefilter_bytes = (1 << prefilter_log2) // 8 if prefilter_log2 else 0
        expected = HEADER_SIZE + 8 * (n_block + n_important + n_exception) + prefilter_bytes
        if len(mm) != expected:
            raise ArtifactError(f"{name}: size {len(mm)} does not match header ({expected})")
        sha = hashlib.sha256(mm).hexdigest()
        if verify_name and name != f"{sha}{SUFFIX}":
            raise ArtifactError(f"{name}: content hash mismatch")
        view = memoryview(mm)
        sections = []
        offset = HEADER_SIZE
        for count in (n_block, n_important, n_exception):
            sections.append(u64_view(view[offset : offset + 8 * count]))
            offset += 8 * count
        prefilter = view[offset : offset + prefilter_bytes]
        info = ArtifactInfo(
            name=name, sha256=sha, block_count=n_block, important_count=n_important,
            exception_count=n_exception, source_sha256=bytes(source).hex(), compiled_at=compiled_at,
            min_labels=min_labels, max_labels=max_labels,
        )
        return cls(info, sections[0], sections[1], sections[2], prefilter, prefilter_log2, mm)
