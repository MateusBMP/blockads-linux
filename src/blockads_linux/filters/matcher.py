"""Domain matching against compiled filter lists.

Semantics follow blockads-android's trie ``ContainsOrParent``: a rule for
``example.com`` matches ``example.com`` and every subdomain. On top of that, an
``@@`` exception cancels blocks *of the same list only*, unless the block is
``$important``. Every list that blocks a name is
reported, security lists first, like upstream's comma-joined ``blockedBy``.

Lookups do not allocate per list: suffix hashes are computed once per query and
each list is a binary search over a sorted, memory-mapped u64 array.
"""

from __future__ import annotations

import functools
from bisect import bisect_left
from collections.abc import Sequence
from dataclasses import dataclass

from .artifact import LoadedArtifact, domain_hash

#: DNS names have at most 127 labels; longer input is cut to its parent-most part.
MAX_LABELS = 128


def suffixes(domain: str) -> list[str]:
    """``"a.b.c"`` -> ``["a.b.c", "b.c", "c"]`` (most specific first)."""
    if not domain:
        return []
    labels = domain.split(".")
    start = max(0, len(labels) - MAX_LABELS)
    return [".".join(labels[i:]) for i in range(start, len(labels))]


def _contains(values: Sequence[int], value: int) -> bool:
    index = bisect_left(values, value)
    return index < len(values) and values[index] == value


def _first_match(values: Sequence[int], hashes: Sequence[int]) -> int:
    """Index in ``hashes`` of the first (most specific) member of ``values``, or -1."""
    if len(values):
        for position, value in enumerate(hashes):
            if _contains(values, value):
                return position
    return -1


@dataclass(frozen=True, slots=True)
class FilterList:
    list_id: str
    rank: int  # category order: lower is checked (and reported) first
    artifact: LoadedArtifact


@dataclass(frozen=True, slots=True)
class MatchResult:
    blocked: bool
    lists: tuple[str, ...] = ()
    matched: str | None = None  # the (most specific) blocked suffix

    @property
    def reason(self) -> str:
        """Upstream-compatible ``blockedBy`` value: comma-joined list ids."""
        return ",".join(self.lists)


NOT_BLOCKED = MatchResult(False)


class FilterMatcher:
    """Immutable set of enabled lists; replaced atomically when lists change."""

    def __init__(self, lists: Sequence[FilterList] = (), cache_size: int = 16384) -> None:
        self._lists = tuple(sorted(lists, key=lambda f: (f.rank, f.list_id)))
        # Verdicts are cached per matcher instance. A rule or list change builds
        # a new matcher (and so a new, empty cache): no stale verdicts possible.
        self._cached = functools.lru_cache(maxsize=cache_size)(self._match_uncached) if cache_size else None

    @property
    def list_ids(self) -> tuple[str, ...]:
        return tuple(f.list_id for f in self._lists)

    @property
    def rule_count(self) -> int:
        return sum(f.artifact.info.block_count for f in self._lists)

    def match(self, domain: str) -> MatchResult:
        """Check a normalized name (lowercase, no trailing dot) against every list."""
        if self._cached is not None:
            return self._cached(domain)
        return self._match_uncached(domain)

    def _match_uncached(self, domain: str) -> MatchResult:
        if not self._lists:
            return NOT_BLOCKED
        names = suffixes(domain)
        if not names:
            return NOT_BLOCKED
        hashes = [domain_hash(name) for name in names]
        count = len(names)  # names[i] has (count - i) labels
        blocking: list[str] = []
        matched_at = count
        for flist in self._lists:
            artifact = flist.artifact
            info = artifact.info
            position = _first_match(artifact.important, hashes) if info.important_count else -1
            if position < 0:
                # Hot path, inlined: the prefilter bitmap rejects most misses
                # with one byte read; set bits are confirmed by binary search.
                prefilter = artifact.prefilter
                if prefilter:
                    shift = artifact.prefilter_shift
                    block = artifact.block
                    size = len(block)
                    # Only suffixes whose label count can occur in this list.
                    for index in range(max(0, count - info.max_labels), count - info.min_labels + 1):
                        value = hashes[index]
                        bit = value >> shift
                        if prefilter[bit >> 3] >> (bit & 7) & 1:
                            found = bisect_left(block, value)
                            if found < size and block[found] == value:
                                position = index
                                break
                if position >= 0 and info.exception_count and _first_match(artifact.exception, hashes) >= 0:
                    position = -1  # cancelled by this list's own exception
            if position >= 0:
                blocking.append(flist.list_id)
                matched_at = min(matched_at, position)
        if not blocking:
            return NOT_BLOCKED
        return MatchResult(True, tuple(blocking), names[matched_at])

    def which_lists(self, domain: str) -> tuple[str, ...]:
        """"Which list blocks this domain?" (Filters page / query log details)."""
        return self.match(domain).lists
