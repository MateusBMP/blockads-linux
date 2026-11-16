"""How much the enabled filter lists duplicate each other.

The idea follows blockads-android's ``FilterOverlapAnalyzer`` (upstream
52875171): per list, how many of its domains another list also blocks and how
many only it blocks; for each pair of lists, how many domains they share; and,
over all of them, entries versus unique domains (the redundancy).

Here a compiled list is a sorted, duplicate-free array of 64-bit domain hashes
(``filters.artifact``), so the whole analysis is one k-way merge of those
arrays; no domain name is needed or stored. Upstream's sample of duplicated
domain names and its combined-list export need the names, which artifacts do
not keep, so they are not offered.
"""

from __future__ import annotations

import heapq
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from itertools import combinations


@dataclass(frozen=True, slots=True)
class ListOverlap:
    list_id: str
    total: int  # domains the list blocks
    shared: int  # of those, blocked by at least one other list too
    unique: int  # blocked by this list only

    @property
    def shared_percent(self) -> float:
        return 100.0 * self.shared / self.total if self.total else 0.0


@dataclass(frozen=True, slots=True)
class PairOverlap:
    a: str
    b: str
    shared: int


@dataclass(frozen=True, slots=True)
class OverlapReport:
    lists: tuple[ListOverlap, ...]
    pairs: tuple[PairOverlap, ...]  # every pair with shared > 0, most shared first
    total_entries: int  # sum of the lists' sizes
    unique_domains: int  # distinct domains over all lists
    overlapping_domains: int  # distinct domains in two lists or more

    @property
    def redundant_entries(self) -> int:
        return self.total_entries - self.unique_domains

    @property
    def redundancy_percent(self) -> float:
        return 100.0 * self.redundant_entries / self.total_entries if self.total_entries else 0.0

    def to_dict(self) -> dict:
        return {
            "total_entries": self.total_entries,
            "unique_domains": self.unique_domains,
            "overlapping_domains": self.overlapping_domains,
            "redundant_entries": self.redundant_entries,
            "redundancy_percent": round(self.redundancy_percent, 2),
            "lists": [{"id": s.list_id, "total": s.total, "shared": s.shared, "unique": s.unique,
                       "shared_percent": round(s.shared_percent, 2)} for s in self.lists],
            "pairs": [{"a": p.a, "b": p.b, "shared": p.shared} for p in self.pairs],
        }


def _tagged(values: Sequence[int], index: int) -> Iterator[tuple[int, int]]:
    for value in values:
        yield value, index


def analyze(lists: Sequence[tuple[str, Sequence[int]]]) -> OverlapReport:
    """Analyze ``(list_id, sorted unique hashes)`` pairs; ids must be distinct.

    Time is O(N log k) for N entries in k lists; memory is O(k^2) beyond the
    input (only counters, never the merged set).
    """
    ids = [list_id for list_id, _ in lists]
    if len(set(ids)) != len(ids):
        raise ValueError("duplicate list id")
    k = len(lists)
    totals = [len(values) for _, values in lists]
    shared = [0] * k
    pair_counts: dict[tuple[int, int], int] = {}
    unique_domains = overlapping = 0

    previous = None
    holders: list[int] = []

    def close_group() -> None:
        nonlocal overlapping
        if len(holders) > 1:
            overlapping += 1
            for index in holders:
                shared[index] += 1
            for pair in combinations(holders, 2):
                pair_counts[pair] = pair_counts.get(pair, 0) + 1

    for value, index in heapq.merge(*(_tagged(values, i) for i, (_, values) in enumerate(lists))):
        if value != previous:
            close_group()
            unique_domains += 1
            previous = value
            holders = [index]
        else:
            holders.append(index)
    close_group()

    per_list = tuple(ListOverlap(ids[i], totals[i], shared[i], totals[i] - shared[i]) for i in range(k))
    pairs = sorted((PairOverlap(ids[a], ids[b], n) for (a, b), n in pair_counts.items()),
                   key=lambda p: (-p.shared, p.a, p.b))
    return OverlapReport(per_list, tuple(pairs), sum(totals), unique_domains, overlapping)
