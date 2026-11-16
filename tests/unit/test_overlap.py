"""Tests for filters.overlap and GetFilterOverlap / `blockadsctl filters overlap`."""

import random
from collections import Counter
from itertools import combinations

import pytest

from blockads_linux.ctl.cli import print_overlap
from blockads_linux.filters.overlap import analyze

from .test_api import call, decoded, make_api


def test_three_lists_by_hand():
    report = analyze([("a", [1, 2, 3, 4]), ("b", [3, 4, 5]), ("c", [4, 6])])
    assert report.total_entries == 9
    assert report.unique_domains == 6  # 1..6
    assert report.overlapping_domains == 2  # 3 (a, b) and 4 (a, b, c)
    assert report.redundant_entries == 3
    assert report.redundancy_percent == pytest.approx(100 * 3 / 9)
    by_id = {s.list_id: s for s in report.lists}
    assert (by_id["a"].total, by_id["a"].shared, by_id["a"].unique) == (4, 2, 2)
    assert (by_id["b"].total, by_id["b"].shared, by_id["b"].unique) == (3, 2, 1)
    assert (by_id["c"].total, by_id["c"].shared, by_id["c"].unique) == (2, 1, 1)
    assert [(p.a, p.b, p.shared) for p in report.pairs] == [("a", "b", 2), ("a", "c", 1), ("b", "c", 1)]


def test_matches_a_brute_force_count():
    rng = random.Random(7)
    lists = [(f"l{i}", sorted(rng.sample(range(400), rng.randint(0, 150)))) for i in range(6)]
    report = analyze(lists)
    counts = Counter(v for _, values in lists for v in values)
    assert report.unique_domains == len(counts)
    assert report.overlapping_domains == sum(1 for n in counts.values() if n > 1)
    for (list_id, values), stat in zip(lists, report.lists):
        assert stat.list_id == list_id and stat.total == len(values)
        assert stat.shared == sum(1 for v in values if counts[v] > 1)
    pairs = {(p.a, p.b): p.shared for p in report.pairs}
    for (ia, va), (ib, vb) in combinations(lists, 2):
        assert pairs.get((ia, ib), 0) == len(set(va) & set(vb))
    assert [p.shared for p in report.pairs] == sorted((p.shared for p in report.pairs), reverse=True)


def test_edge_cases():
    empty = analyze([])
    assert (empty.total_entries, empty.unique_domains, empty.redundancy_percent) == (0, 0, 0.0)
    one = analyze([("a", [1, 2])])
    assert one.overlapping_domains == 0 and one.lists[0].unique == 2 and one.pairs == ()
    assert analyze([("a", []), ("b", [1])]).lists[0].shared_percent == 0.0
    with pytest.raises(ValueError):
        analyze([("a", [1]), ("a", [2])])
    # Hashes use the whole unsigned 64-bit range.
    top = analyze([("a", [0, 2**64 - 1]), ("b", [2**64 - 1])])
    assert top.overlapping_domains == 1


def test_daemon_method_and_cache(tmp_path):
    api, _ = make_api(tmp_path)
    report = decoded(call(api, "GetFilterOverlap"))
    # sec_list {malware, both} and ads_list {ads, both}
    assert (report["total_entries"], report["unique_domains"], report["overlapping_domains"]) == (4, 3, 1)
    assert report["pairs"] == [{"a": "sec_list", "b": "ads_list", "shared": 1}]
    assert report["names"] == {"sec_list": "Sec", "ads_list": "Ads"}
    assert report["missing"] == ["custom_mine"]
    cached = api._overlap
    call(api, "GetFilterOverlap")
    assert api._overlap is cached  # same artifacts: not computed again
    call(api, "DisableFilters", ["ads_list"])
    report = decoded(call(api, "GetFilterOverlap"))
    assert [row["id"] for row in report["lists"]] == ["sec_list"] and report["pairs"] == []


def test_cli_output(tmp_path, capsys):
    api, _ = make_api(tmp_path)
    report = decoded(call(api, "GetFilterOverlap"))
    print_overlap(report, as_json=False)
    out = capsys.readouterr().out
    assert "2 lists, 4 entries, 3 unique domains; 1 entries (25.0%) are duplicates." in out
    assert "1  Sec + Ads" in out
    assert "Not compared (not downloaded yet): custom_mine" in out
    covered = dict(report, lists=[{"id": "ads_list", "total": 2, "shared": 2, "unique": 0, "shared_percent": 100.0},
                                  {"id": "sec_list", "total": 3, "shared": 2, "unique": 1, "shared_percent": 66.7}])
    print_overlap(covered, as_json=False)
    assert "Every domain of Ads is also in another list" in capsys.readouterr().out
    print_overlap(dict(report, lists=report["lists"][:1]), as_json=False)
    assert "nothing to compare" in capsys.readouterr().out
