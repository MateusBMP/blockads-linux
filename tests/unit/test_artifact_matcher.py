"""Tests for filters.artifact and filters.matcher."""

import hashlib
import struct
from array import array

import pytest

from blockads_linux.filters.artifact import (
    HEADER_SIZE,
    ArtifactBuilder,
    ArtifactError,
    LoadedArtifact,
    TooManyRules,
    domain_hash,
    u64_view,
)
from blockads_linux.filters.matcher import FilterList, FilterMatcher, suffixes
from blockads_linux.filters.parser import ListRule, RuleKind, iter_list_rules

SRC_SHA = hashlib.sha256(b"source").digest()


def build(tmp_path, lines, list_id="l", rank=0):
    builder = ArtifactBuilder()
    builder.add_rules(iter_list_rules(lines))
    info = builder.write(tmp_path, source_sha256=SRC_SHA, compiled_at=1_700_000_000)
    return FilterList(list_id, rank, LoadedArtifact.open(tmp_path / info.name))


UPSTREAM_LIST = [
    "! Title: test list",
    "# hosts section",
    "0.0.0.0 tracker.example.com",
    "127.0.0.1 localhost",
    "||ads.example.org^",
    "||ADS.example.org^",
    "@@||allowed.example.net^",
    "metrics.example.net",
    "*.wild.example.io",
    "server=/dnsmasq.example.dev/",
    "",
]

# Upstream TestCompileLoadRoundTrip expectations (ContainsOrParent).
UPSTREAM_EXPECTATIONS = {
    "tracker.example.com": True,
    "a.b.tracker.example.com": True,
    "ads.example.org": True,
    "x.ads.example.org": True,
    "metrics.example.net": True,
    "deep.sub.metrics.example.net": True,
    "a.wild.example.io": True,
    "a.b.wild.example.io": True,
    "wild.example.io": True,
    "dnsmasq.example.dev": True,
    "sub.dnsmasq.example.dev": True,
    "example.com": False,
    "com": False,
    "racker.example.com": False,
    "nottracker.example.com": False,
    "tracker.example.co": False,
    "tracker.example.com.evil": False,
    "allowed.example.net": False,
    "localhost": False,
    "": False,
    "trailing.example.dev": False,
}


def test_round_trip_matches_upstream_expectations(tmp_path):
    flist = build(tmp_path, UPSTREAM_LIST)
    assert flist.artifact.info.block_count == 5
    assert flist.artifact.info.exception_count == 1
    matcher = FilterMatcher([flist])
    for name, want in UPSTREAM_EXPECTATIONS.items():
        assert matcher.match(name).blocked is want, name


def test_trie_edge_cases_from_upstream(tmp_path):
    matcher = FilterMatcher([build(tmp_path, ["exact.org"])])
    assert matcher.match("sub.exact.org").blocked
    assert not matcher.match("exact.org.").blocked  # trailing empty label is literal
    assert not matcher.match("EXACT.ORG").blocked  # callers lowercase
    assert not matcher.match(".").blocked
    assert matcher.match("a." * 200 + "exact.org").blocked


def test_artifact_is_content_addressed_and_written_atomically(tmp_path):
    flist = build(tmp_path, ["a.example"])
    info = flist.artifact.info
    data = (tmp_path / info.name).read_bytes()
    assert info.name == hashlib.sha256(data).hexdigest() + ".bkf"
    assert info.source_sha256 == SRC_SHA.hex()
    assert [p.name for p in tmp_path.iterdir()] == [info.name]  # no temp files left


def test_exceptions_are_list_scoped(tmp_path):
    list_a = build(tmp_path / "a", ["||ads.example^", "@@||ok.ads.example^"], "a", rank=1)
    list_b = build(tmp_path / "b", ["||ok.ads.example^"], "b", rank=2)
    assert FilterMatcher([list_a]).match("ok.ads.example").blocked is False
    assert FilterMatcher([list_a]).match("x.ads.example").blocked is True
    result = FilterMatcher([list_a, list_b]).match("ok.ads.example")
    assert result.blocked and result.lists == ("b",)  # A's exception does not cancel B


def test_important_block_beats_same_list_exception(tmp_path):
    flist = build(tmp_path, ["||x.example^$important", "@@||x.example^"])
    assert FilterMatcher([flist]).match("a.x.example").blocked


def test_all_blocking_lists_reported_in_rank_order(tmp_path):
    ads = build(tmp_path / "ads", ["tracker.example"], "ads_list", rank=1)
    sec = build(tmp_path / "sec", ["evil.tracker.example"], "sec_list", rank=0)
    result = FilterMatcher([ads, sec]).match("x.evil.tracker.example")
    assert result.lists == ("sec_list", "ads_list")
    assert result.reason == "sec_list,ads_list"
    assert result.matched == "evil.tracker.example"  # most specific matching suffix
    assert FilterMatcher([ads, sec]).which_lists("clean.example") == ()


def test_exception_only_artifact_never_blocks(tmp_path):
    flist = build(tmp_path, ["@@||a.example^"])
    assert flist.artifact.info.block_count == 0
    assert not FilterMatcher([flist]).match("a.example").blocked


def test_empty_list_is_rejected(tmp_path):
    with pytest.raises(ArtifactError):
        ArtifactBuilder().write(tmp_path, source_sha256=SRC_SHA, compiled_at=0)
    assert list(tmp_path.iterdir()) == []


def test_entry_limit(tmp_path):
    builder = ArtifactBuilder(max_entries=2)
    builder.add(ListRule(RuleKind.BLOCK, "a.example"))
    builder.add(ListRule(RuleKind.BLOCK, "b.example"))
    with pytest.raises(TooManyRules):
        builder.add(ListRule(RuleKind.BLOCK, "c.example"))


@pytest.mark.parametrize("damage", ["magic", "version", "truncate", "extend", "rename", "labels", "prefilter"])
def test_corrupt_artifacts_are_rejected(tmp_path, damage):
    info = build(tmp_path, ["a.example", "b.example"]).artifact.info
    path = tmp_path / info.name
    data = bytearray(path.read_bytes())
    if damage == "magic":
        data[0:4] = b"XXXX"
    elif damage == "version":
        struct.pack_into("<H", data, 4, 99)
    elif damage == "truncate":
        data = data[:-3]
    elif damage == "extend":
        data += b"\0" * 8
    elif damage == "labels":
        data[6], data[7] = 5, 2  # min_labels > max_labels
    elif damage == "prefilter":
        struct.pack_into("<I", data, 20, 12)  # prefilter size inconsistent with the block count
    if damage == "rename":
        target = tmp_path / ("0" * 64 + ".bkf")
        path.rename(target)
    else:
        target = tmp_path / (hashlib.sha256(bytes(data)).hexdigest() + ".bkf")  # keep the name valid
        path.unlink()
        target.write_bytes(bytes(data))
    with pytest.raises(ArtifactError):
        LoadedArtifact.open(target)


def test_truncated_header_is_rejected(tmp_path):
    path = tmp_path / "x.bkf"
    path.write_bytes(b"BKAF" + b"\0" * (HEADER_SIZE - 10))
    with pytest.raises(ArtifactError):
        LoadedArtifact.open(path, verify_name=False)


def test_u64_view_little_and_big_endian_paths():
    values = [1, 2**63 + 5, 2**64 - 1]
    data = memoryview(b"".join(v.to_bytes(8, "little") for v in values))
    assert list(u64_view(data, little_endian_host=True)) == values
    # The big-endian path reads native order then byteswaps; on this (LE) host
    # that yields the byte-reversed values, proving the swap is applied.
    swapped = [int.from_bytes(v.to_bytes(8, "little"), "big") for v in values]
    assert list(u64_view(data, little_endian_host=False)) == swapped
    assert isinstance(u64_view(data, little_endian_host=False), array)


def test_suffixes_and_hash():
    assert suffixes("a.b.c") == ["a.b.c", "b.c", "c"]
    assert suffixes("") == []
    assert len(suffixes("a." * 300 + "b")) == 128
    assert suffixes("a." * 300 + "b")[-1] == "b"
    assert domain_hash("example.com") == domain_hash("example.com")
    assert domain_hash("example.com") != domain_hash("example.org")
    assert 0 <= domain_hash("x") < 2**64


def test_empty_matcher():
    assert not FilterMatcher().match("anything.example").blocked
    assert FilterMatcher().rule_count == 0


def test_label_range_is_recorded_and_respected(tmp_path):
    flist = build(tmp_path, ["a.b.example.com", "example.org", "@@||x.y.z.w.v.example.org^"])
    info = flist.artifact.info
    assert (info.min_labels, info.max_labels) == (2, 4)  # exceptions do not widen the range
    matcher = FilterMatcher([flist], cache_size=0)
    assert matcher.match("deep.sub.a.b.example.com").blocked  # longer than max_labels: parents checked
    assert matcher.match("example.org").blocked
    assert not matcher.match("b.example.com").blocked
    tld = build(tmp_path / "tld", ["||*.actor^"])
    assert (tld.artifact.info.min_labels, tld.artifact.info.max_labels) == (1, 1)
    assert FilterMatcher([tld]).match("www.film.actor").blocked


def test_match_cache_is_per_matcher_instance(tmp_path):
    flist = build(tmp_path, ["ads.example"])
    matcher = FilterMatcher([flist])
    first = matcher.match("x.ads.example")
    assert matcher.match("x.ads.example") is first  # served from the cache
    assert FilterMatcher([]).match("x.ads.example").blocked is False  # a new matcher starts empty
    uncached = FilterMatcher([flist], cache_size=0)
    assert uncached.match("x.ads.example") == first
