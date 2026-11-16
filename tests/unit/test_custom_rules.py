"""Tests for filters.custom_rules.

The format table is copied from upstream
app/src/test/java/app/pwhs/blockads/utils/CustomRuleParserTest.kt (rev fc95d66a).
"""

import pytest

from blockads_linux.filters.custom_rules import (
    CustomRule,
    CustomRuleSet,
    CustomRuleType,
    CustomVerdict,
    check_domain_and_parents,
    format_block_rule,
    parse_rule,
    parse_rules,
)

B, A, C = CustomRuleType.BLOCK, CustomRuleType.ALLOW, CustomRuleType.COMMENT

UPSTREAM_TABLE = [
    ("||ads.example.com^", B, "ads.example.com"),
    ("||ADS.Example.COM^", B, "ads.example.com"),
    ("||*.ads.example.com^", B, "*.ads.example.com"),
    ("||*.*.example.com^", B, "*.*.example.com"),
    ("example.com", B, "example.com"),
    ("  Example.com  ", B, "example.com"),
    ("*.example.com", B, "*.example.com"),
    ("sub-domain.example.com", B, "sub-domain.example.com"),
    ("1.2.3.4", B, "1.2.3.4"),
    ("localhost", B, "localhost"),
    ("@@||ok.example.com^", A, "ok.example.com"),
    ("@@||*.OK.example^", A, "*.ok.example"),
    ("@@ok.example.com", A, "ok.example.com"),
    ("@@ Ok.Example ", A, "ok.example"),
    ("! a comment", C, ""),
    ("!", C, ""),
    ("", None, None),
    ("   ", None, None),
    ("||^", None, None),
    ("@@||^", None, None),
    ("@@", None, None),
    ("||example.com", None, None),
    ("@@||example.com", None, None),
    ("||bad domain.com^", None, None),
    ("@@||bad domain^", None, None),
    ("@@bad..domain", None, None),
    ("a*b.com", None, None),
    ("*com", None, None),
    ("*", None, None),
    (".example.com", None, None),
    ("example.com.", None, None),
    ("exa..mple.com", None, None),
    ("-bad.com", None, None),
    ("bad-.com", None, None),
    ("http://example.com", None, None),
    ("||ads.example^$third-party", None, None),
    ("0.0.0.0 ads.example", None, None),
    ("# hosts comment", None, None),
]


@pytest.mark.parametrize(("text", "rule_type", "domain"), UPSTREAM_TABLE)
def test_parse_rule_matches_upstream_table(text, rule_type, domain):
    parsed = parse_rule(text)
    if rule_type is None:
        assert parsed is None
    else:
        assert parsed == CustomRule(text.strip(), rule_type, domain)


def test_parse_rules_keeps_order_and_drops_invalid():
    text = "||one.example^\n@@||two.example^\n! note\nthree.example\n\nbad domain\n"
    assert [r.domain for r in parse_rules(text)] == ["one.example", "two.example", "", "three.example"]


def test_parse_rules_line_endings_and_empty():
    assert [r.domain for r in parse_rules("||a.example^\r\n||b.example^\r\n")] == ["a.example", "b.example"]
    assert [r.domain for r in parse_rules("||a.example^\r||b.example^")] == ["a.example", "b.example"]
    assert parse_rules("") == []


def test_format_block_rule_round_trip():
    assert format_block_rule("ADS.Example") == "||ads.example^"
    assert format_block_rule("ADS.Example", use_adblock_format=False) == "ads.example"
    parsed = parse_rule(format_block_rule("Tracker.Example"))
    assert parsed is not None and parsed.rule_type is B and parsed.domain == "tracker.example"


@pytest.mark.parametrize(
    ("entries", "query", "want"),
    [
        ({"example.com"}, "example.com", True),
        ({"example.com"}, "a.b.example.com", True),
        ({"example.com"}, "notexample.com", False),
        ({"*.ads.example.com"}, "x.ads.example.com", True),
        ({"*.ads.example.com"}, "y.x.ads.example.com", True),
        ({"*.ads.example.com"}, "ads.example.com", False),  # strict subdomains only
        ({"*.*.example.com"}, "a.b.example.com", False),  # never matches (as upstream)
        ({"com"}, "anything.com", True),  # single labels are accepted upstream
        (set(), "example.com", False),
    ],
)
def test_check_domain_and_parents(entries, query, want):
    assert check_domain_and_parents(query, entries.__contains__) is want


def test_custom_rule_set_precedence_allow_then_whitelist_then_block():
    rules = parse_rules("||ads.example^\n@@||ok.ads.example^\n||tracker.example^")
    ruleset = CustomRuleSet.build(rules, whitelist=["Tracker.Example"])
    assert ruleset.verdict("x.ads.example") is CustomVerdict.BLOCK
    assert ruleset.verdict("ok.ads.example") is CustomVerdict.ALLOW
    assert ruleset.verdict("tracker.example") is CustomVerdict.WHITELIST  # whitelist beats block
    assert ruleset.verdict("clean.example") is CustomVerdict.NONE
    assert CustomRuleSet().verdict("ads.example") is CustomVerdict.NONE
