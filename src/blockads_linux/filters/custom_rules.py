"""User-defined domain rules (Domain Rules page) and whitelist matching.

Port of blockads-android's ``utils/CustomRuleParser.kt`` and of the matching
in ``data/repository/FilterListRepository.kt`` (``checkDomainAndParents`` and
``hasCustomRule``), upstream revision fc95d66a.

Accepted syntax (one rule per line):

    ! comment                       COMMENT
    @@||example.com^  @@example.com ALLOW  (and their subdomains)
    ||example.com^    example.com   BLOCK  (and their subdomains)
    *.example.com     (any form)    only *strict* subdomains of example.com
"""

from __future__ import annotations

import enum
import re
from collections.abc import Callable, Iterable, Set
from dataclasses import dataclass

# Kotlin's String.lines() splits on \r\n, \n and \r only.
_LINE_SPLIT = re.compile(r"\r\n|\n|\r")
_DOMAIN_RE = re.compile(
    r"(\*\.)*[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*"
)


class CustomRuleType(enum.Enum):
    BLOCK = "block"
    ALLOW = "allow"
    COMMENT = "comment"


@dataclass(frozen=True, slots=True)
class CustomRule:
    rule: str
    rule_type: CustomRuleType
    domain: str


def is_valid_domain(domain: str) -> bool:
    """Port of ``CustomRuleParser.isValidDomain``."""
    if not domain or domain.startswith(".") or domain.endswith("."):
        return False
    if ".." in domain:
        return False
    return _DOMAIN_RE.fullmatch(domain) is not None


def parse_rule(rule_text: str) -> CustomRule | None:
    """Port of ``CustomRuleParser.parseRule``; ``None`` for invalid input."""
    trimmed = rule_text.strip()
    if not trimmed:
        return None
    if trimmed.startswith("!"):
        return CustomRule(trimmed, CustomRuleType.COMMENT, "")
    if trimmed.startswith("@@||") and trimmed.endswith("^"):
        rule_type, domain = CustomRuleType.ALLOW, trimmed.removeprefix("@@||").removesuffix("^").strip()
    elif trimmed.startswith("@@"):
        rule_type, domain = CustomRuleType.ALLOW, trimmed.removeprefix("@@").strip()
    elif trimmed.startswith("||") and trimmed.endswith("^"):
        rule_type, domain = CustomRuleType.BLOCK, trimmed.removeprefix("||").removesuffix("^").strip()
    else:
        rule_type, domain = CustomRuleType.BLOCK, trimmed
    if not is_valid_domain(domain):
        return None
    return CustomRule(trimmed, rule_type, domain.lower())


def parse_rules(rules_text: str) -> list[CustomRule]:
    """Port of ``CustomRuleParser.parseRules``: invalid lines are skipped."""
    rules = (parse_rule(line) for line in _LINE_SPLIT.split(rules_text))
    return [rule for rule in rules if rule is not None]


def format_block_rule(domain: str, use_adblock_format: bool = True) -> str:
    """Port of ``CustomRuleParser.formatBlockRule``."""
    return f"||{domain.lower()}^" if use_adblock_format else domain.lower()


def check_domain_and_parents(domain: str, contains: Callable[[str], bool]) -> bool:
    """Port of ``FilterListRepository.checkDomainAndParents``.

    Tries the name itself, then every parent ``p`` both as ``p`` and as
    ``*.p``; so an entry ``*.p`` matches strict subdomains of ``p`` only.
    """
    if contains(domain):
        return True
    rest = domain
    while "." in rest:
        rest = rest.split(".", 1)[1]
        if contains(rest) or contains("*." + rest):
            return True
    return False


class CustomVerdict(enum.Enum):
    NONE = "none"          # no custom rule applies: continue with the filter lists
    ALLOW = "allow"        # custom allow rule: skip all filtering
    WHITELIST = "whitelist"  # whitelisted domain: skip all filtering
    BLOCK = "block"        # custom block rule


@dataclass(frozen=True, slots=True)
class CustomRuleSet:
    """Immutable snapshot of the user's rules; swapped atomically on change."""

    allow: frozenset[str] = frozenset()
    block: frozenset[str] = frozenset()
    whitelist: frozenset[str] = frozenset()

    @classmethod
    def build(
        cls,
        rules: Iterable[CustomRule],
        whitelist: Iterable[str] = (),
    ) -> "CustomRuleSet":
        allow = {r.domain for r in rules if r.rule_type is CustomRuleType.ALLOW}
        block = {r.domain for r in rules if r.rule_type is CustomRuleType.BLOCK}
        return cls(frozenset(allow), frozenset(block), frozenset(d.lower() for d in whitelist))

    def verdict(self, domain: str) -> CustomVerdict:
        """Port of ``hasCustomRule``: allow, then whitelist, then block."""
        if self.allow and check_domain_and_parents(domain, self.allow.__contains__):
            return CustomVerdict.ALLOW
        if self.whitelist and check_domain_and_parents(domain, self.whitelist.__contains__):
            return CustomVerdict.WHITELIST
        if self.block and check_domain_and_parents(domain, self.block.__contains__):
            return CustomVerdict.BLOCK
        return CustomVerdict.NONE


def entries_match(domain: str, entries: Set[str]) -> bool:
    """Convenience wrapper: does ``domain`` match any entry (with parents)?"""
    return bool(entries) and check_domain_and_parents(domain, entries.__contains__)
