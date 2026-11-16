"""SafeSearch and YouTube Restricted Mode name matching.

Port of blockads-android ``tunnel/internal/safesearch/safesearch.go``
(revision fc95d66a). Names are normalized (lowercase, no final dot).

One deliberate fix: upstream's ``"google."`` pattern matches any name whose
first label (or second, after ``www``) is ``google``, whatever follows, so it
also rewrites ``google.internal``, ``google.evil.example`` and a bare
``google`` (upstream's own test documents this as a known bug). Here the rest
of the name must have the shape of a Google search domain: ``com``, ``cat``, a
two-letter country code, or ``co.``/``com.`` plus a country code. Every entry
of Google's supported-domains list has that shape.
"""

from __future__ import annotations

import re

GOOGLE_TARGET = "forcesafesearch.google.com"
BING_TARGET = "strict.bing.com"
YOUTUBE_TARGET = "restrict.youtube.com"

YOUTUBE_DOMAINS = ("youtube.com", "youtube-nocookie.com", "youtube.googleapis.com", "youtubei.googleapis.com")

_GOOGLE_SUFFIX = re.compile(r"(?:(?:co|com)\.)?(?:com|cat|[a-z]{2})")


def _is_google_search(name: str) -> bool:
    labels = name.split(".")
    if labels[0] == "google":
        rest = labels[1:]
    elif len(labels) > 2 and labels[0] == "www" and labels[1] == "google":
        rest = labels[2:]
    else:
        return False
    return _GOOGLE_SUFFIX.fullmatch(".".join(rest)) is not None


def _is_same_or_subdomain(name: str, domain: str) -> bool:
    return name == domain or name.endswith("." + domain)


def safesearch_target(name: str) -> str | None:
    """Host whose address replaces ``name`` under SafeSearch, or ``None``."""
    if _is_google_search(name):
        return GOOGLE_TARGET
    if _is_same_or_subdomain(name, "bing.com"):
        return BING_TARGET
    return None


def youtube_target(name: str) -> str | None:
    """Host whose address replaces ``name`` under YouTube Restricted Mode."""
    for domain in YOUTUBE_DOMAINS:
        if _is_same_or_subdomain(name, domain):
            return YOUTUBE_TARGET
    return None
