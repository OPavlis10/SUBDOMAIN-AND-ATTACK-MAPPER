"""Keyword-based risk classification of discovered hostnames.

The heuristic is deliberately simple and transparent: a host is only as
interesting as what its name advertises. Names are matched on label
boundaries so ``api.example.com`` matches "api" but ``rapid.example.com``
does not.
"""

from __future__ import annotations

import re
from typing import Dict, List, Tuple

# Exposure of these usually means an internal or privileged surface.
HIGH_RISK_KEYWORDS = [
    "admin", "vpn", "internal", "intranet", "staging", "stage", "uat",
    "jenkins", "gitlab", "git", "portal", "backup", "phpmyadmin", "grafana",
    "kibana", "jira", "confluence", "vault", "sso", "ldap", "rdp", "citrix",
    "manage", "manager", "console", "dashboard", "monitoring", "nagios",
    "zabbix", "sonar", "nexus", "artifactory", "db", "database", "sql",
    "redis", "elastic", "kubernetes", "k8s", "rancher", "openvpn", "ssh",
]

# Non-production environments: lower stakes, but weaker hardening.
MEDIUM_RISK_KEYWORDS = [
    "dev", "devel", "development", "test", "testing", "qa", "beta", "alpha",
    "sandbox", "api", "demo", "preprod", "pre", "lab", "labs", "old", "legacy",
    "tmp", "temp", "new", "v1", "v2", "mobile", "app", "auth", "login",
]

# Ordinary public surface. Listed for completeness; anything unmatched
# also lands here.
LOW_RISK_KEYWORDS = [
    "www", "mail", "smtp", "imap", "pop", "ftp", "cdn", "static", "assets",
    "img", "images", "media", "blog", "shop", "news", "support", "help",
    "docs", "status", "ns", "ns1", "ns2", "mx", "autodiscover", "webmail",
]

RISK_ORDER = {"high": 3, "medium": 2, "low": 1}


def _labels(hostname: str, apex: str) -> List[str]:
    """Split the part of ``hostname`` left of the apex into keyword tokens."""
    hostname = hostname.lower().rstrip(".")
    apex = apex.lower().rstrip(".")
    prefix = hostname[: -(len(apex) + 1)] if hostname.endswith("." + apex) else hostname
    # "dev-api.eu1" -> ["dev", "api", "eu", "1"]
    return [token for token in re.split(r"[.\-_]+", prefix) if token]


def classify(hostname: str, apex: str) -> Tuple[str, List[str]]:
    """Return ``(risk_level, matched_keywords)`` for a hostname.

    The highest-severity match wins; a host named ``dev-admin`` is high risk,
    not medium.
    """
    tokens = _labels(hostname, apex)
    token_set = set(tokens)

    high = sorted(token_set & set(HIGH_RISK_KEYWORDS))
    if high:
        return "high", high

    medium = sorted(token_set & set(MEDIUM_RISK_KEYWORDS))
    if medium:
        return "medium", medium

    low = sorted(token_set & set(LOW_RISK_KEYWORDS))
    return "low", low


def classify_all(records: List[Dict], apex: str) -> List[Dict]:
    """Annotate each record in place with ``risk`` and ``risk_keywords``."""
    for record in records:
        risk, keywords = classify(record["hostname"], apex)
        record["risk"] = risk
        record["risk_keywords"] = keywords
    return records


def summarise(records: List[Dict]) -> Dict[str, int]:
    """Count records per risk level, always returning all three keys."""
    counts = {"high": 0, "medium": 0, "low": 0}
    for record in records:
        counts[record.get("risk", "low")] += 1
    return counts
