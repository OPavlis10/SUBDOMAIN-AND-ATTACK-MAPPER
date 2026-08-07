"""Historical hostname discovery via the Wayback Machine CDX API.

The archive remembers URLs that no longer resolve or are no longer linked
anywhere. Decommissioned staging hosts and forgotten admin panels routinely
show up here and nowhere else.
"""

from __future__ import annotations

import logging
from typing import Set
from urllib.parse import urlparse

import requests

log = logging.getLogger(__name__)

CDX_URL = "http://web.archive.org/cdx/search/cdx"
USER_AGENT = "subdomain-mapper/1.0 (+https://github.com/)"


def _extract_host(original_url: str, domain: str) -> str | None:
    """Pull a valid in-scope hostname out of an archived URL."""
    candidate = original_url if "://" in original_url else f"http://{original_url}"
    try:
        host = urlparse(candidate).hostname
    except ValueError:
        return None
    if not host:
        return None

    host = host.lower().rstrip(".")
    if host.startswith("www.") and host[4:] == domain:
        return host
    if host == domain or host.endswith("." + domain):
        return host
    return None


def fetch(domain: str, timeout: int = 60, limit: int = 20000) -> Set[str]:
    """Return hostnames under ``domain`` that appear in the Wayback index."""
    domain = domain.lower().strip().rstrip(".")
    params = {
        "url": f"*.{domain}",
        "output": "json",
        "collapse": "urlkey",
        "fl": "original",
        "limit": str(limit),
    }
    headers = {"User-Agent": USER_AGENT}

    try:
        log.info("wayback: querying %s", domain)
        response = requests.get(CDX_URL, params=params, headers=headers, timeout=timeout)
        response.raise_for_status()
        rows = response.json()
    except (requests.RequestException, ValueError) as exc:
        log.warning("wayback: query failed: %s", exc)
        return set()

    if not rows:
        return set()

    # The first row is the CDX column header, not data.
    data_rows = rows[1:] if rows and rows[0] and rows[0][0] == "original" else rows

    results: Set[str] = set()
    for row in data_rows:
        if not row:
            continue
        host = _extract_host(str(row[0]), domain)
        if host:
            results.add(host)

    log.info("wayback: %d unique hosts for %s", len(results), domain)
    return results
