"""Certificate Transparency log collection via crt.sh.

crt.sh indexes public CT logs. Every TLS certificate issued for a subdomain
ends up there, which makes it the single richest passive source of subdomains.
No traffic is sent to the target at this stage.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Set

import requests

log = logging.getLogger(__name__)

CRTSH_URL = "https://crt.sh/"
USER_AGENT = "subdomain-mapper/1.0 (+https://github.com/)"


def _clean_name(raw: str, domain: str) -> Set[str]:
    """Normalise one crt.sh name field into zero or more valid hostnames.

    A single ``name_value`` may hold several newline-separated names, and
    wildcard entries (``*.example.com``) must be stripped down to the apex.
    """
    found: Set[str] = set()
    for line in raw.split("\n"):
        name = line.strip().lower().rstrip(".")
        if not name:
            continue
        # Drop the wildcard label: "*.dev.example.com" -> "dev.example.com"
        if name.startswith("*."):
            name = name[2:]
        if "*" in name or " " in name:
            continue
        # Only keep names inside the target zone.
        if name == domain or name.endswith("." + domain):
            found.add(name)
    return found


def fetch(domain: str, timeout: int = 30, retries: int = 3) -> Set[str]:
    """Return the set of subdomains of ``domain`` known to crt.sh.

    crt.sh is frequently rate-limited or slow, so failures are tolerated:
    an empty set is returned rather than raising, letting the other
    collectors still produce a useful result.
    """
    domain = domain.lower().strip().rstrip(".")
    params = {"q": f"%.{domain}", "output": "json"}
    headers = {"User-Agent": USER_AGENT}

    for attempt in range(1, retries + 1):
        try:
            log.info("crt.sh: querying %s (attempt %d/%d)", domain, attempt, retries)
            response = requests.get(
                CRTSH_URL, params=params, headers=headers, timeout=timeout
            )
            response.raise_for_status()
            # crt.sh occasionally returns concatenated JSON objects instead of
            # a proper array; fall back to a lenient parse when that happens.
            try:
                records = response.json()
            except json.JSONDecodeError:
                text = response.text.replace("}{", "},{")
                records = json.loads(f"[{text}]")
            break
        except (requests.RequestException, json.JSONDecodeError) as exc:
            log.warning("crt.sh: attempt %d failed: %s", attempt, exc)
            if attempt == retries:
                log.error("crt.sh: giving up on %s", domain)
                return set()
            time.sleep(2 * attempt)

    results: Set[str] = set()
    for record in records:
        if not isinstance(record, dict):
            continue
        for field in ("name_value", "common_name"):
            value = record.get(field)
            if value:
                results |= _clean_name(str(value), domain)

    log.info("crt.sh: %d unique names for %s", len(results), domain)
    return results
