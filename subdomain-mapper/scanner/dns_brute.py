"""Parallel DNS brute force against a prefix wordlist.

Only standard recursive DNS queries are issued - no traffic reaches the
target's own servers unless they are authoritative for the zone. Concurrency
is bounded so the resolver is not hammered.
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional, Set

import dns.exception
import dns.resolver

log = logging.getLogger(__name__)

DEFAULT_WORDLIST = Path(__file__).resolve().parent.parent / "wordlists" / "subdomains.txt"

# Public resolvers keep results consistent regardless of the operator's ISP.
DEFAULT_NAMESERVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]


def load_wordlist(path: Optional[Path] = None, limit: Optional[int] = None) -> List[str]:
    """Read prefixes from ``path``, skipping blanks and ``#`` comments."""
    path = Path(path) if path else DEFAULT_WORDLIST
    if not path.exists():
        log.error("wordlist not found: %s", path)
        return []

    words: List[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        word = line.strip().lower()
        if word and not word.startswith("#"):
            words.append(word)

    # Preserve order: the wordlist is sorted by likelihood, so truncating
    # keeps the most valuable prefixes.
    seen: Set[str] = set()
    unique = [w for w in words if not (w in seen or seen.add(w))]
    return unique[:limit] if limit else unique


def _build_resolver(timeout: float) -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver()
    resolver.nameservers = DEFAULT_NAMESERVERS
    resolver.timeout = timeout
    resolver.lifetime = timeout
    return resolver


def detect_wildcard(domain: str, timeout: float = 3.0) -> Set[str]:
    """Return the IPs a wildcard record resolves to, or an empty set.

    Zones with ``*.example.com`` resolve every random label, which would make
    brute forcing return thousands of false positives. Probing an unlikely
    label first lets us discard those answers later.
    """
    resolver = _build_resolver(timeout)
    wildcard_ips: Set[str] = set()
    for probe in ("zzz-nonexistent-probe-a1b2", "qqq-nonexistent-probe-c3d4"):
        try:
            answers = resolver.resolve(f"{probe}.{domain}", "A")
            wildcard_ips |= {rdata.address for rdata in answers}
        except (dns.exception.DNSException, ValueError):
            continue

    if wildcard_ips:
        log.warning("wildcard DNS detected for %s -> %s", domain, sorted(wildcard_ips))
    return wildcard_ips


def _resolve_one(
    prefix: str, domain: str, timeout: float, wildcard_ips: Set[str]
) -> Optional[tuple]:
    host = f"{prefix}.{domain}"
    resolver = _build_resolver(timeout)
    try:
        answers = resolver.resolve(host, "A")
    except (dns.exception.DNSException, ValueError):
        return None

    ips = {rdata.address for rdata in answers}
    # Everything the wildcard already covers is noise, not a real host.
    if ips and ips <= wildcard_ips:
        return None
    return (host, sorted(ips)) if ips else None


def brute_force(
    domain: str,
    wordlist: Optional[List[str]] = None,
    workers: int = 50,
    timeout: float = 3.0,
    progress=None,
) -> Dict[str, List[str]]:
    """Resolve ``prefix.domain`` for every prefix, returning hits with their IPs.

    ``progress`` is an optional callable ``(done, total)`` used by the
    Streamlit UI to drive a progress bar.
    """
    domain = domain.lower().strip().rstrip(".")
    words = wordlist if wordlist is not None else load_wordlist()
    if not words:
        return {}

    wildcard_ips = detect_wildcard(domain, timeout)
    found: Dict[str, List[str]] = {}
    total = len(words)

    log.info("dns: brute forcing %d prefixes against %s", total, domain)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(_resolve_one, word, domain, timeout, wildcard_ips): word
            for word in words
        }
        for done, future in enumerate(as_completed(futures), start=1):
            result = future.result()
            if result:
                host, ips = result
                found[host] = ips
            if progress and done % 25 == 0:
                progress(done, total)

    if progress:
        progress(total, total)
    log.info("dns: %d hosts resolved for %s", len(found), domain)
    return found
