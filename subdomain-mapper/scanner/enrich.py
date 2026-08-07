"""Metadata enrichment: DNS resolution, HTTP fingerprint, shared-IP linking.

Exactly one HTTPS request (with an HTTP fallback) is made per host, with a
short timeout and no redirect chasing beyond the default. This is normal web
traffic, not scanning.
"""

from __future__ import annotations

import logging
import re
import socket
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Set

import requests
import urllib3

log = logging.getLogger(__name__)

# Recon targets routinely have expired or self-signed certificates; a TLS
# warning per host would drown out the real output.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

USER_AGENT = (
    "Mozilla/5.0 (compatible; subdomain-mapper/1.0; passive reconnaissance)"
)
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

# Reading the whole body is unnecessary - the title lives in the head.
MAX_BODY_BYTES = 65536


def resolve_ips(hostname: str) -> List[str]:
    """Return every A/AAAA address for ``hostname``, or an empty list."""
    try:
        infos = socket.getaddrinfo(hostname, None)
    except (socket.gaierror, socket.herror, UnicodeError, OSError):
        return []
    return sorted({info[4][0] for info in infos})


def _extract_title(html: str) -> Optional[str]:
    match = TITLE_RE.search(html)
    if not match:
        return None
    title = re.sub(r"\s+", " ", match.group(1)).strip()
    return title[:120] if title else None


def probe_http(hostname: str, timeout: float = 3.0) -> Dict:
    """Try HTTPS then HTTP, returning status, title, scheme and server header."""
    result: Dict = {
        "status": None,
        "title": None,
        "scheme": None,
        "server": None,
        "redirect": None,
    }
    session = requests.Session()
    session.headers["User-Agent"] = USER_AGENT

    for scheme in ("https", "http"):
        url = f"{scheme}://{hostname}"
        try:
            response = session.get(
                url, timeout=timeout, allow_redirects=True, verify=False, stream=True
            )
            body = response.raw.read(MAX_BODY_BYTES, decode_content=True) or b""
            html = body.decode(response.encoding or "utf-8", errors="replace")

            result["status"] = response.status_code
            result["scheme"] = scheme
            result["title"] = _extract_title(html)
            result["server"] = response.headers.get("Server")
            if response.url.rstrip("/") != url.rstrip("/"):
                result["redirect"] = response.url
            return result
        except requests.RequestException:
            continue
        finally:
            session.close()

    return result


def _enrich_one(hostname: str, known_ips: List[str], timeout: float) -> Dict:
    ips = known_ips or resolve_ips(hostname)
    record: Dict = {
        "hostname": hostname,
        "ips": ips,
        "alive": bool(ips),
        "shared_with": [],
    }
    # An unresolvable host has nothing to serve; skip the HTTP request.
    if ips:
        record.update(probe_http(hostname, timeout=timeout))
    else:
        record.update(
            {"status": None, "title": None, "scheme": None, "server": None, "redirect": None}
        )
    return record


def link_shared_ips(records: List[Dict]) -> List[Dict]:
    """Populate ``shared_with`` for hosts that answer on the same address.

    Shared IPs are the strongest available signal of shared infrastructure -
    one misconfigured vhost often exposes its neighbours.
    """
    by_ip: Dict[str, Set[str]] = defaultdict(set)
    for record in records:
        for ip in record.get("ips", []):
            by_ip[ip].add(record["hostname"])

    for record in records:
        neighbours: Set[str] = set()
        for ip in record.get("ips", []):
            neighbours |= by_ip[ip]
        neighbours.discard(record["hostname"])
        record["shared_with"] = sorted(neighbours)

    return records


def enrich_all(
    hostnames: List[str],
    known_ips: Optional[Dict[str, List[str]]] = None,
    workers: int = 30,
    timeout: float = 3.0,
    progress=None,
) -> List[Dict]:
    """Enrich every hostname in parallel and cross-link shared addresses."""
    known_ips = known_ips or {}
    records: List[Dict] = []
    total = len(hostnames)

    log.info("enrich: probing %d hosts", total)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(_enrich_one, host, known_ips.get(host, []), timeout): host
            for host in hostnames
        }
        for done, future in enumerate(as_completed(futures), start=1):
            try:
                records.append(future.result())
            except Exception as exc:  # a single bad host must not kill the run
                log.warning("enrich: %s failed: %s", futures[future], exc)
            if progress and done % 10 == 0:
                progress(done, total)

    if progress:
        progress(total, total)

    link_shared_ips(records)
    records.sort(key=lambda r: r["hostname"])
    log.info("enrich: %d/%d hosts resolved", sum(r["alive"] for r in records), total)
    return records
