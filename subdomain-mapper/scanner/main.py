"""Pipeline orchestration and CLI entry point.

    python -m scanner.main example.com --output results.json --report report.html
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from scanner import classify, crtsh, dns_brute, enrich, wayback

log = logging.getLogger("scanner")

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$"
)


def validate_domain(domain: str) -> str:
    """Normalise and sanity-check the target, raising on obvious garbage."""
    domain = domain.strip().lower().rstrip(".")
    if domain.startswith(("http://", "https://")):
        domain = domain.split("://", 1)[1].split("/", 1)[0]
    domain = domain.split("/", 1)[0].split(":", 1)[0]
    if not DOMAIN_RE.match(domain):
        raise ValueError(f"neplatná doména: {domain!r}")
    return domain


def collect(
    domain: str,
    wordlist_size: Optional[int] = None,
    use_wayback: bool = True,
    dns_timeout: float = 3.0,
    dns_workers: int = 50,
    progress=None,
) -> Dict[str, Dict]:
    """Run the three collectors concurrently and merge their findings.

    Returns ``{hostname: {"sources": [...], "ips": [...]}}``. Sources are kept
    per host so the report can show where each finding came from.
    """
    merged: Dict[str, Dict] = {}

    def add(hostname: str, source: str, ips: Optional[List[str]] = None) -> None:
        entry = merged.setdefault(hostname, {"sources": [], "ips": []})
        if source not in entry["sources"]:
            entry["sources"].append(source)
        for ip in ips or []:
            if ip not in entry["ips"]:
                entry["ips"].append(ip)

    words = dns_brute.load_wordlist(limit=wordlist_size)

    # The three sources are independent and mostly I/O bound, so overlapping
    # them turns three sequential waits into one.
    with ThreadPoolExecutor(max_workers=3) as pool:
        crt_future = pool.submit(crtsh.fetch, domain)
        wb_future = pool.submit(wayback.fetch, domain) if use_wayback else None
        dns_future = pool.submit(
            dns_brute.brute_force,
            domain,
            words,
            dns_workers,
            dns_timeout,
            progress,
        )

        for name in crt_future.result():
            add(name, "crt.sh")
        for host, ips in dns_future.result().items():
            add(host, "dns-brute", ips)
        if wb_future is not None:
            for name in wb_future.result():
                add(name, "wayback")

    # The apex itself is always part of the surface, even if no source listed it.
    add(domain, "target")

    log.info("collect: %d unique hostnames", len(merged))
    return merged


def run(
    domain: str,
    wordlist_size: Optional[int] = None,
    use_wayback: bool = True,
    http_timeout: float = 3.0,
    dns_timeout: float = 3.0,
    workers: int = 40,
    collect_progress=None,
    enrich_progress=None,
) -> Dict:
    """Execute the full pipeline and return the results document."""
    domain = validate_domain(domain)
    started = datetime.now(timezone.utc)

    merged = collect(
        domain,
        wordlist_size=wordlist_size,
        use_wayback=use_wayback,
        dns_timeout=dns_timeout,
        dns_workers=workers,
        progress=collect_progress,
    )

    known_ips = {host: data["ips"] for host, data in merged.items() if data["ips"]}
    records = enrich.enrich_all(
        sorted(merged.keys()),
        known_ips=known_ips,
        workers=workers,
        timeout=http_timeout,
        progress=enrich_progress,
    )

    for record in records:
        record["sources"] = merged[record["hostname"]]["sources"]

    classify.classify_all(records, domain)
    finished = datetime.now(timezone.utc)

    source_counts: Dict[str, int] = {}
    for record in records:
        for source in record["sources"]:
            source_counts[source] = source_counts.get(source, 0) + 1

    return {
        "target": domain,
        "scanned_at": started.isoformat(timespec="seconds"),
        "duration_seconds": round((finished - started).total_seconds(), 1),
        "summary": {
            "total": len(records),
            "alive": sum(1 for r in records if r["alive"]),
            "http_ok": sum(1 for r in records if r.get("status")),
            "by_risk": classify.summarise(records),
            "by_source": source_counts,
            "unique_ips": len({ip for r in records for ip in r["ips"]}),
        },
        "results": records,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="subdomain-mapper",
        description="Passive subdomain discovery and attack surface mapping.",
        epilog="Use only against domains you own or are authorised to test.",
    )
    parser.add_argument("domain", help="target domain, e.g. example.com")
    parser.add_argument(
        "-o", "--output", default="results.json", help="JSON output path"
    )
    parser.add_argument(
        "-r",
        "--report",
        default="report.html",
        help="standalone HTML report path (pass 'none' to skip)",
    )
    parser.add_argument(
        "-w",
        "--wordlist-size",
        type=int,
        default=None,
        help="use only the first N wordlist prefixes (default: all)",
    )
    parser.add_argument(
        "-t", "--timeout", type=float, default=3.0, help="HTTP timeout in seconds"
    )
    parser.add_argument(
        "--dns-timeout", type=float, default=3.0, help="DNS timeout in seconds"
    )
    parser.add_argument(
        "-c", "--workers", type=int, default=40, help="concurrent workers"
    )
    parser.add_argument(
        "--no-wayback", action="store_true", help="skip the Wayback Machine source"
    )
    parser.add_argument("-q", "--quiet", action="store_true", help="errors only")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.ERROR if args.quiet else logging.INFO,
        format="%(asctime)s  %(levelname)-7s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    try:
        data = run(
            args.domain,
            wordlist_size=args.wordlist_size,
            use_wayback=not args.no_wayback,
            http_timeout=args.timeout,
            dns_timeout=args.dns_timeout,
            workers=args.workers,
        )
    except ValueError as exc:
        print(f"chyba: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\npřerušeno uživatelem", file=sys.stderr)
        return 130

    output_path = Path(args.output)
    output_path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    summary = data["summary"]
    print(
        f"\n{data['target']}: {summary['total']} hostů "
        f"({summary['alive']} živých, {summary['unique_ips']} unikátních IP) "
        f"za {data['duration_seconds']} s"
    )
    risk = summary["by_risk"]
    print(
        f"riziko: {risk['high']} vysoké / {risk['medium']} střední / {risk['low']} nízké"
    )
    print(f"JSON: {output_path}")

    if args.report and args.report.lower() != "none":
        # Imported late so the scanner stays usable without the viz package.
        from viz.build_report import build_report

        report_path = build_report(data, Path(args.report))
        print(f"report: {report_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
