"""Inline scan results into the D3 template to produce a standalone report.

The output is a single HTML file with no backend and no local assets - it can
be opened straight from disk or published to GitHub Pages.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, Union

TEMPLATE_PATH = Path(__file__).resolve().parent / "template.html"


def _safe_json(data: Dict) -> str:
    """Serialise data for embedding inside a <script> block.

    ``</script>`` anywhere in a page title would otherwise terminate the block
    early and break the report, so the sequence is escaped.
    """
    payload = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    return (
        payload.replace("</", "<\\/")
        # U+2028/U+2029 are literal line terminators in JavaScript source.
        .replace(" ", "\\u2028")
        .replace(" ", "\\u2029")
    )


def build_report(
    data: Dict,
    output: Union[str, Path] = "report.html",
    template: Union[str, Path, None] = None,
) -> Path:
    """Write the finished report and return its path."""
    template_path = Path(template) if template else TEMPLATE_PATH
    if not template_path.exists():
        raise FileNotFoundError(f"template not found: {template_path}")

    html = template_path.read_text(encoding="utf-8")
    html = html.replace("__DATA__", _safe_json(data))
    html = html.replace("__TARGET__", str(data.get("target", "unknown")))

    output_path = Path(output)
    if output_path.parent != Path(""):
        output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")
    return output_path


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="build_report",
        description="Render a standalone HTML report from a results.json file.",
    )
    parser.add_argument("results", help="path to results.json")
    parser.add_argument("-o", "--output", default="report.html", help="output HTML path")
    parser.add_argument("--template", default=None, help="custom template path")
    args = parser.parse_args(argv)

    try:
        data = json.loads(Path(args.results).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"chyba: nelze načíst {args.results}: {exc}", file=sys.stderr)
        return 2

    path = build_report(data, args.output, args.template)
    size_kb = path.stat().st_size / 1024
    print(f"report: {path} ({size_kb:.0f} kB, {len(data.get('results', []))} hostů)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
