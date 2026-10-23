"""Command line entry point."""
from __future__ import annotations

import argparse
import json
import sys

from .analyser import analyse

BAND_MARK = {
    "phishing": "!!",
    "likely_phishing": "! ",
    "suspicious": "~ ",
    "safe": "  ",
}


def render(verdict) -> str:
    lines = [
        f"URL   : {verdict.url}",
        f"Domain: {verdict.parsed.registrable if verdict.parsed else '?'}",
        f"Score : {verdict.score}/100  ->  {verdict.band.upper()}",
        "",
    ]
    if not verdict.signals:
        lines.append("No phishing signals detected.")
        return "\n".join(lines)
    lines.append("Signals (strongest first):")
    for signal in verdict.signals:
        lines.append(f"{BAND_MARK[verdict.band]} +{signal.weight:>3}  {signal.name}")
        lines.append(f"        {signal.detail}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="phishguard", description="Explainable phishing-URL analyser")
    parser.add_argument("url")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    args = parser.parse_args(argv)

    verdict = analyse(args.url)
    if args.json:
        print(json.dumps(verdict.public(), indent=2))
    else:
        print(render(verdict))
    return 1 if verdict.band in ("phishing", "likely_phishing") else 0


if __name__ == "__main__":
    sys.exit(main())
