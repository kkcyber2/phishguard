"""Combine signals into a score and a band."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from . import signals as signal_module
from .signals import Signal
from .urlparse import ParsedURL, parse

BANDS = (
    (70, "phishing"),
    (45, "likely_phishing"),
    (20, "suspicious"),
    (0, "safe"),
)


@dataclass
class Verdict:
    url: str
    score: int
    band: str
    signals: list[Signal] = field(default_factory=list)
    parsed: ParsedURL | None = None

    def public(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "score": self.score,
            "band": self.band,
            "signals": [s.public() for s in self.signals],
            "registrable_domain": self.parsed.registrable if self.parsed else None,
        }


def band_for(score: int) -> str:
    for threshold, name in BANDS:
        if score >= threshold:
            return name
    return "safe"


def score_signals(signals: list[Signal]) -> int:
    """Sum the weights and squash into 0-100.

    The raw sum is capped at 100 rather than scaled, so a URL with one decisive
    signal (an IP-literal host, say) is not diluted by the absence of others.
    """
    return min(100, sum(s.weight for s in signals))


def analyse(url: str) -> Verdict:
    parsed = parse(url)
    found = signal_module.collect(parsed)
    found.sort(key=lambda s: -s.weight)
    score = score_signals(found)
    return Verdict(url=url, score=score, band=band_for(score), signals=found, parsed=parsed)
