"""Detection metrics with Wilson score intervals.

A scanner is scored as a binary classifier per sample: flagged or not. Every
rate comes with a 95% Wilson interval, because on a few hundred samples a
two-point difference is often noise.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

Z95 = 1.959963984540054


def wilson(successes: int, total: int, z: float = Z95) -> tuple[float, float]:
    """95% Wilson score interval for a proportion. (0, 1) when total is 0."""
    if total <= 0:
        return (0.0, 1.0)
    p = successes / total
    denom = 1 + z * z / total
    centre = (p + z * z / (2 * total)) / denom
    half = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


@dataclass
class Rate:
    hits: int
    total: int

    @property
    def value(self) -> float | None:
        return self.hits / self.total if self.total else None

    @property
    def interval(self) -> tuple[float, float]:
        return wilson(self.hits, self.total)

    def as_dict(self) -> dict:
        lo, hi = self.interval
        return {"hits": self.hits, "total": self.total, "value": self.value, "ci95": [lo, hi]}


@dataclass
class Confusion:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0

    def add(self, malicious: bool, flagged: bool) -> None:
        if malicious and flagged:
            self.tp += 1
        elif malicious:
            self.fn += 1
        elif flagged:
            self.fp += 1
        else:
            self.tn += 1

    @property
    def recall(self) -> Rate:
        return Rate(self.tp, self.tp + self.fn)

    @property
    def false_positive_rate(self) -> Rate:
        return Rate(self.fp, self.fp + self.tn)

    @property
    def precision(self) -> Rate:
        return Rate(self.tp, self.tp + self.fp)

    @property
    def f1(self) -> float | None:
        p, r = self.precision.value, self.recall.value
        if not p or not r:
            return None
        return 2 * p * r / (p + r)

    def as_dict(self) -> dict:
        return {
            "tp": self.tp, "fp": self.fp, "tn": self.tn, "fn": self.fn,
            "recall": self.recall.as_dict(),
            "precision": self.precision.as_dict(),
            "false_positive_rate": self.false_positive_rate.as_dict(),
            "f1": self.f1,
        }


# A sample counts as "flagged" at two thresholds: any non-clean verdict
# (block or review), and block only. Both are reported.
THRESHOLDS = {
    "flagged": {"block", "review"},
    "blocked": {"block"},
}


@dataclass
class Scorecard:
    overall: dict[str, Confusion] = field(default_factory=lambda: {t: Confusion() for t in THRESHOLDS})
    # breakdown name -> group value -> threshold -> Confusion
    groups: dict[str, dict[str, dict[str, Confusion]]] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def add(self, sample: dict, verdict: str) -> None:
        malicious = sample["label"] == "malicious"
        for name, verdicts in THRESHOLDS.items():
            self.overall[name].add(malicious, verdict in verdicts)
        breakdowns = {
            "category": sample.get("categories") or [],
            "source": [sample["source"]] if sample.get("source") else [],
            "provenance": [sample["provenance"]] if sample.get("provenance") else [],
            "dataset": [sample["dataset"]],
        }
        for name, values in breakdowns.items():
            for value in values:
                group = self.groups.setdefault(name, {}).setdefault(value, {t: Confusion() for t in THRESHOLDS})
                for t, verdicts in THRESHOLDS.items():
                    group[t].add(malicious, verdict in verdicts)

    def as_dict(self) -> dict:
        return {
            "overall": {t: c.as_dict() for t, c in self.overall.items()},
            "groups": {
                name: {value: {t: c.as_dict() for t, c in by_t.items()} for value, by_t in sorted(groups.items())}
                for name, groups in sorted(self.groups.items())
            },
            "errors": self.errors,
        }
