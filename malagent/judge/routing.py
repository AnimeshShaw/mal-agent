"""Which samples are 'hard' and are sent to the judge.

Fixed before any judge result was seen, from the v1 calibration only:
  ember_ood            no in-distribution EMBER score (non-PE with no PE
                       payload, or EMBER unavailable)
  ember_gray           in-distribution score inside the gray zone
                       (0.05, 0.30) -- the band where no v1 sample fell
  ember_gate_conflict  EMBER and the deterministic evidence disagree:
                       EMBER says benign (< 0.15) but the gate is
                       corroborated, or EMBER says malicious (>= 0.15) on a
                       validly signed file with no high-signal category
Everything else keeps the EMBER-alone ('simple') verdict.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional

GRAY_LOW, GRAY_HIGH, THRESHOLD = 0.05, 0.30, 0.15


@dataclass
class Route:
    routed: bool
    reasons: list = field(default_factory=list)


def route(bundle: dict) -> Route:
    reasons = []
    p = (bundle.get("ember") or {}).get("decisive")
    gate = bundle.get("gate") or {}
    cats = gate.get("categories") or []
    corroborated = len(cats) >= gate.get("required", 3)
    if p is None:
        reasons.append("ember_ood")
    else:
        if GRAY_LOW < p < GRAY_HIGH:
            reasons.append("ember_gray")
        if (p < THRESHOLD and corroborated) or (p >= THRESHOLD and gate.get("signed") and not cats):
            reasons.append("ember_gate_conflict")
    return Route(routed=bool(reasons), reasons=reasons)


def hybrid_verdict(bundle: dict, judge_verdict: Optional[str]) -> str:
    """Routed samples take the judge's verdict (abstain -> undetermined);
    the rest keep the EMBER-alone baseline."""
    if not route(bundle).routed:
        return bundle["baselines"]["simple"]["verdict"]
    if judge_verdict in ("malicious", "benign"):
        return judge_verdict
    return "undetermined"
