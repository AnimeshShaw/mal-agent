"""Evaluation metrics for the judge experiments.

Conventions (stated once, used everywhere):
  - verdicts normalise to malicious / benign / undetermined; 'suspicious'
    counts as a positive call, 'abstain' as undetermined;
  - recall is STRICT: an undetermined call on real malware is a miss;
  - FPR is over committed calls on benign samples; the abstention rate on
    benign samples is reported separately;
  - coverage = committed calls / all samples.
"""
from __future__ import annotations
import math
import random
from collections import Counter
from typing import Callable, Iterable, Optional


def normalize_verdict(v: Optional[str]) -> str:
    if v in ("malicious", "suspicious"):
        return "malicious"
    if v == "benign":
        return "benign"
    return "undetermined"


def _div(a, b):
    return a / b if b else None


def confusion(pairs: Iterable[tuple[str, str]]) -> dict:
    """pairs of (label, predicted)."""
    tp = fp = tn = fn = um = ub = 0
    for label, pred in pairs:
        p = normalize_verdict(pred)
        if p == "undetermined":
            if label == "malicious":
                um += 1
            else:
                ub += 1
        elif label == "malicious":
            tp, fn = tp + (p == "malicious"), fn + (p == "benign")
        else:
            fp, tn = fp + (p == "malicious"), tn + (p == "benign")
    n = tp + fp + tn + fn + um + ub
    precision = _div(tp, tp + fp)
    recall = _div(tp, tp + fn + um)
    f1 = (2 * precision * recall / (precision + recall)
          if precision is not None and recall is not None and (precision + recall) else None)
    return {"n": n, "tp": tp, "fp": fp, "tn": tn, "fn": fn, "undet_mal": um, "undet_ben": ub,
            "precision": precision, "recall": recall, "f1": f1,
            "fpr": _div(fp, fp + tn), "fnr_committed": _div(fn, tp + fn),
            "coverage": _div(n - um - ub, n),
            "accuracy_committed": _div(tp + tn, tp + tn + fp + fn),
            "abstain_rate_benign": _div(ub, fp + tn + ub),
            "abstain_rate_malicious": _div(um, tp + fn + um)}


def bootstrap_ci(values: list, stat: Callable, n: int = 1000, seed: int = 0,
                 alpha: float = 0.05) -> tuple[Optional[float], Optional[float]]:
    rng = random.Random(seed)
    stats = []
    for _ in range(n):
        s = stat([values[rng.randrange(len(values))] for _ in values])
        if s is not None:
            stats.append(s)
    if not stats:
        return None, None
    stats.sort()
    return stats[int(alpha / 2 * len(stats))], stats[min(len(stats) - 1, int((1 - alpha / 2) * len(stats)))]


def cohen_kappa(a: list, b: list) -> Optional[float]:
    n = len(a)
    if n == 0 or n != len(b):
        return None
    po = sum(x == y for x, y in zip(a, b)) / n
    ca, cb = Counter(a), Counter(b)
    pe = sum(ca[k] * cb.get(k, 0) for k in ca) / (n * n)
    return 1.0 if pe == 1 else (po - pe) / (1 - pe)


def fleiss_kappa(ratings: list[list]) -> Optional[float]:
    """ratings: per item, the list of category labels from k raters."""
    if not ratings:
        return None
    k = len(ratings[0])
    cats = sorted({c for r in ratings for c in r})
    N = len(ratings)
    counts = [[r.count(c) for c in cats] for r in ratings]
    P_i = [(sum(x * x for x in row) - k) / (k * (k - 1)) for row in counts]
    P_bar = sum(P_i) / N
    p_j = [sum(row[j] for row in counts) / (N * k) for j in range(len(cats))]
    Pe = sum(p * p for p in p_j)
    return 1.0 if Pe == 1 else (P_bar - Pe) / (1 - Pe)


def ece(confidences: list[float], correct: list[bool], bins: int = 10) -> Optional[float]:
    """Expected calibration error of stated confidence vs. correctness."""
    if not confidences:
        return None
    total, err = len(confidences), 0.0
    for b in range(bins):
        lo, hi = b / bins, (b + 1) / bins
        idx = [i for i, c in enumerate(confidences) if (lo < c <= hi) or (b == 0 and c == 0)]
        if not idx:
            continue
        acc = sum(correct[i] for i in idx) / len(idx)
        conf = sum(confidences[i] for i in idx) / len(idx)
        err += len(idx) / total * abs(acc - conf)
    return err


def aurc(confidences: list[float], correct: list[bool]) -> Optional[float]:
    """Area under the risk-coverage curve (lower is better): sort decisions
    by confidence, and average the error rate of the top-k over all k."""
    if not confidences:
        return None
    order = sorted(range(len(confidences)), key=lambda i: -confidences[i])
    errs, area = 0, 0.0
    for k, i in enumerate(order, start=1):
        errs += not correct[i]
        area += errs / k
    return area / len(order)


def risk_coverage_curve(confidences: list[float], correct: list[bool]) -> list[tuple[float, float]]:
    order = sorted(range(len(confidences)), key=lambda i: -confidences[i])
    out, errs = [], 0
    for k, i in enumerate(order, start=1):
        errs += not correct[i]
        out.append((k / len(order), errs / k))
    return out


def mcnemar(a_correct: list[bool], b_correct: list[bool]) -> dict:
    """Paired test between two arms on the same samples (exact binomial)."""
    b01 = sum(1 for x, y in zip(a_correct, b_correct) if x and not y)
    b10 = sum(1 for x, y in zip(a_correct, b_correct) if y and not x)
    n = b01 + b10
    if n == 0:
        return {"b01": 0, "b10": 0, "p": 1.0}
    k = min(b01, b10)
    p = sum(math.comb(n, i) for i in range(0, k + 1)) / 2 ** n * 2
    return {"b01": b01, "b10": b10, "p": min(1.0, p)}
