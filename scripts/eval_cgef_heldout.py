#!/usr/bin/env python3
"""Real evaluation of Confidence-Gated Evidence Fusion (CGEF) against a
genuinely held-out set (dataset/manifest_heldout.csv -- 45 fresh
MalwareBazaar samples from 7 families never used to design CGEF's
thresholds, plus 12 real diverse third-party benign executables).

Runs each sample through the real pipeline ONCE (enable_models=False --
CGEF's decision never depends on the LLM stages, which are severity=info
and never counted), then derives THREE verdicts from that single run's
state, avoiding a second expensive pipeline pass per sample:
  1. CGEF (fused)      -- reporter.build_verdict()'s real, current output
  2. EMBER alone        -- the naive 0.15 threshold from Phase 1
  3. Deterministic gate alone -- build_verdict() with EMBER's evidence
                                 stripped, forcing the old fallback path
"""
from __future__ import annotations
import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from malagent import pipeline
from malagent.contracts import EgressPolicy
from malagent.reporter import build_verdict

_EMBER_NAIVE_THRESHOLD = 0.15


def _ember_score(state):
    for ev in state.evidence:
        if ev.locator == "ember:score":
            try:
                return float(ev.excerpt)
            except (TypeError, ValueError):
                return None
    return None


def _confusion(rows, key):
    tp = fp = tn = fn = other = other_mal = 0
    for label, pred in rows:
        p = pred[key]
        if label == "malicious":
            if p == "malicious":
                tp += 1
            elif p == "benign":
                fn += 1
            else:
                other += 1
                other_mal += 1
        else:
            if p == "benign":
                tn += 1
            elif p == "malicious":
                fp += 1
            else:
                other += 1
    precision = tp / (tp + fp) if (tp + fp) else float("nan")
    # strict recall: a non-committal call on real malware is a miss
    recall = tp / (tp + fn + other_mal) if (tp + fn + other_mal) else float("nan")
    f1 = (2 * precision * recall / (precision + recall)
         if (precision + recall) and precision == precision and recall == recall else float("nan"))
    return dict(tp=tp, fp=fp, tn=tn, fn=fn, other=other, precision=precision, recall=recall, f1=f1)


def main():
    start = int(sys.argv[1]) if len(sys.argv) > 1 else 1

    rows = []
    with open("dataset/manifest_heldout.csv", newline="") as f:
        for r in csv.DictReader(f):
            rows.append((r["path"], r["label"]))

    results = []
    total = len(rows)
    for i, (path, label) in enumerate(rows, start=1):
        if i < start:
            continue
        try:
            state, cgef_verdict, *_ = pipeline.analyze(
                path, enable_models=False, policy=EgressPolicy(allow_cloud=False))
        except Exception as e:
            print(f"[{i}/{total}] {path} -> ERROR: {e}", flush=True)
            results.append((label, {"cgef": "error", "ember_alone": "error", "gate_alone": "error"}))
            continue

        ember_p = _ember_score(state)
        if ember_p is None:
            ember_alone = "undetermined"
        else:
            ember_alone = "malicious" if ember_p >= _EMBER_NAIVE_THRESHOLD else "benign"

        state_no_ember = state.model_copy(update={
            "evidence": [e for e in state.evidence if e.locator != "ember:score"]})
        gate_alone_verdict = build_verdict(state_no_ember)

        pred = {"cgef": cgef_verdict.verdict, "ember_alone": ember_alone,
               "gate_alone": gate_alone_verdict.verdict}
        results.append((label, pred))
        print(f"[{i}/{total}] {Path(path).name[:50]:50s} (actual={label:10s}) -> "
             f"cgef={pred['cgef']:12s} ember_alone={pred['ember_alone']:12s} "
             f"gate_alone={pred['gate_alone']:12s} (ember_p={ember_p})", flush=True)

    print()
    print("=" * 70)
    print(f"HELD-OUT EVALUATION: {total} samples "
         f"({sum(1 for l, _ in results if l=='malicious')} malicious, "
         f"{sum(1 for l, _ in results if l=='benign')} benign)")
    print("=" * 70)
    for key, label in [("cgef", "CGEF (fused)"), ("ember_alone", "EMBER alone (naive 0.15 threshold)"),
                       ("gate_alone", "Deterministic gate alone")]:
        c = _confusion(results, key)
        print(f"\n{label}:")
        print(f"  TP={c['tp']} FP={c['fp']} TN={c['tn']} FN={c['fn']} other/undetermined={c['other']}")
        print(f"  precision={c['precision']:.3f} recall={c['recall']:.3f} f1={c['f1']:.3f}")


if __name__ == "__main__":
    main()
