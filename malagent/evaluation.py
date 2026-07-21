"""M6 evaluation harness: runs analyze() over a labeled benign/malicious
sample set and reports precision/recall/F1 against ground truth.

'undetermined' verdicts are the system's own honest abstention -- this
harness tracks them separately (undetermined_malicious/undetermined_benign)
rather than silently folding them into benign or malicious. Doing the
latter would misrepresent the project's own central design principle:
report where the evidence can't support a call, don't guess. Both a
standard 'recall' (which counts an abstention on real malware as a miss,
same as everyone expects 'recall' to mean) and a 'committed_recall'
(computed only over cases where the system actually took a side) are
reported, so calibration work can see both "how often we're right when we
commit" and "how often we correctly commit at all"."""
from __future__ import annotations
import csv
from dataclasses import dataclass, field
from typing import Callable, Literal, Optional
from .contracts import Provenance

GroundTruth = Literal["benign", "malicious"]
_VALID_LABELS = {"benign", "malicious"}


@dataclass(frozen=True)
class LabeledSample:
    path: str
    label: GroundTruth
    notes: str = ""


@dataclass
class SampleResult:
    sample: LabeledSample
    predicted_verdict: str
    confidence: float


@dataclass
class EvaluationReport:
    results: list = field(default_factory=list)
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    undetermined_malicious: int = 0
    undetermined_benign: int = 0

    @property
    def _total(self) -> int:
        return (self.tp + self.fp + self.tn + self.fn
                + self.undetermined_malicious + self.undetermined_benign)

    @property
    def precision(self) -> Optional[float]:
        denom = self.tp + self.fp
        return self.tp / denom if denom else None

    @property
    def committed_recall(self) -> Optional[float]:
        """Recall over committed (non-abstained) predictions only."""
        denom = self.tp + self.fn
        return self.tp / denom if denom else None

    @property
    def recall(self) -> Optional[float]:
        """Standard recall: an abstention on real malware still counts as
        a miss in the denominator -- it didn't produce a correct positive
        call, whatever the reason."""
        denom = self.tp + self.fn + self.undetermined_malicious
        return self.tp / denom if denom else None

    @property
    def f1(self) -> Optional[float]:
        p, r = self.precision, self.committed_recall
        if p is None or r is None or (p + r) == 0:
            return None
        return 2 * p * r / (p + r)

    @property
    def undetermined_rate(self) -> float:
        total = self._total
        if not total:
            return 0.0
        return (self.undetermined_malicious + self.undetermined_benign) / total

    @property
    def undetermined_rate_malicious(self) -> Optional[float]:
        denom = self.tp + self.fn + self.undetermined_malicious
        return self.undetermined_malicious / denom if denom else None

    @property
    def undetermined_rate_benign(self) -> Optional[float]:
        denom = self.tn + self.fp + self.undetermined_benign
        return self.undetermined_benign / denom if denom else None


class _Counters:
    """Shared confusion-matrix classification rule: 'malicious'/'suspicious'
    count as a positive call, 'undetermined' is abstention tracked
    separately by ground truth, never folded into a bucket. Shared between
    evaluate() (the deterministic verdict) and verdict_suggestion.py's
    harness (an LLM's holistic guess) so both are scored by the exact same
    rule -- any difference between their numbers is a real difference in
    judgment quality, not an artifact of differently-written bucketing
    logic."""
    def __init__(self):
        self.tp = self.fp = self.tn = self.fn = 0
        self.undetermined_malicious = self.undetermined_benign = 0

    def classify(self, predicted: str, label: str) -> None:
        positive = predicted in ("malicious", "suspicious")
        if predicted == "undetermined":
            if label == "malicious":
                self.undetermined_malicious += 1
            else:
                self.undetermined_benign += 1
        elif label == "malicious":
            self.tp += 1 if positive else 0
            self.fn += 0 if positive else 1
        else:  # benign
            self.fp += 1 if positive else 0
            self.tn += 0 if positive else 1

    def to_report(self, results: list) -> "EvaluationReport":
        return EvaluationReport(results=results, tp=self.tp, fp=self.fp, tn=self.tn, fn=self.fn,
                                undetermined_malicious=self.undetermined_malicious,
                                undetermined_benign=self.undetermined_benign)


def load_labeled_samples(manifest_path: str) -> list[LabeledSample]:
    """CSV manifest: path,label[,notes]. label must be 'benign' or
    'malicious' -- this harness only evaluates binary ground truth; the
    system's own verdict.verdict is the four-valued thing being measured."""
    samples: list[LabeledSample] = []
    with open(manifest_path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            label = row["label"].strip()
            if label not in _VALID_LABELS:
                raise ValueError(
                    f"invalid label {label!r} for {row['path']!r}: "
                    f"must be one of {sorted(_VALID_LABELS)}")
            samples.append(LabeledSample(
                path=row["path"].strip(), label=label,  # type: ignore[arg-type]
                notes=(row.get("notes") or "").strip()))
    return samples


def evaluate(samples: list[LabeledSample], *,
            analyze_fn: Optional[Callable] = None, **analyze_kwargs) -> EvaluationReport:
    if analyze_fn is None:
        from .pipeline import analyze as analyze_fn

    results: list[SampleResult] = []
    counters = _Counters()
    total = len(samples)

    for i, sample in enumerate(samples, start=1):
        _, verdict, _, _, _ = analyze_fn(
            sample.path, provenance=Provenance(source="dataset"), **analyze_kwargs)
        predicted = verdict.verdict
        results.append(SampleResult(sample=sample, predicted_verdict=predicted,
                                    confidence=verdict.confidence))
        print(f"[{i}/{total}] {sample.path} (actual={sample.label}) -> "
              f"predicted={predicted} (confidence={verdict.confidence})", flush=True)
        counters.classify(predicted, sample.label)

    return counters.to_report(results)


def format_report(report: EvaluationReport) -> str:
    def fmt(x):
        return "n/a" if x is None else f"{x:.4f}"

    lines = [
        "M6 EVALUATION REPORT",
        "=" * 40,
        f"Samples evaluated: {report._total}",
        f"TP={report.tp}  FP={report.fp}  TN={report.tn}  FN={report.fn}",
        f"Undetermined (abstained): {report.undetermined_malicious + report.undetermined_benign} "
        f"(on actual malicious: {report.undetermined_malicious}, "
        f"on actual benign: {report.undetermined_benign})",
        "-" * 40,
        f"precision:        {fmt(report.precision)}",
        f"recall:           {fmt(report.recall)}  (counts abstention on malware as a miss)",
        f"committed_recall: {fmt(report.committed_recall)}  (only among committed calls)",
        f"f1:               {fmt(report.f1)}",
        f"undetermined_rate:          {report.undetermined_rate:.4f}",
        f"undetermined_rate_malicious: {fmt(report.undetermined_rate_malicious)}",
        f"undetermined_rate_benign:    {fmt(report.undetermined_rate_benign)}",
    ]
    return "\n".join(lines)
