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
    tp = fp = tn = fn = undetermined_malicious = undetermined_benign = 0
    total = len(samples)

    for i, sample in enumerate(samples, start=1):
        _, verdict, _, _, _ = analyze_fn(
            sample.path, provenance=Provenance(source="dataset"), **analyze_kwargs)
        predicted = verdict.verdict
        results.append(SampleResult(sample=sample, predicted_verdict=predicted,
                                    confidence=verdict.confidence))
        print(f"[{i}/{total}] {sample.path} (actual={sample.label}) -> "
              f"predicted={predicted} (confidence={verdict.confidence})", flush=True)

        positive = predicted in ("malicious", "suspicious")
        if predicted == "undetermined":
            if sample.label == "malicious":
                undetermined_malicious += 1
            else:
                undetermined_benign += 1
        elif sample.label == "malicious":
            tp += 1 if positive else 0
            fn += 0 if positive else 1
        else:  # benign
            fp += 1 if positive else 0
            tn += 0 if positive else 1

    return EvaluationReport(results=results, tp=tp, fp=fp, tn=tn, fn=fn,
                            undetermined_malicious=undetermined_malicious,
                            undetermined_benign=undetermined_benign)


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
