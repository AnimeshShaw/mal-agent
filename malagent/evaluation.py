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
import statistics
from dataclasses import dataclass, field
from typing import Callable, Literal, Optional
from .contracts import AnalysisState, Provenance

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
        print(f"=== [{i}/{total}] starting {sample.path} ===", flush=True)
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


# ---- efficiency/cost aggregation (docs/EFFICIENCY.md) ----
# Real-run timing/cost numbers for the research-paper-style efficiency
# table referenced in docs/AI-Malware-Analysis-Research-and-Framework.md
# section 5 ("Efficiency: wall-clock ... token/$ cost; local-vs-cloud
# trade-off"). Timing is captured by orchestrator.run_linear() (per named
# pipeline stage, on AnalysisState.stage_durations_ms) and models.ModelRouter
# (per model call, on ModelCall.duration_ms) -- purely observational
# instrumentation, never fed back into reporter.build_verdict()'s score.
#
# Cost: ModelCall does not currently record token counts (the ModelProvider
# protocol's complete() returns only text, discarding whatever usage data
# the underlying SDK response carried). Without token counts there is no
# real number to report -- guessing one from prompt length would be a
# fabricated figure, which this project's rules explicitly forbid. So cost
# is reported as "not computed" with an honest reason whenever cloud calls
# occurred, and as "$0 (no cloud calls made)" only when that's literally
# true. Adding token-count capture to the provider protocol is a natural
# follow-up once cloud escalation is actually exercised against a live API.

@dataclass(frozen=True)
class TimingStats:
    n: int
    min_ms: float
    median_ms: float
    max_ms: float
    mean_ms: float


def _timing_stats(values: list) -> Optional[TimingStats]:
    if not values:
        return None
    return TimingStats(n=len(values), min_ms=min(values), median_ms=statistics.median(values),
                       max_ms=max(values), mean_ms=statistics.mean(values))


@dataclass
class EfficiencyReport:
    n_runs: int
    per_stage: dict = field(default_factory=dict)             # stage -> TimingStats
    per_stage_statuses: dict = field(default_factory=dict)    # stage -> {status: count}
    total_wallclock: Optional[TimingStats] = None
    model_call_count_local: int = 0
    model_call_count_cloud: int = 0
    local_call_duration: Optional[TimingStats] = None
    cloud_call_duration: Optional[TimingStats] = None
    cost_computed: bool = False
    total_cost_usd: Optional[float] = None
    cost_note: str = ""


def aggregate_efficiency(states: list) -> EfficiencyReport:
    """Aggregates real per-stage/per-run timing (and, where computable,
    cost) across a set of completed AnalysisState runs. Synthetic states
    with hand-set stage_durations_ms/model_calls are exactly as valid an
    input as ones produced by a real analyze() call -- this function only
    does arithmetic over whatever AnalysisState it's given."""
    per_stage_values: dict[str, list] = {}
    per_stage_statuses: dict[str, dict[str, int]] = {}
    run_totals: list = []
    local_durations: list = []
    cloud_durations: list = []
    n_local = 0
    n_cloud = 0
    any_cloud_calls = False

    for state in states:
        run_total = 0.0
        for stage, ms in state.stage_durations_ms.items():
            per_stage_values.setdefault(stage, []).append(ms)
            run_total += ms
        run_totals.append(run_total)

        for sr in state.stage_results:
            counts = per_stage_statuses.setdefault(sr.stage, {})
            counts[sr.status] = counts.get(sr.status, 0) + 1

        for mc in state.model_calls:
            if mc.location == "local":
                n_local += 1
                if mc.duration_ms is not None:
                    local_durations.append(mc.duration_ms)
            else:
                n_cloud += 1
                any_cloud_calls = True
                if mc.duration_ms is not None:
                    cloud_durations.append(mc.duration_ms)

    per_stage = {stage: _timing_stats(vals) for stage, vals in per_stage_values.items()}

    if any_cloud_calls:
        cost_note = (f"cost not computed: {n_cloud} cloud model call(s) were made, but "
                     f"ModelCall does not currently record token counts, so real "
                     f"cost cannot be derived without guessing")
    else:
        cost_note = ("no cloud model calls were made in these runs (0 cloud ModelCall "
                     "records) -- cost is $0 for these specific runs; this says nothing "
                     "about the cost of a hypothetical run that does escalate to cloud")

    return EfficiencyReport(
        n_runs=len(states),
        per_stage=per_stage,
        per_stage_statuses=per_stage_statuses,
        total_wallclock=_timing_stats(run_totals),
        model_call_count_local=n_local,
        model_call_count_cloud=n_cloud,
        local_call_duration=_timing_stats(local_durations),
        cloud_call_duration=_timing_stats(cloud_durations),
        cost_computed=False,
        total_cost_usd=None,
        cost_note=cost_note,
    )


def format_efficiency_report(report: EfficiencyReport) -> str:
    def fmt_stats(s: Optional[TimingStats]) -> str:
        if s is None:
            return "n/a (no data)"
        return (f"n={s.n}  min={s.min_ms:.1f}ms  median={s.median_ms:.1f}ms  "
               f"max={s.max_ms:.1f}ms  mean={s.mean_ms:.1f}ms")

    lines = [
        "EFFICIENCY/COST REPORT",
        "=" * 40,
        f"Runs aggregated: {report.n_runs}",
        "-" * 40,
        "Per-stage wall-clock time:",
    ]
    for stage in sorted(report.per_stage):
        statuses = report.per_stage_statuses.get(stage, {})
        status_note = ", ".join(f"{k}:{v}" for k, v in sorted(statuses.items()))
        lines.append(f"  {stage:<20} {fmt_stats(report.per_stage[stage])}"
                     f"{f'  [{status_note}]' if status_note else ''}")
    lines += [
        "-" * 40,
        f"Total wall-clock per run: {fmt_stats(report.total_wallclock)}",
        "-" * 40,
        f"Model calls: local={report.model_call_count_local} "
        f"cloud={report.model_call_count_cloud}",
        f"  local call duration:  {fmt_stats(report.local_call_duration)}",
        f"  cloud call duration:  {fmt_stats(report.cloud_call_duration)}",
        "-" * 40,
        f"Cost computed: {report.cost_computed}",
        f"  {report.cost_note}",
    ]
    return "\n".join(lines)
