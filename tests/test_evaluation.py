"""M6 evaluation harness: runs analyze() over a labeled benign/malicious
sample set and reports precision/recall/F1 -- with 'undetermined' verdicts
tracked as honest abstention, never silently folded into benign or
malicious. Folding an abstention either way would misrepresent this
project's own central design principle (report where you can't tell,
don't guess), so the harness reports abstention rates separately instead
of hiding them inside the confusion matrix."""
from __future__ import annotations
from malagent import evaluation
from malagent.contracts import AnalysisState, ModelCall, Provenance, Sample, StageResult
from malagent.evaluation import (EvaluationReport, LabeledSample, aggregate_efficiency, evaluate,
                                 format_efficiency_report, format_report, load_labeled_samples)


def test_load_labeled_samples_from_csv_manifest(tmp_path):
    manifest = tmp_path / "manifest.csv"
    manifest.write_text(
        "path,label,notes\n"
        "/samples/notepad.exe,benign,stock windows binary\n"
        "/samples/sample1.bin,malicious,\n"
    )
    samples = load_labeled_samples(str(manifest))
    assert samples == [
        LabeledSample(path="/samples/notepad.exe", label="benign", notes="stock windows binary"),
        LabeledSample(path="/samples/sample1.bin", label="malicious", notes=""),
    ]


def test_load_labeled_samples_rejects_invalid_label(tmp_path):
    manifest = tmp_path / "manifest.csv"
    manifest.write_text("path,label\n/samples/x.bin,definitely_bad\n")
    try:
        load_labeled_samples(str(manifest))
        assert False, "expected ValueError"
    except ValueError as e:
        assert "definitely_bad" in str(e)


class _FakeVerdict:
    def __init__(self, verdict, confidence=0.5):
        self.verdict = verdict
        self.confidence = confidence


def _fake_analyze_factory(verdict_by_path):
    def _fake_analyze(path, **kwargs):
        v = _FakeVerdict(verdict_by_path[path])
        return (None, v, "", "", "", None)
    return _fake_analyze


def test_evaluate_prints_progress_per_sample(capsys):
    """A 46-sample real-data run has no other visibility into progress --
    evaluate() must print something after each sample completes, not just
    at the very end, so a long-running batch isn't silent."""
    samples = [LabeledSample(path="mal1", label="malicious"),
              LabeledSample(path="ben1", label="benign")]
    fake_analyze = _fake_analyze_factory({"mal1": "malicious", "ben1": "benign"})
    evaluate(samples, analyze_fn=fake_analyze)
    out = capsys.readouterr().out
    assert "[1/2]" in out and "mal1" in out
    assert "[2/2]" in out and "ben1" in out


def test_evaluate_computes_confusion_matrix_treating_suspicious_as_positive():
    samples = [
        LabeledSample(path="mal1", label="malicious"),   # predicted malicious -> TP
        LabeledSample(path="mal2", label="malicious"),   # predicted suspicious -> TP (positive bucket)
        LabeledSample(path="mal3", label="malicious"),   # predicted benign -> FN
        LabeledSample(path="ben1", label="benign"),       # predicted benign -> TN
        LabeledSample(path="ben2", label="benign"),       # predicted malicious -> FP
    ]
    fake_analyze = _fake_analyze_factory({
        "mal1": "malicious", "mal2": "suspicious", "mal3": "benign",
        "ben1": "benign", "ben2": "malicious",
    })
    report = evaluate(samples, analyze_fn=fake_analyze)
    assert report.tp == 2
    assert report.fn == 1
    assert report.tn == 1
    assert report.fp == 1
    assert report.undetermined_malicious == 0
    assert report.undetermined_benign == 0


def test_evaluate_tracks_undetermined_separately_not_as_fn_or_tn():
    samples = [
        LabeledSample(path="mal1", label="malicious"),   # predicted undetermined
        LabeledSample(path="ben1", label="benign"),       # predicted undetermined
    ]
    fake_analyze = _fake_analyze_factory({"mal1": "undetermined", "ben1": "undetermined"})
    report = evaluate(samples, analyze_fn=fake_analyze)
    assert report.tp == report.fp == report.tn == report.fn == 0
    assert report.undetermined_malicious == 1
    assert report.undetermined_benign == 1


def test_precision_recall_f1_committed_only():
    """precision/recall/f1 are computed over committed (non-undetermined)
    predictions only -- this is standard confusion-matrix math and is
    unaffected by abstentions by construction."""
    report = EvaluationReport(
        results=[], tp=8, fp=2, tn=15, fn=2, undetermined_malicious=0, undetermined_benign=0)
    assert report.precision == 0.8
    assert report.recall == 0.8
    assert round(report.f1, 4) == 0.8


def test_recall_denominator_includes_undetermined_malicious_as_a_miss():
    """Strict recall (the number most people mean by 'recall') must count
    an honest 'undetermined' on an actually-malicious sample as a miss in
    the denominator -- it's still a failure to flag real malware, even if
    it's an honest failure rather than a confident wrong answer."""
    report = EvaluationReport(
        results=[], tp=8, fp=0, tn=0, fn=1, undetermined_malicious=1, undetermined_benign=0)
    assert report.recall == 0.8  # 8 / (8 + 1 + 1)
    assert report.committed_recall == 8 / 9  # 8 / (8 + 1), excludes the abstention


def test_metrics_handle_zero_denominators_without_crashing():
    report = EvaluationReport(results=[], tp=0, fp=0, tn=0, fn=0,
                              undetermined_malicious=0, undetermined_benign=0)
    assert report.precision is None
    assert report.recall is None
    assert report.f1 is None
    assert report.undetermined_rate == 0.0


def test_undetermined_rate_reported_and_broken_out_by_ground_truth():
    report = EvaluationReport(
        results=[], tp=1, fp=1, tn=1, fn=1, undetermined_malicious=2, undetermined_benign=0)
    # total = tp+fp+tn+fn+undetermined = 1+1+1+1+2 = 6
    assert report.undetermined_rate == 2 / 6
    # of all actual-malicious samples (tp=1 + fn=1 + undet_mal=2 = 4), 2 were abstained on
    assert report.undetermined_rate_malicious == 2 / 4
    # of all actual-benign samples (tn=1 + fp=1 + undet_ben=0 = 2), none were abstained on
    assert report.undetermined_rate_benign == 0.0


def test_format_report_includes_all_key_numbers():
    report = EvaluationReport(
        results=[], tp=8, fp=2, tn=15, fn=2, undetermined_malicious=1, undetermined_benign=1)
    text = format_report(report)
    assert "precision" in text.lower()
    assert "recall" in text.lower()
    assert "0.8" in text
    assert "undetermined" in text.lower()


# ---- efficiency/cost aggregation (docs/EFFICIENCY.md) ----

def _synthetic_state(run_id: str, stage_durations: dict, *, statuses: dict | None = None,
                     model_calls: list | None = None) -> AnalysisState:
    sample = Sample(sha256="a" * 64, md5="b" * 32, path="/tmp/x.malz",
                    file_type="PE", size=1, provenance=Provenance())
    state = AnalysisState(run_id=run_id, sample=sample)
    state.stage_durations_ms = dict(stage_durations)
    for stage, status in (statuses or {}).items():
        state.stage_results.append(StageResult(stage=stage, status=status))
    for mc in (model_calls or []):
        state.model_calls.append(mc)
    return state


def test_aggregate_efficiency_computes_per_stage_timing_stats():
    states = [
        _synthetic_state("r1", {"triage": 10.0, "static": 100.0}),
        _synthetic_state("r2", {"triage": 20.0, "static": 200.0}),
        _synthetic_state("r3", {"triage": 30.0, "static": 300.0}),
    ]
    report = aggregate_efficiency(states)

    triage = report.per_stage["triage"]
    assert triage.n == 3
    assert triage.min_ms == 10.0
    assert triage.median_ms == 20.0
    assert triage.max_ms == 30.0
    assert triage.mean_ms == 20.0

    static = report.per_stage["static"]
    assert static.n == 3
    assert static.min_ms == 100.0
    assert static.median_ms == 200.0
    assert static.max_ms == 300.0
    assert static.mean_ms == 200.0


def test_aggregate_efficiency_computes_total_wallclock_per_run():
    states = [
        _synthetic_state("r1", {"triage": 10.0, "static": 90.0}),    # total 100
        _synthetic_state("r2", {"triage": 20.0, "static": 180.0}),   # total 200
    ]
    report = aggregate_efficiency(states)
    assert report.n_runs == 2
    assert report.total_wallclock.min_ms == 100.0
    assert report.total_wallclock.max_ms == 200.0
    assert report.total_wallclock.mean_ms == 150.0
    assert report.total_wallclock.median_ms == 150.0


def test_aggregate_efficiency_tracks_stage_status_counts():
    """So the doc can honestly say 'skipped' rather than implying a fast
    real run when a stage was actually a no-op (e.g. Ghidra unavailable, or
    the known-good short-circuit)."""
    states = [
        _synthetic_state("r1", {"static": 5.0}, statuses={"static": "skipped"}),
        _synthetic_state("r2", {"static": 5000.0}, statuses={"static": "ok"}),
    ]
    report = aggregate_efficiency(states)
    assert report.per_stage_statuses["static"] == {"skipped": 1, "ok": 1}


def test_aggregate_efficiency_reports_cost_not_computed_when_no_cloud_calls():
    states = [_synthetic_state("r1", {"triage": 10.0}, model_calls=[
        ModelCall(provider="ollama", model="qwen2.5-coder:7b", location="local",
                  prompt_hash="x", egress_allowed=True, duration_ms=50.0),
    ])]
    report = aggregate_efficiency(states)
    assert report.model_call_count_local == 1
    assert report.model_call_count_cloud == 0
    assert report.cost_computed is False
    assert report.total_cost_usd is None
    assert "cloud" in report.cost_note.lower()


def test_aggregate_efficiency_reports_cost_not_computed_when_cloud_calls_lack_token_counts():
    """Even if cloud calls DID happen, ModelCall doesn't currently record
    token counts, so cost still can't be computed -- this must not be
    silently reported as $0, which would be a fabricated number."""
    states = [_synthetic_state("r1", {"triage": 10.0}, model_calls=[
        ModelCall(provider="anthropic", model="claude-sonnet-4-6", location="cloud",
                  prompt_hash="x", egress_allowed=True, duration_ms=800.0),
    ])]
    report = aggregate_efficiency(states)
    assert report.model_call_count_cloud == 1
    assert report.cost_computed is False
    assert report.total_cost_usd is None
    assert "token" in report.cost_note.lower()


def test_aggregate_efficiency_separates_local_and_cloud_call_durations():
    states = [_synthetic_state("r1", {}, model_calls=[
        ModelCall(provider="ollama", model="qwen2.5-coder:7b", location="local",
                  prompt_hash="a", egress_allowed=True, duration_ms=100.0),
        ModelCall(provider="ollama", model="qwen2.5-coder:7b", location="local",
                  prompt_hash="b", egress_allowed=True, duration_ms=300.0),
        ModelCall(provider="anthropic", model="claude-sonnet-4-6", location="cloud",
                  prompt_hash="c", egress_allowed=True, duration_ms=900.0),
    ])]
    report = aggregate_efficiency(states)
    assert report.model_call_count_local == 2
    assert report.model_call_count_cloud == 1
    assert report.local_call_duration.mean_ms == 200.0
    assert report.cloud_call_duration.mean_ms == 900.0


def test_aggregate_efficiency_handles_empty_states_list():
    report = aggregate_efficiency([])
    assert report.n_runs == 0
    assert report.total_wallclock is None
    assert report.per_stage == {}
    assert report.local_call_duration is None
    assert report.cloud_call_duration is None


def test_format_efficiency_report_includes_stage_and_cost_info():
    states = [_synthetic_state("r1", {"triage": 10.0, "static": 40.0},
                               statuses={"triage": "ok", "static": "ok"})]
    report = aggregate_efficiency(states)
    text = format_efficiency_report(report)
    assert "triage" in text.lower()
    assert "static" in text.lower()
    assert "cost" in text.lower()
    assert "1" in text  # n_runs somewhere in the output


# ---- 2026-09-27 audit fixes ----

def test_f1_uses_strict_recall_so_abstention_counts():
    """A system that abstains on 3 of 4 malware and gets the 1 it commits
    to right must not report F1=1.0 (the old behavior used committed
    recall). Strict recall 0.25, precision 1.0 -> F1 0.4."""
    report = EvaluationReport(results=[], tp=1, fp=0, tn=5, fn=0,
                              undetermined_malicious=3, undetermined_benign=0)
    assert round(report.f1, 4) == 0.4
    assert report.committed_f1 == 1.0


def test_fpr_over_committed_benign_calls():
    report = EvaluationReport(results=[], tp=0, fp=1, tn=3, fn=0,
                              undetermined_malicious=0, undetermined_benign=4)
    assert report.fpr == 0.25


def test_evaluate_disables_known_good_allowlist_by_default(monkeypatch, tmp_path):
    """The allowlist decides benign by hash lookup, so leaving it on while
    scoring a benign set whose hashes are in it measures the lookup, not
    the analysis (the original manifest's 26/26 benign were all in it)."""
    import os
    monkeypatch.setenv("KNOWN_GOOD_HASHES_PATH", str(tmp_path / "kg.csv"))
    seen = []

    def fake(path, **kw):
        seen.append(os.environ.get("KNOWN_GOOD_HASHES_PATH"))
        return _fake_analyze_factory({"ben1": "benign"})(path, **kw)

    evaluate([LabeledSample(path="ben1", label="benign")], analyze_fn=fake)
    assert seen == [None]
    assert os.environ.get("KNOWN_GOOD_HASHES_PATH") == str(tmp_path / "kg.csv")


def test_evaluate_can_opt_into_known_good(monkeypatch, tmp_path):
    import os
    monkeypatch.setenv("KNOWN_GOOD_HASHES_PATH", "kg.csv")
    seen = []

    def fake(path, **kw):
        seen.append(os.environ.get("KNOWN_GOOD_HASHES_PATH"))
        return _fake_analyze_factory({"ben1": "benign"})(path, **kw)

    evaluate([LabeledSample(path="ben1", label="benign")], analyze_fn=fake, with_known_good=True)
    assert seen == ["kg.csv"]


def test_known_good_overlap_counts_manifest_hashes_in_allowlist(tmp_path):
    import hashlib
    from malagent.evaluation import known_good_overlap
    a = tmp_path / "a.bin"; a.write_bytes(b"aaa")
    b = tmp_path / "b.bin"; b.write_bytes(b"bbb")
    kg = tmp_path / "kg.csv"
    kg.write_text(hashlib.sha256(b"aaa").hexdigest() + ",a.bin\n")
    samples = [LabeledSample(path=str(a), label="benign"), LabeledSample(path=str(b), label="benign")]
    assert known_good_overlap(samples, str(kg)) == 1
