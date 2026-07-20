"""M6 evaluation harness: runs analyze() over a labeled benign/malicious
sample set and reports precision/recall/F1 -- with 'undetermined' verdicts
tracked as honest abstention, never silently folded into benign or
malicious. Folding an abstention either way would misrepresent this
project's own central design principle (report where you can't tell,
don't guess), so the harness reports abstention rates separately instead
of hiding them inside the confusion matrix."""
from __future__ import annotations
from malagent import evaluation
from malagent.evaluation import EvaluationReport, LabeledSample, evaluate, format_report, load_labeled_samples


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
        return (None, v, "", "", None)
    return _fake_analyze


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
