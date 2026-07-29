"""M6 sub-task: full-pipeline deterministic-only vs. +LLM ablation.

Distinct from critic_ablation.py (which isolates verifier_critic alone
against synthetic narrative fixtures): this runs the SAME labeled sample
through pipeline.analyze() twice -- once with enable_models=False (pure
deterministic tools) and once with enable_models=True (LLM narrative +
verifier_critic fact-checking enabled) -- and checks the project's core
invariant empirically: reporter.build_verdict()'s label/score must be
IDENTICAL regardless of whether LLMs ran. Any observed difference is a
critical bug (see tests/test_llm_agents_never_score.py for the unit-level
guard), not a calibration nuance, and this harness must flag it loudly."""
from __future__ import annotations
from malagent.contracts import AnalysisState, Finding, Provenance, Sample, StageResult, Verdict
from malagent.evaluation import LabeledSample
from malagent.llm_ablation import (
    LlmAblationReport, SampleAblationResult, format_report, run_llm_ablation,
)


def _sample():
    return Sample(sha256="a" * 64, md5="b" * 32, path="/tmp/x.bin",
                  file_type="PE", size=10, provenance=Provenance())


def _state(narrative_text="", unresolved=None):
    state = AnalysisState(run_id="r", sample=_sample())
    if narrative_text:
        state.findings.append(Finding(
            finding_id="behavioral_1", claim=narrative_text, category="behavior",
            severity="info", confidence=0.5, source_stage="behavioral_analyst", grounded=True))
    state.stage_results.append(StageResult(stage="triage", status="ok",
                                           unresolved=unresolved or []))
    return state


def _verdict(verdict="benign", confidence=0.55):
    return Verdict(sample_sha256="a" * 64, verdict=verdict, confidence=confidence)


def _labeled(path="/tmp/x.bin", label="benign"):
    return LabeledSample(path=path, label=label)


def _make_fake_analyze(det_result, llm_result):
    """det_result/llm_result: (state, verdict) pairs returned depending on
    the enable_models kwarg -- mirrors pipeline.analyze()'s real signature
    and return shape (state, verdict, report_md, report_txt, audit)."""
    def _fake_analyze(path, *, provenance=None, policy=None, enable_models=False,
                      local_model="qwen2.5-coder:7b", escalation_provider=None,
                      escalation_model=None):
        state, verdict = llm_result if enable_models else det_result
        return state, verdict, "md", "txt", object()
    return _fake_analyze


def test_identical_verdicts_across_both_conditions_not_flagged_as_changed():
    det = (_state(), _verdict("benign", 0.55))
    llm = (_state(narrative_text="A rich narrative about this benign tool."), _verdict("benign", 0.55))
    fake_analyze = _make_fake_analyze(det, llm)

    report = run_llm_ablation([_labeled()], analyze_fn=fake_analyze)

    assert report.n == 1
    r = report.results[0]
    assert r.det_verdict == "benign"
    assert r.llm_verdict == "benign"
    assert r.verdict_changed is False
    assert r.confidence_changed is False
    assert report.verdict_changes == []


def test_verdict_label_change_is_detected_and_flagged():
    """This is the critical-bug detector: a real label difference between
    conditions must never be silently swallowed."""
    det = (_state(), _verdict("benign", 0.55))
    llm = (_state(), _verdict("malicious", 0.9))
    fake_analyze = _make_fake_analyze(det, llm)

    report = run_llm_ablation([_labeled()], analyze_fn=fake_analyze)

    r = report.results[0]
    assert r.verdict_changed is True
    assert len(report.verdict_changes) == 1
    text = format_report(report)
    assert "CRITICAL" in text
    assert "1" in text


def test_confidence_change_detected_even_when_label_is_the_same():
    det = (_state(), _verdict("benign", 0.55))
    llm = (_state(), _verdict("benign", 0.80))
    fake_analyze = _make_fake_analyze(det, llm)

    report = run_llm_ablation([_labeled()], analyze_fn=fake_analyze)

    r = report.results[0]
    assert r.verdict_changed is False
    assert r.confidence_changed is True
    assert report.confidence_changes == [r]


def test_narrative_richness_captured_per_sample():
    det = (_state(), _verdict())
    llm = (_state(narrative_text="A" * 120, unresolved=["could not decompile func@0x1000"]),
          _verdict())
    fake_analyze = _make_fake_analyze(det, llm)

    report = run_llm_ablation([_labeled()], analyze_fn=fake_analyze)

    r = report.results[0]
    assert r.det_narrative_chars == 0
    assert r.llm_narrative_chars == 120
    assert r.det_unresolved == 0
    assert r.llm_unresolved == 1


def test_timing_is_recorded_per_condition(monkeypatch):
    det = (_state(), _verdict())
    llm = (_state(), _verdict())
    fake_analyze = _make_fake_analyze(det, llm)

    import malagent.llm_ablation as mod
    ticks = iter([0.0, 1.0, 1.0, 3.5])  # det: 0->1 (1s); llm: 1->3.5 (2.5s)
    monkeypatch.setattr(mod.time, "monotonic", lambda: next(ticks))

    report = run_llm_ablation([_labeled()], analyze_fn=fake_analyze)

    r = report.results[0]
    assert r.det_seconds == 1.0
    assert r.llm_seconds == 2.5
    assert report.total_det_seconds == 1.0
    assert report.total_llm_seconds == 2.5


def test_a_failing_sample_is_recorded_as_an_error_not_a_crash():
    def _raising_analyze(path, **kw):
        raise RuntimeError("capa binary missing")

    report = run_llm_ablation([_labeled()], analyze_fn=_raising_analyze)

    assert report.n == 1
    r = report.results[0]
    assert r.error is not None
    assert "capa binary missing" in r.error
    assert r.verdict_changed is False


def test_report_aggregates_multiple_samples():
    det = (_state(), _verdict("benign", 0.55))
    llm_same = (_state(), _verdict("benign", 0.55))
    llm_diff = (_state(), _verdict("suspicious", 0.5))

    calls = {"n": 0}

    def _fake_analyze(path, *, provenance=None, policy=None, enable_models=False,
                      local_model="qwen2.5-coder:7b", escalation_provider=None,
                      escalation_model=None):
        if not enable_models:
            return det[0], det[1], "md", "txt", object()
        calls["n"] += 1
        state, verdict = llm_diff if calls["n"] == 1 else llm_same
        return state, verdict, "md", "txt", object()

    report = run_llm_ablation(
        [_labeled("/tmp/a.bin"), _labeled("/tmp/b.bin")], analyze_fn=_fake_analyze)

    assert report.n == 2
    assert len(report.verdict_changes) == 1


def test_format_report_reports_zero_changes_cleanly_when_invariant_holds():
    det = (_state(), _verdict("benign", 0.55))
    llm = (_state(), _verdict("benign", 0.55))
    fake_analyze = _make_fake_analyze(det, llm)

    report = run_llm_ablation([_labeled()], analyze_fn=fake_analyze)
    text = format_report(report)

    assert "CRITICAL" not in text
    assert "0" in text
    assert "Samples evaluated: 1" in text


def test_ablation_report_dataclasses_are_importable():
    assert LlmAblationReport is not None
    assert SampleAblationResult is not None
