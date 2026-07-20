"""M6 sub-task (V2-DESIGN.md S6): measures whether verifier_critic actually
catches overclaiming, using synthetic (evidence, narrative, ground-truth)
fixtures. Deliberately needs no real malware corpus -- unlike the
benign/malicious evaluation harness, every fixture here is hand-written
with known ground truth about whether the narrative overclaims beyond its
cited evidence."""
from __future__ import annotations
from malagent.critic_ablation import (
    DEFAULT_CASES, AblationCase, AblationReport, format_report, run_ablation,
)


class _FakeResponse:
    def __init__(self, text):
        self.text = text
        self.provider = "fake"
        self.location = "local"


class _ScriptedRouter:
    """Returns canned SUPPORTED/UNSUPPORTED verdicts in order, one per
    analyze() call, so the harness's own TP/FP/TN/FN scoring logic can be
    tested deterministically without a real model."""
    def __init__(self, verdicts_in_order):
        self._verdicts = list(verdicts_in_order)

    def analyze(self, *, system, untrusted_label, untrusted_text, escalate=False,
                artifact_class="derived"):
        return _FakeResponse(self._verdicts.pop(0))


def _case(case_id, overclaims):
    return AblationCase(case_id=case_id, evidence_excerpts=["some evidence text"],
                        narrative="some narrative claim", overclaims=overclaims)


def test_tp_when_critic_correctly_flags_overclaiming():
    cases = [_case("c1", overclaims=True)]
    router = _ScriptedRouter(["UNSUPPORTED: no evidence for this claim"])
    report = run_ablation(cases, router=router)
    assert report.tp == 1
    assert report.fp == report.tn == report.fn == 0


def test_tn_when_critic_correctly_passes_accurate_narrative():
    cases = [_case("c1", overclaims=False)]
    router = _ScriptedRouter(["SUPPORTED"])
    report = run_ablation(cases, router=router)
    assert report.tn == 1
    assert report.tp == report.fp == report.fn == 0


def test_fp_when_critic_wrongly_flags_accurate_narrative():
    cases = [_case("c1", overclaims=False)]
    router = _ScriptedRouter(["UNSUPPORTED: overcautious false alarm"])
    report = run_ablation(cases, router=router)
    assert report.fp == 1
    assert report.tp == report.tn == report.fn == 0


def test_fn_when_critic_misses_real_overclaiming():
    cases = [_case("c1", overclaims=True)]
    router = _ScriptedRouter(["SUPPORTED"])
    report = run_ablation(cases, router=router)
    assert report.fn == 1
    assert report.tp == report.fp == report.tn == 0


def test_precision_recall_f1_computed_correctly():
    report = AblationReport(results=[], tp=3, fp=1, tn=4, fn=2)
    assert report.precision == 0.75
    assert report.recall == 0.6
    assert round(report.f1, 4) == round(2 * 0.75 * 0.6 / (0.75 + 0.6), 4)
    assert report.accuracy == 7 / 10


def test_metrics_handle_zero_denominators():
    report = AblationReport(results=[], tp=0, fp=0, tn=0, fn=0)
    assert report.precision is None
    assert report.recall is None
    assert report.f1 is None
    assert report.accuracy is None


def test_format_report_includes_key_numbers():
    report = AblationReport(results=[], tp=3, fp=1, tn=4, fn=2)
    text = format_report(report)
    assert "precision" in text.lower()
    assert "recall" in text.lower()
    assert "0.75" in text


def test_default_cases_bundle_has_both_classes_represented():
    assert any(c.overclaims for c in DEFAULT_CASES)
    assert any(not c.overclaims for c in DEFAULT_CASES)
    assert len(DEFAULT_CASES) >= 6
    assert len({c.case_id for c in DEFAULT_CASES}) == len(DEFAULT_CASES)
