"""Phase 3.6 (docs/ML_CLASSIFIER_PLAN.md §11): "simple" fusion mode --
EMBER alone decides malicious/benign when configured. This is now the
DEFAULT (AnalysisState.fusion_mode == "simple" unless a caller opts into
"cgef"). No gray zone, no "suspicious" middle ground when an EMBER score
is present: a single calibrated threshold (0.15 -- the same value already
validated as the naive-threshold baseline against a genuinely held-out
57-sample set: 45 TP, 0 FP, 12 TN, 0 FN, 0 undetermined) decides outright.
The other triage tools' findings become evidence/explanation only in this
mode -- they must not be able to flip or soften the verdict.

Distinct from tests/test_reporter_ember_fusion.py, which covers the
opt-in "cgef" mode's gray-zone/suspicious behavior -- that file's states
now explicitly set fusion_mode="cgef" so it's unaffected by this default
change."""
from __future__ import annotations
from malagent.contracts import AnalysisState, EvidenceRecord, Finding, Provenance, Sample, StageResult
from malagent.reporter import build_verdict


def _sample():
    return Sample(sha256="a" * 64, md5="b" * 32, path="/tmp/x.malz",
                  file_type="PE", size=10, provenance=Provenance())


def _ember_finding_and_evidence(score: float):
    ev = EvidenceRecord(evidence_id="ev_ember", artifact_id="art1",
                        locator="ember:score", excerpt=f"{score:.4f}", trust="tool")
    finding = Finding(finding_id="f_ember", claim=f"EMBER2024 classifier score: {score:.4f}",
                      category="capability", severity="info", confidence=0.5,
                      evidence=[ev.evidence_id], grounded=True, source_stage="triage")
    return finding, ev


def _capa_finding(fid, ev_id, namespace, severity="medium"):
    return Finding(finding_id=fid, claim=f"Capability detected: {fid}", category="capability",
                   severity=severity, confidence=0.7, evidence=[ev_id], grounded=True)


def _capa_evidence(ev_id, namespace):
    return EvidenceRecord(evidence_id=ev_id, artifact_id="art1",
                          locator=f"capa:{namespace}:{ev_id}", excerpt=ev_id, trust="tool")


def _yara_finding_and_evidence(rule="evil_rule"):
    ev = EvidenceRecord(evidence_id="ev_yara", artifact_id="art1",
                        locator=f"yara_match:{rule}", excerpt=rule, trust="tool")
    finding = Finding(finding_id="f_yara", claim=f"Matched YARA rule '{rule}'.",
                      category="capability", severity="medium", confidence=0.65,
                      evidence=[ev.evidence_id], grounded=True)
    return finding, ev


def _state_with(findings, evidence, fusion_mode=None):
    kwargs = {} if fusion_mode is None else {"fusion_mode": fusion_mode}
    s = AnalysisState(run_id="r1", sample=_sample(), **kwargs)
    s.findings = findings
    s.evidence = evidence
    s.stage_results = [StageResult(stage="triage", status="ok")]
    return s


def test_default_fusion_mode_is_simple():
    s = AnalysisState(run_id="r1", sample=_sample())
    assert s.fusion_mode == "simple"


def test_gray_zone_score_that_would_be_suspicious_under_cgef_is_benign_under_simple():
    """The exact 0.20-score, single-capa-category scenario that
    test_reporter_ember_fusion.py's CGEF test asserts is "suspicious" --
    under the new default, EMBER alone decides, no gray zone, no
    "suspicious" outcome; 0.20 >= 0.15 so it's simply malicious."""
    ember_f, ember_ev = _ember_finding_and_evidence(0.20)
    findings = [ember_f, _capa_finding("f1", "ev1", "anti-analysis")]
    evidence = [ember_ev, _capa_evidence("ev1", "anti-analysis")]
    v = build_verdict(_state_with(findings, evidence))
    assert v.verdict == "malicious"
    assert v.verdict != "suspicious"


def test_score_just_below_threshold_is_benign_regardless_of_corroboration():
    """Even with full 3-category corroboration -- which would convict
    under cgef mode -- simple mode ignores it entirely below threshold."""
    ember_f, ember_ev = _ember_finding_and_evidence(0.10)
    findings = [ember_f,
                _capa_finding("f1", "ev1", "anti-analysis"),
                _capa_finding("f2", "ev2", "collection"),
                _capa_finding("f3", "ev3", "communication")]
    evidence = [ember_ev, _capa_evidence("ev1", "anti-analysis"),
                _capa_evidence("ev2", "collection"), _capa_evidence("ev3", "communication")]
    v = build_verdict(_state_with(findings, evidence))
    assert v.verdict == "benign"


def test_score_just_above_threshold_is_malicious_with_zero_corroboration():
    ember_f, ember_ev = _ember_finding_and_evidence(0.16)
    v = build_verdict(_state_with([ember_f], [ember_ev]))
    assert v.verdict == "malicious"


def test_no_suspicious_outcome_is_ever_produced_when_ember_present():
    """Binary only: sweep a range of scores that would trigger cgef's
    'suspicious' outcome and confirm simple mode never returns it."""
    for score in (0.06, 0.10, 0.15, 0.20, 0.29):
        ember_f, ember_ev = _ember_finding_and_evidence(score)
        findings = [ember_f, _capa_finding("f1", "ev1", "anti-analysis")]
        evidence = [ember_ev, _capa_evidence("ev1", "anti-analysis")]
        v = build_verdict(_state_with(findings, evidence))
        assert v.verdict in ("malicious", "benign"), (score, v.verdict)


def test_confidence_is_near_half_right_at_the_threshold():
    ember_f, ember_ev = _ember_finding_and_evidence(0.15)
    v = build_verdict(_state_with([ember_f], [ember_ev]))
    assert 0.49 <= v.confidence <= 0.55


def test_confidence_rises_toward_high_end_away_from_threshold_on_malicious_side():
    ember_f_near, ember_ev_near = _ember_finding_and_evidence(0.16)
    ember_f_far, ember_ev_far = _ember_finding_and_evidence(0.99)
    v_near = build_verdict(_state_with([ember_f_near], [ember_ev_near]))
    v_far = build_verdict(_state_with([ember_f_far], [ember_ev_far]))
    assert v_far.confidence > v_near.confidence
    assert v_far.confidence <= 0.99


def test_confidence_rises_toward_high_end_away_from_threshold_on_benign_side():
    ember_f_near, ember_ev_near = _ember_finding_and_evidence(0.14)
    ember_f_far, ember_ev_far = _ember_finding_and_evidence(0.001)
    v_near = build_verdict(_state_with([ember_f_near], [ember_ev_near]))
    v_far = build_verdict(_state_with([ember_f_far], [ember_ev_far]))
    assert v_far.confidence > v_near.confidence
    assert v_far.confidence <= 0.99


def test_known_good_still_overrides_in_simple_mode():
    kg_ev = EvidenceRecord(evidence_id="ev_kg", artifact_id="art1",
                          locator="known_good:sha256", excerpt="kg", trust="tool")
    kg_f = Finding(finding_id="f_kg", claim="known good", category="verdict_factor",
                  severity="info", confidence=0.97, evidence=[kg_ev.evidence_id], grounded=True)
    ember_f, ember_ev = _ember_finding_and_evidence(0.99)
    v = build_verdict(_state_with([kg_f, ember_f], [kg_ev, ember_ev]))
    assert v.verdict == "benign"
    assert v.confidence == 0.97


def test_named_threat_intel_override_still_wins_in_simple_mode():
    """A named YARA match must still override a confident-benign EMBER
    score in simple mode -- this override is a deterministic factual
    match, not part of the corroboration-gate voting being removed."""
    ember_f, ember_ev = _ember_finding_and_evidence(0.01)
    yara_f, yara_ev = _yara_finding_and_evidence()
    v = build_verdict(_state_with([ember_f, yara_f], [ember_ev, yara_ev]))
    assert v.verdict == "malicious"


def test_explicit_cgef_mode_still_reachable_via_state_field():
    """Sanity check that the mode is genuinely selectable, not hardcoded --
    the same 0.20/single-category scenario now produces cgef's 'suspicious'
    when fusion_mode='cgef' is set explicitly."""
    ember_f, ember_ev = _ember_finding_and_evidence(0.20)
    findings = [ember_f, _capa_finding("f1", "ev1", "anti-analysis")]
    evidence = [ember_ev, _capa_evidence("ev1", "anti-analysis")]
    v = build_verdict(_state_with(findings, evidence, fusion_mode="cgef"))
    assert v.verdict == "suspicious"
