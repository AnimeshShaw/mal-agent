"""Phase 3 of the ML classifier plan (docs/ML_CLASSIFIER_PLAN.md): when
EmberClassifierTool's score is present, it becomes the verdict authority
-- binary malicious/benign, no 'undetermined'/'suspicious' middle ground,
since a trained classifier always produces a real number and forcing a
guess without one is what the old deterministic-gate-only path was
built to avoid. The deterministic gate's categories/score still get
computed and still corroborate/explain, but they no longer decide,
matching the explicit architecture decision recorded in the plan doc.

Threshold (0.15) is the real, calibrated value chosen from the actual
score distribution across all 71 real labeled samples in dataset/ (all
benign scores <= 0.0325, all malicious scores >= 0.3707 -- a wide, real
gap, not a guess). See docs/ML_CLASSIFIER_PLAN.md Phase 3 for the full
reasoning and the honest caveat that this gap is measured on a narrow,
71-sample set."""
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


def _known_good_finding():
    ev = EvidenceRecord(evidence_id="ev_kg", artifact_id="art1",
                        locator="known_good:sha256", excerpt="known-good", trust="tool")
    finding = Finding(finding_id="f_kg", claim="Sample matches known-good hash.",
                      category="verdict_factor", severity="info", confidence=0.97,
                      evidence=[ev.evidence_id], grounded=True)
    return finding, ev


def _state_with(findings, evidence):
    s = AnalysisState(run_id="r1", sample=_sample())
    s.findings = findings
    s.evidence = evidence
    s.stage_results = [StageResult(stage="triage", status="ok")]
    return s


def test_high_ember_score_is_malicious_with_zero_capa_categories():
    """The whole point of Phase 3: a real malicious sample that the old
    category-counting gate would have called 'undetermined' (no
    corroborating capa categories at all) must now be called malicious,
    since EMBER's score is real, independent evidence on its own."""
    f, ev = _ember_finding_and_evidence(0.95)
    state = _state_with([f], [ev])
    v = build_verdict(state)
    assert v.verdict == "malicious"
    assert v.confidence > 0.9


def test_low_ember_score_is_benign_even_with_one_weak_capa_category():
    """The exact real-world case this fixes: certutil.exe/schtasks.exe
    scored 'malicious' 0.9 under the old gate despite being genuinely
    benign, because their real, documented functionality spans multiple
    capa categories. EMBER scored both confidently benign
    (0.0009/0.0006, live-verified in docs/ML_CLASSIFIER_PLAN.md) using
    an entirely different, orthogonal feature set -- that must now win."""
    from malagent.contracts import EvidenceRecord as EV, Finding as F
    ember_f, ember_ev = _ember_finding_and_evidence(0.001)
    capa_ev = EV(evidence_id="ev_capa", artifact_id="art1",
                locator="capa:anti-analysis:rule1", excerpt="rule1", trust="tool")
    capa_f = F(finding_id="f_capa", claim="Capability detected: rule1", category="capability",
              severity="medium", confidence=0.7, evidence=["ev_capa"], grounded=True)
    state = _state_with([ember_f, capa_f], [ember_ev, capa_ev])
    v = build_verdict(state)
    assert v.verdict == "benign"


def test_known_good_hash_match_still_overrides_ember():
    """A cryptographic hash match is evidence about THIS EXACT file --
    stronger than any probabilistic classifier's guess. Must still win."""
    kg_f, kg_ev = _known_good_finding()
    ember_f, ember_ev = _ember_finding_and_evidence(0.95)  # would say malicious alone
    state = _state_with([kg_f, ember_f], [kg_ev, ember_ev])
    v = build_verdict(state)
    assert v.verdict == "benign"
    assert v.confidence == 0.97


def test_no_ember_score_falls_back_to_deterministic_gate_undetermined():
    """Graceful degradation, matching every other optional tool in this
    codebase: with no EMBER evidence present at all (not configured,
    thrember/lightgbm not installed, or model file missing), the
    existing deterministic-gate logic -- including 'undetermined' as a
    real, honest outcome -- must be completely unchanged."""
    from malagent.contracts import EvidenceRecord as EV, Finding as F
    capa_ev = EV(evidence_id="ev_capa", artifact_id="art1",
                locator="capa:anti-analysis:rule1", excerpt="rule1", trust="tool")
    capa_f = F(finding_id="f_capa", claim="Capability detected: rule1", category="capability",
              severity="medium", confidence=0.7, evidence=["ev_capa"], grounded=True)
    state = _state_with([capa_f], [capa_ev])
    v = build_verdict(state)
    assert v.verdict == "undetermined"


def test_ember_confidence_reflects_the_real_score_not_a_fixed_constant():
    f1, ev1 = _ember_finding_and_evidence(0.999)
    f2, ev2 = _ember_finding_and_evidence(0.60)
    v1 = build_verdict(_state_with([f1], [ev1]))
    v2 = build_verdict(_state_with([f2], [ev2]))
    assert v1.verdict == v2.verdict == "malicious"
    assert v1.confidence > v2.confidence


def test_malformed_ember_excerpt_falls_back_to_deterministic_gate():
    """Defensive: if the excerpt somehow isn't a parseable float (a
    future bug elsewhere, a corrupted record), this must degrade to the
    existing gate rather than crash build_verdict() -- the single most
    load-bearing function in the whole system."""
    ev = EvidenceRecord(evidence_id="ev_ember", artifact_id="art1",
                        locator="ember:score", excerpt="not-a-number", trust="tool")
    finding = Finding(finding_id="f_ember", claim="broken", category="capability",
                      severity="info", confidence=0.5, evidence=[ev.evidence_id], grounded=True)
    state = _state_with([finding], [ev])
    v = build_verdict(state)
    assert v.verdict == "undetermined"
