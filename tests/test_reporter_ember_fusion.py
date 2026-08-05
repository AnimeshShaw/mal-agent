"""Confidence-Gated Evidence Fusion (docs/ML_CLASSIFIER_PLAN.md §10 --
Phase 3.5). Replaces "EMBER decides alone": EMBER's score is trusted
directly only in the two zones a real 71-sample measurement showed it
separates classes perfectly (<=0.05 benign, >=0.30 malicious -- with
margin around the real observed gap 0.0325-0.3707). In the gray zone
between them, and nowhere else, the deterministic corroboration gate
gets a genuine vote, not just narrative value -- and a named
threat-intel match (YARA rule, high-confidence VirusTotal hit) can
override even a confident EMBER "benign" call, since a specific
signature match is stronger evidence than a generic probability.

Distinct from tests/test_reporter_ember_decision.py, which covers the
simpler Phase 3 behavior (ember score present -> binary decision, no
gray zone) -- those tests must all still pass unchanged, since every
case they cover falls inside one of the two confident zones."""
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


def _vt_finding_and_evidence(malicious_count=10):
    ev = EvidenceRecord(evidence_id="ev_vt", artifact_id="art1",
                        locator="virustotal:detections", excerpt=str(malicious_count), trust="tool")
    finding = Finding(finding_id="f_vt", claim=f"{malicious_count} engines flagged as malicious.",
                      category="capability", severity="high", confidence=0.8,
                      evidence=[ev.evidence_id], grounded=True)
    return finding, ev


def _state_with(findings, evidence):
    # This whole file exercises CGEF (docs/ML_CLASSIFIER_PLAN.md §10), now an
    # opt-in mode -- "simple" (§11) is the default and behaves differently in
    # the gray zone, so every state built here must explicitly opt into cgef.
    s = AnalysisState(run_id="r1", sample=_sample(), fusion_mode="cgef")
    s.findings = findings
    s.evidence = evidence
    s.stage_results = [StageResult(stage="triage", status="ok")]
    return s


def test_gray_zone_score_with_full_corroboration_is_malicious():
    """Score in the real, empirically-unobserved gray zone (0.05-0.30) --
    deterministic evidence reaching the normal >=3-category corroboration
    bar should win outright, since it's stronger than an uncertain
    ML score."""
    ember_f, ember_ev = _ember_finding_and_evidence(0.15)
    findings = [ember_f,
                _capa_finding("f1", "ev1", "anti-analysis"),
                _capa_finding("f2", "ev2", "collection"),
                _capa_finding("f3", "ev3", "communication")]
    evidence = [ember_ev, _capa_evidence("ev1", "anti-analysis"),
                _capa_evidence("ev2", "collection"), _capa_evidence("ev3", "communication")]
    v = build_verdict(_state_with(findings, evidence))
    assert v.verdict == "malicious"


def test_gray_zone_score_with_partial_corroboration_is_suspicious():
    """The one genuinely non-binary outcome CGEF allows: both signals
    lean toward something being wrong (a mid-range EMBER score AND some,
    but not enough, deterministic corroboration), neither strong enough
    alone. Must be rare (only this narrow zone), not the default."""
    ember_f, ember_ev = _ember_finding_and_evidence(0.20)
    findings = [ember_f, _capa_finding("f1", "ev1", "anti-analysis")]
    evidence = [ember_ev, _capa_evidence("ev1", "anti-analysis")]
    v = build_verdict(_state_with(findings, evidence))
    assert v.verdict == "suspicious"


def test_gray_zone_score_with_no_corroboration_is_benign():
    ember_f, ember_ev = _ember_finding_and_evidence(0.10)
    v = build_verdict(_state_with([ember_f], [ember_ev]))
    assert v.verdict == "benign"


def test_yara_match_overrides_confident_benign_ember_score():
    """A specific, named third-party YARA rule match is stronger,
    more specific evidence than a generic low probability -- must win
    even when EMBER is confidently (and, in this synthetic case,
    wrongly) calling the sample benign."""
    ember_f, ember_ev = _ember_finding_and_evidence(0.01)  # deep in the confident-benign zone
    yara_f, yara_ev = _yara_finding_and_evidence()
    v = build_verdict(_state_with([ember_f, yara_f], [ember_ev, yara_ev]))
    assert v.verdict == "malicious"


def test_virustotal_high_severity_overrides_confident_benign_ember_score():
    ember_f, ember_ev = _ember_finding_and_evidence(0.01)
    vt_f, vt_ev = _vt_finding_and_evidence(malicious_count=15)
    v = build_verdict(_state_with([ember_f, vt_f], [ember_ev, vt_ev]))
    assert v.verdict == "malicious"


def test_virustotal_low_severity_does_not_override():
    """Only a HIGH-severity VT result (>=5 engines, per VirusTotalTool's
    own existing severity assignment) is strong enough to override --
    a handful of detections shouldn't override a confident model."""
    ember_f, ember_ev = _ember_finding_and_evidence(0.01)
    ev = EvidenceRecord(evidence_id="ev_vt", artifact_id="art1",
                        locator="virustotal:detections", excerpt="2", trust="tool")
    finding = Finding(finding_id="f_vt", claim="2 engines flagged.", category="capability",
                      severity="medium", confidence=0.6, evidence=[ev.evidence_id], grounded=True)
    v = build_verdict(_state_with([ember_f, finding], [ember_ev, ev]))
    assert v.verdict == "benign"


def test_known_good_still_overrides_yara_and_ember_both():
    """Known-good hash match remains absolute priority -- unchanged from
    Phase 3, still ahead of even the new override mechanism."""
    kg_ev = EvidenceRecord(evidence_id="ev_kg", artifact_id="art1",
                          locator="known_good:sha256", excerpt="kg", trust="tool")
    kg_f = Finding(finding_id="f_kg", claim="known good", category="verdict_factor",
                  severity="info", confidence=0.97, evidence=[kg_ev.evidence_id], grounded=True)
    ember_f, ember_ev = _ember_finding_and_evidence(0.9)
    yara_f, yara_ev = _yara_finding_and_evidence()
    v = build_verdict(_state_with([kg_f, ember_f, yara_f], [kg_ev, ember_ev, yara_ev]))
    assert v.verdict == "benign"
    assert v.confidence == 0.97


def test_confident_malicious_zone_still_wins_without_any_override_needed():
    ember_f, ember_ev = _ember_finding_and_evidence(0.9995)
    v = build_verdict(_state_with([ember_f], [ember_ev]))
    assert v.verdict == "malicious"
