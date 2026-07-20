"""build_verdict must short-circuit to a high-confidence 'benign' when a
known-good hash match is present, bypassing the normal heuristic scoring
entirely -- a cryptographic hash match to a trusted reference is a
categorically stronger signal than capability-based scoring, and even a
sample with other (weaker) suspicious findings shouldn't out-vote it."""
from __future__ import annotations
from malagent.contracts import AnalysisState, EvidenceRecord, Finding, Provenance, Sample, StageResult
from malagent.reporter import build_verdict


def _sample():
    return Sample(sha256="a" * 64, md5="b" * 32, path="/tmp/x.malz",
                  file_type="PE", size=10, provenance=Provenance())


def _known_good_finding():
    return Finding(finding_id="kg1", claim="Sample SHA256 matches a known-good reference hash.",
                   category="verdict_factor", severity="info", confidence=0.97,
                   evidence=["ev_kg"], grounded=True)


def _known_good_evidence():
    return EvidenceRecord(evidence_id="ev_kg", artifact_id="art1",
                          locator="known_good:sha256", excerpt="a" * 64, trust="tool")


def test_known_good_match_short_circuits_to_high_confidence_benign():
    state = AnalysisState(run_id="r1", sample=_sample())
    state.findings = [_known_good_finding()]
    state.evidence = [_known_good_evidence()]
    v = build_verdict(state)
    assert v.verdict == "benign"
    assert v.confidence >= 0.9


def test_known_good_match_outweighs_other_capability_findings():
    """Even with other (weaker, non-corroborated) suspicious findings
    present, a known-good hash match wins -- it's evidence about the exact
    file, not a heuristic inference from its capabilities."""
    other = Finding(finding_id="f1", claim="Capability detected: something",
                    category="capability", severity="medium", confidence=0.7,
                    evidence=["ev1"], grounded=True)
    ev_other = EvidenceRecord(evidence_id="ev1", artifact_id="art1",
                              locator="capa:anti-analysis:something", excerpt="x", trust="tool")
    state = AnalysisState(run_id="r1", sample=_sample())
    state.findings = [_known_good_finding(), other]
    state.evidence = [_known_good_evidence(), ev_other]
    v = build_verdict(state)
    assert v.verdict == "benign"
