"""UnpackerTool's findings (category='capability', locator
'unpacker:contains:<path>') are a real, independent corroborating signal --
a risky-import payload recovered from inside a container, or a suspicious
nested-container pattern (ZIP wrapping an ISO wrapping an executable), is
evidence a human analyst would weigh alongside capa's capability
detections. Mirrors the exact pattern already established for
'packing'/'ioc_reputation'/'yara_match' in the sibling
test_reporter_*_category.py files."""
from __future__ import annotations
from malagent.contracts import AnalysisState, EvidenceRecord, Finding, Provenance, Sample, StageResult
from malagent.reporter import build_verdict


def _sample():
    return Sample(sha256="a" * 64, md5="b" * 32, path="/tmp/x.malz",
                  file_type="PE", size=10, provenance=Provenance())


def _capa_finding(fid, ev_id, severity="medium"):
    return Finding(finding_id=fid, claim=f"Capability detected: {fid}", category="capability",
                   severity=severity, confidence=0.7, evidence=[ev_id], grounded=True)


def _capa_evidence(ev_id, namespace):
    return EvidenceRecord(evidence_id=ev_id, artifact_id="art1",
                          locator=f"capa:{namespace}:{ev_id}", excerpt=ev_id, trust="tool")


def _unpacker_finding(fid, ev_id, severity="medium"):
    return Finding(finding_id=fid, claim="Extracted payload imports CreateRemoteThread.",
                   category="capability", severity=severity, confidence=0.6,
                   evidence=[ev_id], grounded=True)


def _unpacker_evidence(ev_id, path="payload.exe"):
    return EvidenceRecord(evidence_id=ev_id, artifact_id="art1",
                          locator=f"unpacker:contains:{path}", excerpt=path, trust="tool")


def _state_with(findings, evidence):
    s = AnalysisState(run_id="r1", sample=_sample())
    s.findings = findings
    s.evidence = evidence
    s.stage_results = [StageResult(stage="static", status="ok")]
    return s


def test_unpacker_finding_plus_two_capa_categories_reaches_corroboration():
    u_f = _unpacker_finding("f_unpack", "ev_unpack")
    findings = [u_f, _capa_finding("f_aa", "ev_aa"), _capa_finding("f_lc", "ev_lc")]
    evidence = [_unpacker_evidence("ev_unpack"), _capa_evidence("ev_aa", "anti-analysis"),
                _capa_evidence("ev_lc", "load-code")]
    state = _state_with(findings, evidence)
    v = build_verdict(state)
    assert v.verdict == "suspicious"


def test_unpacker_finding_alone_with_one_capa_category_is_not_enough():
    u_f = _unpacker_finding("f_unpack", "ev_unpack")
    findings = [u_f, _capa_finding("f_aa", "ev_aa")]
    evidence = [_unpacker_evidence("ev_unpack"), _capa_evidence("ev_aa", "anti-analysis")]
    state = _state_with(findings, evidence)
    v = build_verdict(state)
    assert v.verdict not in ("suspicious", "malicious")


def test_multiple_unpacker_findings_still_count_as_one_category_not_several():
    f1 = _unpacker_finding("f_u1", "ev_u1")
    f2 = _unpacker_finding("f_u2", "ev_u2")
    findings = [f1, f2]
    evidence = [_unpacker_evidence("ev_u1", "payload.exe"), _unpacker_evidence("ev_u2", "nested.iso/payload.exe")]
    state = _state_with(findings, evidence)
    v = build_verdict(state)
    assert v.verdict not in ("suspicious", "malicious")


def test_info_severity_unpacker_finding_does_not_count():
    u_f = _unpacker_finding("f_unpack", "ev_unpack", severity="info")
    findings = [u_f, _capa_finding("f_aa", "ev_aa"), _capa_finding("f_lc", "ev_lc")]
    evidence = [_unpacker_evidence("ev_unpack"), _capa_evidence("ev_aa", "anti-analysis"),
                _capa_evidence("ev_lc", "load-code")]
    state = _state_with(findings, evidence)
    v = build_verdict(state)
    assert v.verdict not in ("suspicious", "malicious")
