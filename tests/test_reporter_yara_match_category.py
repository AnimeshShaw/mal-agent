"""YaraMatchTool's rule-match findings (category='capability', locator
'yara_match:<rule_name>') are a real, independent corroborating signal --
a real match against an operator-supplied third-party rule set is
comparable in strength to IocReputationTool's blocklist match. Mirrors
the exact pattern already established for 'packing'/'ioc_reputation' in
test_reporter_packing_category.py / test_reporter_ioc_reputation_category.py."""
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


def _yara_finding(fid, ev_id, severity="medium"):
    return Finding(finding_id=fid, claim="Matched YARA rule 'evil_rule'.",
                   category="capability", severity=severity, confidence=0.65,
                   evidence=[ev_id], grounded=True)


def _yara_evidence(ev_id, rule_name="evil_rule"):
    return EvidenceRecord(evidence_id=ev_id, artifact_id="art1",
                          locator=f"yara_match:{rule_name}", excerpt=rule_name, trust="tool")


def _state_with(findings, evidence):
    s = AnalysisState(run_id="r1", sample=_sample())
    s.findings = findings
    s.evidence = evidence
    s.stage_results = [StageResult(stage="static", status="ok")]
    return s


def test_yara_match_plus_two_capa_categories_reaches_corroboration():
    yara_f = _yara_finding("f_yara", "ev_yara")
    findings = [yara_f, _capa_finding("f_aa", "ev_aa"), _capa_finding("f_lc", "ev_lc")]
    evidence = [_yara_evidence("ev_yara"), _capa_evidence("ev_aa", "anti-analysis"),
                _capa_evidence("ev_lc", "load-code")]
    state = _state_with(findings, evidence)
    v = build_verdict(state)
    assert v.verdict == "suspicious"


def test_yara_match_alone_with_one_capa_category_is_not_enough():
    yara_f = _yara_finding("f_yara", "ev_yara")
    findings = [yara_f, _capa_finding("f_aa", "ev_aa")]
    evidence = [_yara_evidence("ev_yara"), _capa_evidence("ev_aa", "anti-analysis")]
    state = _state_with(findings, evidence)
    v = build_verdict(state)
    assert v.verdict not in ("suspicious", "malicious")


def test_multiple_yara_matches_still_count_as_one_category_not_several():
    f1 = _yara_finding("f_y1", "ev_y1")
    f2 = _yara_finding("f_y2", "ev_y2")
    findings = [f1, f2]
    evidence = [_yara_evidence("ev_y1", "rule_a"), _yara_evidence("ev_y2", "rule_b")]
    state = _state_with(findings, evidence)
    v = build_verdict(state)
    assert v.verdict not in ("suspicious", "malicious")


def test_info_severity_yara_finding_does_not_count():
    yara_f = _yara_finding("f_yara", "ev_yara", severity="info")
    findings = [yara_f, _capa_finding("f_aa", "ev_aa"), _capa_finding("f_lc", "ev_lc")]
    evidence = [_yara_evidence("ev_yara"), _capa_evidence("ev_aa", "anti-analysis"),
                _capa_evidence("ev_lc", "load-code")]
    state = _state_with(findings, evidence)
    v = build_verdict(state)
    assert v.verdict not in ("suspicious", "malicious")
