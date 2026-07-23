"""IocReputationTool's blocklist-match findings (category='ioc', locator
'ioc_reputation:<type>') are a real, independent corroborating signal --
a capability match plus a genuine "this sample talks to a known-bad IP/
domain" hit is stronger evidence than two capability matches alone.
Mirrors the exact pattern already established for the 'packing' category
in test_reporter_packing_category.py: extend _high_signal_categories()
with a new synthetic category rather than trying to shoehorn IOC hits
into the capa-namespace bucket."""
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


def _ioc_finding(fid, ev_id, severity="medium"):
    return Finding(finding_id=fid, claim="IP indicator matches a local blocklist entry.",
                   category="ioc", severity=severity, confidence=0.7, evidence=[ev_id],
                   grounded=True)


def _ioc_evidence(ev_id, ioc_type="ip"):
    return EvidenceRecord(evidence_id=ev_id, artifact_id="art1",
                          locator=f"ioc_reputation:{ioc_type}", excerpt="1.2.3.4", trust="tool")


def _state_with(findings, evidence):
    s = AnalysisState(run_id="r1", sample=_sample())
    s.findings = findings
    s.evidence = evidence
    s.stage_results = [StageResult(stage="static", status="ok")]
    return s


def test_ioc_match_plus_two_capa_categories_reaches_corroboration():
    ioc_f = _ioc_finding("f_ioc", "ev_ioc")
    findings = [ioc_f, _capa_finding("f_aa", "ev_aa"), _capa_finding("f_lc", "ev_lc")]
    evidence = [_ioc_evidence("ev_ioc"), _capa_evidence("ev_aa", "anti-analysis"),
                _capa_evidence("ev_lc", "load-code")]
    state = _state_with(findings, evidence)
    v = build_verdict(state)
    assert v.verdict == "suspicious"


def test_ioc_match_alone_with_one_capa_category_is_not_enough():
    ioc_f = _ioc_finding("f_ioc", "ev_ioc")
    findings = [ioc_f, _capa_finding("f_aa", "ev_aa")]
    evidence = [_ioc_evidence("ev_ioc"), _capa_evidence("ev_aa", "anti-analysis")]
    state = _state_with(findings, evidence)
    v = build_verdict(state)
    assert v.verdict not in ("suspicious", "malicious")


def test_domain_ioc_type_also_counts():
    ioc_f = _ioc_finding("f_ioc", "ev_ioc")
    findings = [ioc_f, _capa_finding("f_aa", "ev_aa"), _capa_finding("f_lc", "ev_lc")]
    evidence = [_ioc_evidence("ev_ioc", ioc_type="domain"), _capa_evidence("ev_aa", "anti-analysis"),
                _capa_evidence("ev_lc", "load-code")]
    state = _state_with(findings, evidence)
    v = build_verdict(state)
    assert v.verdict == "suspicious"


def test_multiple_ioc_matches_still_count_as_one_category_not_several():
    ip_f = _ioc_finding("f_ip", "ev_ip")
    domain_f = _ioc_finding("f_dom", "ev_dom")
    findings = [ip_f, domain_f]
    evidence = [_ioc_evidence("ev_ip", "ip"), _ioc_evidence("ev_dom", "domain")]
    state = _state_with(findings, evidence)
    v = build_verdict(state)
    assert v.verdict not in ("suspicious", "malicious")


def test_info_severity_ioc_finding_does_not_count():
    ioc_f = _ioc_finding("f_ioc", "ev_ioc", severity="info")
    findings = [ioc_f, _capa_finding("f_aa", "ev_aa"), _capa_finding("f_lc", "ev_lc")]
    evidence = [_ioc_evidence("ev_ioc"), _capa_evidence("ev_aa", "anti-analysis"),
                _capa_evidence("ev_lc", "load-code")]
    state = _state_with(findings, evidence)
    v = build_verdict(state)
    assert v.verdict not in ("suspicious", "malicious")
