"""render_txt is the mandatory, unabridged detailed report -- every
finding, every evidence excerpt, the full audit log -- on every run, never
gated behind --out. Unlike report.md (which caps key_findings at 25 and
doesn't include raw evidence text), nothing here is truncated."""
from __future__ import annotations
from malagent.audit import AuditLog
from malagent.contracts import AnalysisState, EvidenceRecord, Finding, Provenance, Sample, Verdict
from malagent.reporter import render_txt


def _sample():
    return Sample(sha256="a" * 64, md5="b" * 32, path="/tmp/x.malz",
                  file_type="PE", size=10, provenance=Provenance())


def test_includes_all_major_sections():
    state = AnalysisState(run_id="r1", sample=_sample())
    v = Verdict(sample_sha256="a" * 64, verdict="benign", confidence=0.55)
    audit = AuditLog("r1")
    audit.log("test_event", detail="x")
    text = render_txt(state, v, audit, ("Summary text.", "Recommendation text."))
    for heading in ("EXECUTIVE SUMMARY", "VERDICT", "DETAILED FINDINGS NARRATIVE",
                    "RECOMMENDATIONS", "APPENDIX A", "APPENDIX B", "APPENDIX C",
                    "APPENDIX D", "APPENDIX E", "APPENDIX F", "APPENDIX G", "APPENDIX H"):
        assert heading in text
    assert "Summary text." in text
    assert "Recommendation text." in text


def test_fusion_mode_line_shown_in_verdict_section():
    ev = EvidenceRecord(evidence_id="ev1", artifact_id="art1", locator="ember:score",
                        excerpt="0.9", trust="tool")
    f = Finding(finding_id="f1", claim="EMBER2024 classifier score: 0.9000",
               category="capability", severity="info", confidence=0.5,
               evidence=["ev1"], grounded=True)
    state = AnalysisState(run_id="r1", sample=_sample())
    state.findings = [f]
    state.evidence = [ev]
    v = Verdict(sample_sha256="a" * 64, verdict="malicious", confidence=0.9)
    audit = AuditLog("r1")
    text = render_txt(state, v, audit, ("s", "r"))
    assert "Fusion mode:" in text
    assert "simple" in text.lower()


def test_grounded_findings_not_truncated_at_25():
    """report.md caps key_findings at 25; the txt report must not."""
    state = AnalysisState(run_id="r1", sample=_sample())
    state.findings = [
        Finding(finding_id=f"f{i}", claim=f"Finding number {i}", category="capability",
               severity="info", confidence=0.7, evidence=[f"ev{i}"], grounded=True)
        for i in range(40)
    ]
    v = Verdict(sample_sha256="a" * 64, verdict="benign", confidence=0.55)
    audit = AuditLog("r1")
    text = render_txt(state, v, audit, ("s", "r"))
    for i in range(40):
        assert f"Finding number {i}" in text


def test_evidence_excerpts_are_not_truncated():
    state = AnalysisState(run_id="r1", sample=_sample())
    long_excerpt = "x" * 3000
    state.evidence = [EvidenceRecord(evidence_id="ev1", artifact_id="a1", locator="test",
                                     excerpt=long_excerpt, trust="tool")]
    v = Verdict(sample_sha256="a" * 64, verdict="benign", confidence=0.55)
    audit = AuditLog("r1")
    text = render_txt(state, v, audit, ("s", "r"))
    assert long_excerpt in text


def test_audit_log_entries_and_chain_verify_result_included():
    state = AnalysisState(run_id="r1", sample=_sample())
    v = Verdict(sample_sha256="a" * 64, verdict="benign", confidence=0.55)
    audit = AuditLog("r1")
    audit.log("event_one")
    audit.log("event_two")
    text = render_txt(state, v, audit, ("s", "r"))
    assert "chain intact: True" in text
    assert "event_one" in text
    assert "event_two" in text


def test_yara_rules_included_when_present():
    state = AnalysisState(run_id="r1", sample=_sample())
    v = Verdict(sample_sha256="a" * 64, verdict="suspicious", confidence=0.5,
               yara_rules=["rule test_rule { condition: true }"])
    audit = AuditLog("r1")
    text = render_txt(state, v, audit, ("s", "r"))
    assert "rule test_rule" in text


def test_empty_state_still_produces_a_complete_report():
    """Even a bare-minimum state (nothing found, no findings, no evidence)
    must produce a complete, well-formed report -- never crash on empty
    collections."""
    state = AnalysisState(run_id="r1", sample=_sample())
    v = Verdict(sample_sha256="a" * 64, verdict="undetermined", confidence=0.3)
    audit = AuditLog("r1")
    text = render_txt(state, v, audit, ("s", "r"))
    assert "END OF REPORT" in text
