"""build_verdict must populate Verdict.yara_rules from grounded literal
evidence (M4), not leave the field always empty."""
from __future__ import annotations
from malagent.contracts import AnalysisState, EvidenceRecord, Finding
from malagent.reporter import build_verdict
from tests.test_escalation import _sample


def test_build_verdict_populates_yara_rules_from_grounded_evidence():
    state = AnalysisState(run_id="r1", sample=_sample())
    ev = EvidenceRecord(evidence_id="ev1", artifact_id="art1",
                        locator="string:powershell", excerpt="powershell", trust="tool")
    f = Finding(finding_id="f1", claim="x", category="capability", severity="low",
                confidence=0.6, evidence=["ev1"], grounded=True)
    state.evidence = [ev]
    state.findings = [f]
    verdict = build_verdict(state)
    assert len(verdict.yara_rules) == 1
    assert "powershell" in verdict.yara_rules[0]


def test_build_verdict_yara_rules_empty_when_nothing_grounded():
    state = AnalysisState(run_id="r1", sample=_sample())
    verdict = build_verdict(state)
    assert verdict.yara_rules == []
