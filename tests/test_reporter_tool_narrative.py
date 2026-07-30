"""Verbose per-tool narrative (requested directly: every tool's output
written out in detail -- what it is, why it's there, what it suggests --
without making the decision for the analyst reading it). Distinct from
the existing Appendix A/E (bare findings list / stage status trace):
this groups by TOOL (StageResult.tool), adds a static what/why
description per tool, and an honest, generic "what this indicates"
annotation per finding based on real facts about how the corroboration
gate actually treats it -- never a fabricated per-finding explanation,
and never a verdict word ("malicious"/"benign") in the indication text
itself."""
from __future__ import annotations
from malagent.contracts import AnalysisState, EvidenceRecord, Finding, Provenance, Sample, StageResult
from malagent.reporter import render_tool_narrative


def _sample():
    return Sample(sha256="a" * 64, md5="b" * 32, path="/tmp/x.malz",
                  file_type="PE", size=10, provenance=Provenance())


def _state():
    return AnalysisState(run_id="r1", sample=_sample())


def test_known_tool_description_is_included():
    state = _state()
    state.stage_results = [StageResult(stage="triage", status="ok", tool="capa",
                                       notes="capa rules matched=0")]
    text = render_tool_narrative(state)
    assert "capa" in text.lower()
    assert "att&ck" in text.lower() or "capability" in text.lower()


def test_medium_severity_corroborating_finding_gets_indication_not_verdict():
    ev = EvidenceRecord(evidence_id="ev1", artifact_id="art1",
                        locator="capa:anti-analysis:rule1", excerpt="rule1", trust="tool")
    f = Finding(finding_id="f1", claim="Capability detected: rule1", category="capability",
               severity="medium", confidence=0.7, evidence=["ev1"], grounded=True,
               source_stage="triage")
    state = _state()
    state.evidence = [ev]
    state.findings = [f]
    state.stage_results = [StageResult(stage="triage", status="ok", tool="capa",
                                       findings=[f], evidence=[ev])]
    text = render_tool_narrative(state)
    assert "rule1" in text
    assert "corroborat" in text.lower()
    assert "malicious" not in text.lower() and "benign" not in text.lower()


def test_info_severity_finding_marked_as_context_only():
    ev = EvidenceRecord(evidence_id="ev1", artifact_id="art1",
                        locator="ember:score", excerpt="0.9", trust="tool")
    f = Finding(finding_id="f1", claim="EMBER2024 classifier: P(malicious)=0.9",
               category="capability", severity="info", confidence=0.5,
               evidence=["ev1"], grounded=True, source_stage="triage")
    state = _state()
    state.evidence = [ev]
    state.findings = [f]
    state.stage_results = [StageResult(stage="triage", status="ok", tool="ember_classifier",
                                       findings=[f], evidence=[ev])]
    text = render_tool_narrative(state)
    assert "informational" in text.lower() or "context" in text.lower()


def test_skipped_tool_shows_status_and_reason_honestly():
    state = _state()
    state.stage_results = [StageResult(stage="triage", status="skipped", tool="virustotal",
                                       unresolved=["VIRUSTOTAL_API_KEY not set."])]
    text = render_tool_narrative(state)
    assert "skipped" in text.lower()
    assert "VIRUSTOTAL_API_KEY" in text


def test_unknown_tool_name_does_not_crash():
    state = _state()
    state.stage_results = [StageResult(stage="triage", status="ok", tool="some_future_tool")]
    text = render_tool_narrative(state)
    assert "some_future_tool" in text


def test_tool_with_no_findings_says_nothing_relevant_found():
    state = _state()
    state.stage_results = [StageResult(stage="triage", status="ok", tool="die",
                                       notes="no packer detected")]
    text = render_tool_narrative(state)
    assert "die" in text.lower()
    assert "no relevant" in text.lower() or "nothing" in text.lower() or "no findings" in text.lower()
