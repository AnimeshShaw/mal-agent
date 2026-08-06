"""build_tool_report(): a JSON-serializable equivalent of
render_tool_narrative()'s canonical per-tool accounting, for the web UI
(docs/TODO.md Phase 8) to render its own ToolCard components against.
Deliberately reuses the exact same helpers (_finding_indication,
_finding_direction, TOOL_DESCRIPTIONS, is_known_good_match) as the text
report, so the web UI can never drift from what report.txt says -- the
Python side stays the single source of truth for "what does this finding
indicate and which way does it lean," not duplicated in TypeScript."""
from __future__ import annotations
from malagent.contracts import AnalysisState, EvidenceRecord, Finding, Provenance, Sample, StageResult
from malagent.reporter import TOOL_DESCRIPTIONS, build_tool_report


def _sample():
    return Sample(sha256="a" * 64, md5="b" * 32, path="/tmp/x.malz",
                  file_type="PE", size=10, provenance=Provenance())


def _state():
    return AnalysisState(run_id="r1", sample=_sample())


def test_every_canonical_tool_is_present_in_order():
    state = _state()
    report = build_tool_report(state)
    assert [entry["tool"] for entry in report] == list(TOOL_DESCRIPTIONS.keys())


def test_tool_with_no_stage_result_is_marked_skipped_with_a_reason():
    state = _state()
    report = build_tool_report(state)
    capa_entry = next(e for e in report if e["tool"] == "capa")
    assert capa_entry["status"] == "skipped"
    assert capa_entry["reason"]
    assert capa_entry["findings"] == []


def test_tool_with_a_real_stage_result_carries_its_findings_with_direction():
    ev = EvidenceRecord(evidence_id="ev1", artifact_id="art1",
                        locator="capa:anti-analysis:rule1", excerpt="rule1", trust="tool")
    f = Finding(finding_id="f1", claim="Capability detected: rule1", category="capability",
               severity="medium", confidence=0.7, evidence=["ev1"], grounded=True)
    state = _state()
    state.evidence = [ev]
    state.findings = [f]
    state.stage_results = [StageResult(stage="triage", status="ok", tool="capa",
                                       findings=[f], evidence=[ev])]
    report = build_tool_report(state)
    capa_entry = next(e for e in report if e["tool"] == "capa")
    assert capa_entry["status"] == "ok"
    assert len(capa_entry["findings"]) == 1
    finding_entry = capa_entry["findings"][0]
    assert finding_entry["claim"] == "Capability detected: rule1"
    assert finding_entry["severity"] == "medium"
    assert finding_entry["direction"] == "supports_malicious"
    assert "indicates" in finding_entry and finding_entry["indicates"]


def test_known_good_match_marks_other_tools_skipped_with_known_good_reason():
    kg_ev = EvidenceRecord(evidence_id="ev_kg", artifact_id="art1",
                          locator="known_good:sha256", excerpt="kg", trust="tool")
    kg_f = Finding(finding_id="f_kg", claim="known good", category="verdict_factor",
                  severity="info", confidence=0.97, evidence=[kg_ev.evidence_id], grounded=True)
    state = _state()
    state.evidence = [kg_ev]
    state.findings = [kg_f]
    state.stage_results = [StageResult(stage="triage", status="ok", tool="known_good",
                                       findings=[kg_f], evidence=[kg_ev])]
    report = build_tool_report(state)
    capa_entry = next(e for e in report if e["tool"] == "capa")
    assert capa_entry["status"] == "skipped"
    assert "known-good" in capa_entry["reason"].lower()


def test_output_is_json_serializable():
    import json
    ev = EvidenceRecord(evidence_id="ev1", artifact_id="art1", locator="ember:score",
                        excerpt="0.9", trust="tool")
    f = Finding(finding_id="f1", claim="EMBER score", category="capability",
               severity="info", confidence=0.5, evidence=["ev1"], grounded=True)
    state = _state()
    state.evidence = [ev]
    state.findings = [f]
    state.stage_results = [StageResult(stage="triage", status="ok", tool="ember_classifier",
                                       findings=[f], evidence=[ev])]
    report = build_tool_report(state)
    json.dumps(report)  # must not raise
