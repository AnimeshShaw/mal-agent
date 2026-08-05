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
    """The Indicates: line itself must never state a verdict word -- that
    invariant still holds. A separate, explicitly-labeled Direction: line
    (added so a reader can see which way a finding leans even though, in
    simple mode, it doesn't itself decide anything) is expected to use
    "malicious"/"benign" as its own honest content, and is checked
    separately below rather than conflated with the indication text."""
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
    indicates_line = next(line for line in text.splitlines() if line.strip().startswith("Indicates:"))
    assert "malicious" not in indicates_line.lower() and "benign" not in indicates_line.lower()
    assert "direction: supports malicious" in text.lower()


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


def test_every_canonical_tool_appears_even_with_no_stage_results_at_all():
    """A known-good hash match short-circuits triage_agent right after
    KnownGoodTool -- the other 11 triage tools never produce a
    StageResult at all. Every one of them must still appear, honestly
    marked skipped with a real reason, not silently vanish."""
    from malagent.reporter import TOOL_DESCRIPTIONS

    state = _state()
    kg_ev = EvidenceRecord(evidence_id="ev_kg", artifact_id="art1",
                          locator="known_good:sha256", excerpt="kg", trust="tool")
    kg_f = Finding(finding_id="f_kg", claim="known good", category="verdict_factor",
                  severity="info", confidence=0.97, evidence=[kg_ev.evidence_id], grounded=True)
    state.evidence = [kg_ev]
    state.findings = [kg_f]
    state.stage_results = [StageResult(stage="triage", status="ok", tool="known_good",
                                       findings=[kg_f], evidence=[kg_ev])]
    text = render_tool_narrative(state)
    for tool_name in TOOL_DESCRIPTIONS:
        assert tool_name in text, f"{tool_name} missing from report entirely"
    assert "known-good" in text.lower()
    assert text.count("Status:  skipped") >= len(TOOL_DESCRIPTIONS) - 1


def test_finding_direction_badge_present_for_malicious_leaning_finding():
    ev = EvidenceRecord(evidence_id="ev1", artifact_id="art1",
                        locator="capa:anti-analysis:rule1", excerpt="rule1", trust="tool")
    f = Finding(finding_id="f1", claim="Capability detected: rule1", category="capability",
               severity="medium", confidence=0.7, evidence=["ev1"], grounded=True)
    state = _state()
    state.evidence = [ev]
    state.findings = [f]
    state.stage_results = [StageResult(stage="triage", status="ok", tool="capa",
                                       findings=[f], evidence=[ev])]
    text = render_tool_narrative(state)
    assert "direction: supports malicious" in text.lower()
