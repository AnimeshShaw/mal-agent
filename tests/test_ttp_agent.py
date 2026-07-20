"""ttp_agent should resolve ATT&CK technique IDs to human-readable names via
the local reference table (M4) and produce grounded per-technique Findings,
not just aggregate raw IDs into a notes string."""
from __future__ import annotations
from malagent.agents import ttp_agent
from malagent.contracts import AnalysisState, EvidenceRecord, Finding, Provenance, Sample


def _sample():
    return Sample(sha256="a" * 64, md5="b" * 32, path="/tmp/x.malz",
                  file_type="PE", size=10, provenance=Provenance())


def _state(findings, evidence=None):
    s = AnalysisState(run_id="r1", sample=_sample())
    s.findings = findings
    s.evidence = evidence or []
    return s


def test_resolves_known_technique_to_readable_name():
    f = Finding(finding_id="f1", claim="x", category="capability", evidence=["ev1"],
               attack_techniques=["T1055"], source_stage="triage")
    state = _state([f])
    ttp_agent(state)
    ttp_findings = [x for x in state.findings if x.category == "ttp"]
    assert len(ttp_findings) == 1
    assert "T1055" in ttp_findings[0].claim
    assert "Process Injection" in ttp_findings[0].claim
    assert ttp_findings[0].evidence == ["ev1"]
    assert ttp_findings[0].attack_techniques == ["T1055"]


def test_flags_unknown_technique_id_honestly():
    f = Finding(finding_id="f1", claim="x", category="capability", evidence=["ev1"],
               attack_techniques=["T9999"], source_stage="triage")
    state = _state([f])
    ttp_agent(state)
    ttp_sr = next(sr for sr in state.stage_results if sr.stage == "ttp")
    assert any("T9999" in u for u in ttp_sr.unresolved)


def test_merges_evidence_from_multiple_findings_sharing_a_technique():
    f1 = Finding(finding_id="f1", claim="x", category="capability", evidence=["ev1"],
                attack_techniques=["T1055"], source_stage="triage")
    f2 = Finding(finding_id="f2", claim="y", category="capability", evidence=["ev2"],
                attack_techniques=["T1055"], source_stage="triage")
    state = _state([f1, f2])
    ttp_agent(state)
    ttp_findings = [x for x in state.findings if x.category == "ttp"]
    assert len(ttp_findings) == 1
    assert sorted(ttp_findings[0].evidence) == ["ev1", "ev2"]


def test_no_techniques_present_produces_no_ttp_findings():
    f = Finding(finding_id="f1", claim="x", category="capability", evidence=["ev1"],
               source_stage="triage")
    state = _state([f])
    ttp_agent(state)
    assert [x for x in state.findings if x.category == "ttp"] == []
    ttp_sr = next(sr for sr in state.stage_results if sr.stage == "ttp")
    assert ttp_sr.status == "ok"
    assert ttp_sr.unresolved == []


def test_notes_include_readable_names_for_known_techniques():
    f = Finding(finding_id="f1", claim="x", category="capability", evidence=["ev1"],
               attack_techniques=["T1055"], source_stage="triage")
    state = _state([f])
    ttp_agent(state)
    ttp_sr = next(sr for sr in state.stage_results if sr.stage == "ttp")
    assert "T1055 (Process Injection)" in ttp_sr.notes
