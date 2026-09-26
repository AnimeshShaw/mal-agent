"""EMBER2024 is trained on PE files; on anything else thrember silently
falls back to byte-histogram/string features. Measured 2026-09-27: 94/117
real benign non-PE files (markdown, Python, PDF, docx, zip, PowerShell,
JS) scored >= 0.15, and `mal-agent analyze docs/SETUP.md` came back
MALICIOUS 0.95 in the default mode. So EMBER may only *decide* for PE
samples; for anything else its score stays visible as evidence, the
decision falls through to the deterministic gate, and the report says
why."""
from __future__ import annotations
from malagent.contracts import AnalysisState, EvidenceRecord, Finding, Provenance, Sample, StageResult
from malagent.reporter import build_verdict, fusion_mode_label


def _state(file_type: str, score: float, fusion_mode: str = "simple") -> AnalysisState:
    sample = Sample(sha256="a" * 64, md5="b" * 32, path="/tmp/x.malz",
                    file_type=file_type, size=10, provenance=Provenance())
    ev = EvidenceRecord(evidence_id="ev_ember", artifact_id="art1",
                        locator="ember:score", excerpt=f"{score:.4f}", trust="tool")
    f = Finding(finding_id="f_ember", claim=f"EMBER2024 classifier: P(malicious)={score:.4f}",
                category="capability", severity="info", confidence=0.5,
                evidence=[ev.evidence_id], grounded=True, source_stage="triage")
    s = AnalysisState(run_id="r1", sample=sample, fusion_mode=fusion_mode)
    s.findings, s.evidence = [f], [ev]
    s.stage_results = [StageResult(stage="triage", status="ok")]
    return s


def test_non_pe_high_ember_score_does_not_convict_in_simple_mode():
    v = build_verdict(_state("unknown", 0.94))
    assert v.verdict != "malicious"


def test_non_pe_low_ember_score_does_not_clear_in_simple_mode():
    v = build_verdict(_state("unknown", 0.001))
    assert v.verdict != "benign"


def test_non_pe_is_not_decided_by_ember_in_cgef_mode_either():
    assert build_verdict(_state("ELF", 0.94, "cgef")).verdict != "malicious"


def test_non_pe_verdict_explains_out_of_distribution():
    v = build_verdict(_state("unknown", 0.94))
    assert any("out-of-distribution" in u for u in v.unresolved)


def test_non_pe_fusion_label_says_ember_was_not_used():
    label = fusion_mode_label(_state("unknown", 0.94))
    assert "not decisive" in label


def test_pe_still_decided_by_ember():
    assert build_verdict(_state("PE", 0.94)).verdict == "malicious"
    assert build_verdict(_state("PE", 0.001)).verdict == "benign"
