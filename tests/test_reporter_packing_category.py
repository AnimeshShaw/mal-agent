"""The corroboration gate originally only counted capa namespace evidence
toward its 'distinct categories' requirement -- but PEHeaderTool/
StaticFeaturesTool's own entropy/overlay findings are a real, independent
signal (packing/obfuscation) that a human analyst would absolutely weigh
alongside capa's capability detections. A real AgentTesla sample
(live-verified during M6 evaluation) had high file entropy + a high-entropy
.text section + only 2 distinct high-signal capa categories -- landing in
'undetermined' even though the packing signal was, in effect, a third
independent category the gate wasn't counting. Entropy and overlay findings
both indicate the same underlying phenomenon (the file is packed/hiding
data), so they count as ONE 'packing' category, not one each -- otherwise a
single packed sample could inflate the category count on its own."""
from __future__ import annotations
from malagent.contracts import (AnalysisState, EvidenceRecord, Finding, Provenance, RawArtifact,
                                Sample, StageResult)
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


def _packing_finding(fid, ev_id, locator, severity="medium"):
    finding = Finding(finding_id=fid, claim="High entropy suggests packing.", category="capability",
                      severity=severity, confidence=0.6, evidence=[ev_id], grounded=True)
    evidence = EvidenceRecord(evidence_id=ev_id, artifact_id="art1", locator=locator,
                              excerpt="7.9", trust="tool")
    return finding, evidence


def _state_with(findings, evidence, deep_ran=True):
    s = AnalysisState(run_id="r1", sample=_sample())
    s.findings = findings
    s.evidence = evidence
    if deep_ran:
        # A real artifact, not a bare "ok" status: deep_ran requires
        # genuine deterministic tool output (see test_reporter_deep_ran.py),
        # not just an LLM-narrated static stage reporting "ok".
        art = RawArtifact(artifact_id="art_ghidra", tool="ghidra", input_ref="a" * 64,
                          storage_ref="artifact://art_ghidra")
        s.stage_results = [StageResult(stage="static", status="ok", artifacts=[art])]
    return s


def test_packing_plus_two_capa_categories_reaches_corroboration():
    """The exact real-world shape found live: entropy/packing signal +
    2 distinct capa categories = 3 total corroborating categories."""
    packing_f, packing_ev = _packing_finding("f_pack", "ev_pack", "file:entropy")
    findings = [
        packing_f,
        _capa_finding("f_aa", "ev_aa"),
        _capa_finding("f_lc", "ev_lc"),
    ]
    evidence = [packing_ev, _capa_evidence("ev_aa", "anti-analysis"),
                _capa_evidence("ev_lc", "load-code")]
    state = _state_with(findings, evidence)
    v = build_verdict(state)
    assert v.verdict == "suspicious"


def test_packing_alone_with_one_capa_category_is_not_enough():
    packing_f, packing_ev = _packing_finding("f_pack", "ev_pack", "file:entropy")
    findings = [packing_f, _capa_finding("f_aa", "ev_aa")]
    evidence = [packing_ev, _capa_evidence("ev_aa", "anti-analysis")]
    state = _state_with(findings, evidence)
    v = build_verdict(state)
    assert v.verdict not in ("suspicious", "malicious")


def test_overlay_evidence_also_counts_as_packing_category():
    packing_f, packing_ev = _packing_finding("f_ov", "ev_ov", "overlay:size")
    findings = [packing_f, _capa_finding("f_aa", "ev_aa"), _capa_finding("f_lc", "ev_lc")]
    evidence = [packing_ev, _capa_evidence("ev_aa", "anti-analysis"),
                _capa_evidence("ev_lc", "load-code")]
    state = _state_with(findings, evidence)
    v = build_verdict(state)
    assert v.verdict == "suspicious"


def test_section_entropy_locator_also_counts_as_packing_category():
    packing_f, packing_ev = _packing_finding("f_sec", "ev_sec", "section:.text:entropy")
    findings = [packing_f, _capa_finding("f_aa", "ev_aa"), _capa_finding("f_lc", "ev_lc")]
    evidence = [packing_ev, _capa_evidence("ev_aa", "anti-analysis"),
                _capa_evidence("ev_lc", "load-code")]
    state = _state_with(findings, evidence)
    v = build_verdict(state)
    assert v.verdict == "suspicious"


def test_multiple_packing_signals_still_count_as_one_category_not_several():
    """File entropy + section entropy + overlay all firing together must
    not, by themselves, satisfy a 3-category requirement -- they're the
    same underlying 'this file is packed' signal, not three independent
    corroborating behaviors."""
    file_f, file_ev = _packing_finding("f_file", "ev_file", "file:entropy")
    sec_f, sec_ev = _packing_finding("f_sec", "ev_sec", "section:.text:entropy")
    ov_f, ov_ev = _packing_finding("f_ov", "ev_ov", "overlay:size")
    findings = [file_f, sec_f, ov_f]
    evidence = [file_ev, sec_ev, ov_ev]
    state = _state_with(findings, evidence)
    v = build_verdict(state)
    assert v.verdict not in ("suspicious", "malicious")


def test_die_packer_detection_also_counts_as_packing_category():
    """DieTool's packer/protector detection (docs/TODO.md Phase 2) is a
    DIFFERENT signal source but the SAME underlying phenomenon as entropy/
    overlay-based packing detection -- must join the existing 'packing'
    category, not create an independent one (else a single packed file
    could inflate corroboration just by having 2 tools detect the same
    fact)."""
    die_f, die_ev = _packing_finding("f_die", "ev_die", "die:packer")
    findings = [die_f, _capa_finding("f_aa", "ev_aa"), _capa_finding("f_lc", "ev_lc")]
    evidence = [die_ev, _capa_evidence("ev_aa", "anti-analysis"),
                _capa_evidence("ev_lc", "load-code")]
    state = _state_with(findings, evidence)
    v = build_verdict(state)
    assert v.verdict == "suspicious"


def test_die_packer_plus_entropy_signal_still_count_as_one_category():
    die_f, die_ev = _packing_finding("f_die", "ev_die", "die:packer")
    entropy_f, entropy_ev = _packing_finding("f_ent", "ev_ent", "file:entropy")
    findings = [die_f, entropy_f]
    evidence = [die_ev, entropy_ev]
    state = _state_with(findings, evidence)
    v = build_verdict(state)
    assert v.verdict not in ("suspicious", "malicious")


def test_info_severity_packing_finding_does_not_count():
    """Mirrors the existing capa-demotion-respecting test: only medium+
    severity packing findings count, same trust-the-severity-decision rule
    as capa evidence."""
    packing_f, packing_ev = _packing_finding("f_pack", "ev_pack", "file:entropy", severity="info")
    findings = [packing_f, _capa_finding("f_aa", "ev_aa"), _capa_finding("f_lc", "ev_lc")]
    evidence = [packing_ev, _capa_evidence("ev_aa", "anti-analysis"),
                _capa_evidence("ev_lc", "load-code")]
    state = _state_with(findings, evidence)
    v = build_verdict(state)
    assert v.verdict not in ("suspicious", "malicious")
