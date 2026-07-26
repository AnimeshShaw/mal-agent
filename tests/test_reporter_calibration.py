"""Verdict scoring must require corroboration across multiple distinct
high-signal capa namespace categories before calling something suspicious or
malicious -- a pile of matches within just one or two categories (which can
themselves be individually false-positive-prone, e.g. anti-debugging checks
also used by legitimate DRM/licensing code) shouldn't alone convict. This is
what a live run against notepad.exe demonstrated: it hit exactly 2 distinct
high-signal categories (anti-analysis, collection) and scored MALICIOUS at
0.9 confidence under the old scoring. Real malware typically spans more
categories (e.g. a RAT needs load-code + communication + persistence)."""
from __future__ import annotations
from malagent.contracts import (AnalysisState, EvidenceRecord, Finding, Provenance, RawArtifact,
                                Sample, StageResult)
from malagent.reporter import build_verdict


def _sample():
    return Sample(sha256="a" * 64, md5="b" * 32, path="/tmp/x.malz",
                  file_type="PE", size=10, provenance=Provenance())


def _capa_finding(fid, ev_id, namespace, severity):
    return Finding(finding_id=fid, claim=f"Capability detected: {fid}", category="capability",
                   severity=severity, confidence=0.7, evidence=[ev_id], grounded=True)


def _capa_evidence(ev_id, namespace):
    return EvidenceRecord(evidence_id=ev_id, artifact_id="art1",
                          locator=f"capa:{namespace}:{ev_id}", excerpt=ev_id, trust="tool")


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


def test_two_high_signal_categories_alone_do_not_reach_suspicious():
    findings = [
        _capa_finding("f1", "ev1", "anti-analysis", "medium"),
        _capa_finding("f2", "ev2", "collection", "medium"),
    ]
    evidence = [_capa_evidence("ev1", "anti-analysis"), _capa_evidence("ev2", "collection")]
    state = _state_with(findings, evidence)
    v = build_verdict(state)
    assert v.verdict not in ("suspicious", "malicious")


def test_three_distinct_categories_with_moderate_score_is_suspicious():
    findings = [
        _capa_finding("f1", "ev1", "anti-analysis", "medium"),
        _capa_finding("f2", "ev2", "collection", "medium"),
        _capa_finding("f3", "ev3", "load-code", "medium"),
    ]
    evidence = [_capa_evidence("ev1", "anti-analysis"), _capa_evidence("ev2", "collection"),
                _capa_evidence("ev3", "load-code")]
    state = _state_with(findings, evidence)
    v = build_verdict(state)
    assert v.verdict == "suspicious"


def test_three_distinct_categories_with_high_score_is_malicious():
    findings = [
        _capa_finding("f1", "ev1", "anti-analysis", "critical"),
        _capa_finding("f2", "ev2", "collection", "critical"),
        _capa_finding("f3", "ev3", "load-code", "critical"),
    ]
    evidence = [_capa_evidence("ev1", "anti-analysis"), _capa_evidence("ev2", "collection"),
                _capa_evidence("ev3", "load-code")]
    state = _state_with(findings, evidence)
    v = build_verdict(state)
    assert v.verdict == "malicious"


def test_low_signal_finding_in_a_high_signal_namespace_does_not_count():
    """CapaTool itself can demote a rule within a normally-high-signal
    namespace to severity='info' (e.g. load-code/pe structural rules). The
    category-diversity count must trust that decision, not re-derive
    namespace membership independently of severity -- otherwise an 'info'
    finding could still smuggle in a corroborating category."""
    findings = [
        _capa_finding("f1", "ev1", "anti-analysis", "medium"),
        _capa_finding("f2", "ev2", "collection", "medium"),
        Finding(finding_id="f3", claim="x", category="capability", severity="info",
               confidence=0.7, evidence=["ev3"], grounded=True),
    ]
    evidence = [_capa_evidence("ev1", "anti-analysis"), _capa_evidence("ev2", "collection"),
                _capa_evidence("ev3", "load-code")]
    state = _state_with(findings, evidence)
    v = build_verdict(state)
    assert v.verdict not in ("suspicious", "malicious")


def test_zero_high_signal_categories_with_coverage_is_benign():
    findings = [
        Finding(finding_id="f1", claim="x", category="capability", severity="info",
               confidence=0.7, evidence=["ev1"], grounded=True),
    ]
    evidence = [_capa_evidence("ev1", "host-interaction")]
    state = _state_with(findings, evidence)
    v = build_verdict(state)
    assert v.verdict == "benign"


def test_notepad_shaped_case_does_not_reach_suspicious_or_malicious():
    """Reproduces the real live-verified shape: 33 generic (info) capa
    findings plus 2 distinct high-signal-category findings (anti-analysis,
    collection). Must not be suspicious/malicious -- exactly the false
    positive this fix addresses."""
    findings = [Finding(finding_id=f"generic{i}", claim=f"generic {i}", category="capability",
                        severity="info", confidence=0.7, evidence=[f"gev{i}"], grounded=True)
               for i in range(33)]
    evidence = [_capa_evidence(f"gev{i}", "host-interaction") for i in range(33)]
    findings += [
        _capa_finding("f_aa1", "ev_aa1", "anti-analysis", "medium"),
        _capa_finding("f_aa2", "ev_aa2", "anti-analysis", "medium"),
        _capa_finding("f_col", "ev_col", "collection", "medium"),
    ]
    evidence += [_capa_evidence("ev_aa1", "anti-analysis"), _capa_evidence("ev_aa2", "anti-analysis"),
                _capa_evidence("ev_col", "collection")]
    state = _state_with(findings, evidence)
    v = build_verdict(state)
    assert v.verdict not in ("suspicious", "malicious")
