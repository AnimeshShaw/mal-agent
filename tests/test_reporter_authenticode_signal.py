"""A valid Authenticode signature is corroborating context, never a trust
shortcut (AuthenticodeTool's own docstring -- stolen/abused code-signing
certs are a real attack vector). But live-verified with gemma4:12b during
research calibration: on real Windows admin LOLBins (schtasks.exe,
powershell.exe, wmic.exe), gemma correctly reasoned from this exact
evidence to 'benign' -- explicitly citing the Microsoft signature as
outweighing the borderline capability evidence -- while the deterministic
gate scored 'malicious' 0.9 on the identical evidence, because a valid-
signature finding is severity='info' and _high_signal_categories() only
counts medium+ findings, so the signature was structurally inert to the
score. This raises the corroboration bar by ONE category when a valid
signature is present -- never a short-circuit to benign, just a modestly
higher bar, the same way a human analyst gives a signed binary the
benefit of the doubt without treating it as proof."""
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


def _valid_signature_finding():
    ev = EvidenceRecord(evidence_id="ev_sig", artifact_id="art1", locator="authenticode:status",
                        excerpt="Valid", trust="tool")
    finding = Finding(finding_id="f_sig",
                      claim="File carries a valid Authenticode signature (signer: CN=Microsoft Windows).",
                      category="capability", severity="info", confidence=0.6,
                      evidence=["ev_sig"], grounded=True)
    return finding, ev


def _invalid_signature_finding():
    ev = EvidenceRecord(evidence_id="ev_sig", artifact_id="art1", locator="authenticode:status",
                        excerpt="NotSigned", trust="tool")
    finding = Finding(finding_id="f_sig", claim="File is not validly Authenticode-signed (NotSigned).",
                      category="capability", severity="info", confidence=0.6,
                      evidence=["ev_sig"], grounded=True)
    return finding, ev


def _state_with(findings, evidence):
    s = AnalysisState(run_id="r1", sample=_sample())
    s.findings = findings
    s.evidence = evidence
    s.stage_results = [StageResult(stage="static", status="ok")]
    return s


def _three_categories():
    return (
        [_capa_finding("f_aa", "ev_aa"), _capa_finding("f_lc", "ev_lc"), _capa_finding("f_comm", "ev_comm")],
        [_capa_evidence("ev_aa", "anti-analysis"), _capa_evidence("ev_lc", "load-code"),
         _capa_evidence("ev_comm", "communication")])


def test_validly_signed_sample_with_exactly_three_categories_does_not_convict():
    """The exact real-world shape found live: schtasks.exe/powershell.exe
    cross 3 categories (persistence/communication/anti-analysis) but are
    validly signed -- the raised bar should keep this out of suspicious/malicious."""
    findings, evidence = _three_categories()
    sig_finding, sig_ev = _valid_signature_finding()
    state = _state_with(findings + [sig_finding], evidence + [sig_ev])
    v = build_verdict(state)
    assert v.verdict not in ("suspicious", "malicious")


def test_validly_signed_sample_with_four_categories_still_convicts():
    """A valid signature raises the bar, it does not grant immunity --
    strong enough evidence must still be able to override it."""
    findings, evidence = _three_categories()
    findings.append(_capa_finding("f_impact", "ev_impact"))
    evidence.append(_capa_evidence("ev_impact", "impact"))
    sig_finding, sig_ev = _valid_signature_finding()
    state = _state_with(findings + [sig_finding], evidence + [sig_ev])
    v = build_verdict(state)
    assert v.verdict in ("suspicious", "malicious")


def test_unsigned_sample_with_three_categories_still_convicts():
    """Baseline behavior for the common case (no signature info at all)
    must be unchanged -- this is the existing, already-tested corroboration
    gate behavior from test_reporter_packing_category.py etc."""
    findings, evidence = _three_categories()
    state = _state_with(findings, evidence)
    v = build_verdict(state)
    assert v.verdict in ("suspicious", "malicious")


def test_invalidly_signed_sample_with_three_categories_still_convicts():
    """A finding stating the file is NOT validly signed must not be
    mistaken for a valid-signature finding -- must not raise the bar."""
    findings, evidence = _three_categories()
    sig_finding, sig_ev = _invalid_signature_finding()
    state = _state_with(findings + [sig_finding], evidence + [sig_ev])
    v = build_verdict(state)
    assert v.verdict in ("suspicious", "malicious")


def test_ungrounded_signature_finding_does_not_raise_bar():
    """Only grounded findings should count -- an ungrounded (unverified)
    signature claim shouldn't be trusted to soften the verdict."""
    findings, evidence = _three_categories()
    sig_finding, sig_ev = _valid_signature_finding()
    sig_finding = sig_finding.model_copy(update={"grounded": False})
    state = _state_with(findings + [sig_finding], evidence + [sig_ev])
    v = build_verdict(state)
    assert v.verdict in ("suspicious", "malicious")
