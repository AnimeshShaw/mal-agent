"""render_html(): a self-contained, offline-viewable HTML report generated
alongside report.md/report.txt. Security-relevant, not just cosmetic:
every piece of text rendered here (Finding.claim, EvidenceRecord.excerpt,
notes/unresolved) originates from -- or is derived from -- an untrusted
malware sample. A sample authored specifically to break out of the HTML
(e.g. a "suspicious string" containing a real <script> tag) must never
execute when an analyst opens this report in a browser. Every dynamic
value must be HTML-escaped, not just the obviously long ones."""
from __future__ import annotations
from malagent.contracts import AnalysisState, EvidenceRecord, Finding, Provenance, Sample, StageResult, Verdict
from malagent.reporter import render_html


def _sample():
    return Sample(sha256="a" * 64, md5="b" * 32, path="/tmp/x.malz",
                  file_type="PE", size=10, provenance=Provenance())


def _verdict(verdict="malicious", confidence=0.9):
    return Verdict(sample_sha256="a" * 64, verdict=verdict, confidence=confidence,
                   attack_techniques=["T1055"], iocs=[], yara_rules=[],
                   key_findings=[], unresolved=[], evidence_complete=True)


def test_html_is_self_contained_no_external_resources():
    state = AnalysisState(run_id="r1", sample=_sample())
    html = render_html(state, _verdict(), audit=None, narrative=("summary", "recommendations"))
    assert "<html" in html.lower()
    assert "http://" not in html and "https://" not in html
    assert "<script src=" not in html.lower()


def test_html_escapes_malicious_claim_text_from_sample():
    """The core security property: a Finding.claim derived from an
    attacker-controlled string containing raw HTML/script must not
    execute when the report is opened in a browser."""
    ev = EvidenceRecord(evidence_id="ev1", artifact_id="art1", locator="string:x",
                        excerpt="<script>alert(document.cookie)</script>", trust="tool")
    f = Finding(finding_id="f1", claim="Suspicious string: <img src=x onerror=alert(1)>",
               category="capability", severity="medium", confidence=0.6,
               evidence=["ev1"], grounded=True, source_stage="triage")
    state = AnalysisState(run_id="r1", sample=_sample())
    state.findings = [f]
    state.evidence = [ev]
    state.stage_results = [StageResult(stage="triage", status="ok", tool="static_features",
                                       findings=[f], evidence=[ev])]
    html = render_html(state, _verdict(), audit=None, narrative=("summary", "recommendations"))
    assert "<script>alert" not in html
    assert "<img src=x onerror" not in html
    assert "&lt;script&gt;" in html or "&lt;img" in html


def test_html_shows_verdict_and_confidence():
    state = AnalysisState(run_id="r1", sample=_sample())
    html = render_html(state, _verdict("malicious", 0.94), audit=None,
                       narrative=("summary", "recommendations"))
    assert "MALICIOUS" in html or "malicious" in html.lower()
    assert "0.94" in html


def test_html_includes_per_tool_sections():
    state = AnalysisState(run_id="r1", sample=_sample())
    state.stage_results = [StageResult(stage="triage", status="ok", tool="capa",
                                       notes="capa rules matched=0")]
    html = render_html(state, _verdict(), audit=None, narrative=("summary", "recommendations"))
    assert "capa" in html.lower()


def test_html_renders_without_audit_object():
    """audit can be None (e.g. when called outside the normal pipeline
    flow) -- must degrade gracefully, not crash."""
    state = AnalysisState(run_id="r1", sample=_sample())
    html = render_html(state, _verdict(), audit=None, narrative=("summary", "recommendations"))
    assert "<html" in html.lower()
