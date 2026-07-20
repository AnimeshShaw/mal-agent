"""write_narrative produces Executive Summary + Recommendations prose for
the mandatory txt report. Three-tier fallback: behavioral_analyst's
verified narrative (if present) -> direct router call over grounded
findings -> fully templated text from Verdict fields when no router is
configured. Must always return usable text -- the mandatory report cannot
have a missing section because a model was unavailable."""
from __future__ import annotations
from malagent.contracts import AnalysisState, Finding, Provenance, Sample, Verdict
from malagent.reporter import write_narrative


def _sample():
    return Sample(sha256="a" * 64, md5="b" * 32, path="/tmp/x.malz",
                  file_type="PE", size=10, provenance=Provenance())


def _verdict(verdict="suspicious", confidence=0.5):
    return Verdict(sample_sha256="a" * 64, verdict=verdict, confidence=confidence)


class _FakeResponse:
    def __init__(self, text):
        self.text = text
        self.provider = "fake"
        self.location = "local"


class _RecordingRouter:
    def __init__(self, response_text=None, always_none=False):
        self.calls = []
        self._response_text = response_text
        self._always_none = always_none

    def analyze(self, *, system, untrusted_label, untrusted_text, escalate=False,
                artifact_class="derived"):
        self.calls.append({"label": untrusted_label, "text": untrusted_text})
        return None if self._always_none else _FakeResponse(self._response_text)


def test_no_router_produces_templated_fallback():
    state = AnalysisState(run_id="r1", sample=_sample())
    summary, recs = write_narrative(state, _verdict("malicious", 0.9), router=None)
    assert "MALICIOUS" in summary
    assert "escalate" in recs.lower()


def test_uses_behavioral_analyst_narrative_when_present_and_grounded():
    state = AnalysisState(run_id="r1", sample=_sample())
    state.findings = [Finding(finding_id="behavioral_r1",
                              claim="This sample injects code into explorer.exe.",
                              category="behavior", severity="info", confidence=0.5,
                              evidence=["ev1"], source_stage="behavioral_analyst", grounded=True)]
    router = _RecordingRouter(response_text=(
        "EXECUTIVE SUMMARY:\nThis sample injects code, high risk.\n"
        "RECOMMENDATIONS:\nQuarantine immediately."))
    summary, recs = write_narrative(state, _verdict("malicious", 0.9), router=router)
    assert summary == "This sample injects code, high risk."
    assert recs == "Quarantine immediately."
    assert router.calls[0]["label"] == "behavioral_narrative"
    assert "injects code into explorer.exe" in router.calls[0]["text"]


def test_ignores_ungrounded_behavioral_narrative_falls_back_to_grounded_findings():
    """A behavioral_analyst finding that verifier_critic downgraded
    (grounded=False) must not be used as the narrative source -- an
    unverified/rejected claim shouldn't drive the report's headline
    summary."""
    state = AnalysisState(run_id="r1", sample=_sample())
    state.findings = [
        Finding(finding_id="behavioral_r1", claim="Rejected narrative claim.",
               category="behavior", severity="info", confidence=0.5,
               evidence=["ev1"], source_stage="behavioral_analyst", grounded=False),
        Finding(finding_id="f1", claim="Capability detected: XYZ", category="capability",
               severity="medium", confidence=0.7, evidence=["ev2"], grounded=True),
    ]
    router = _RecordingRouter(response_text=(
        "EXECUTIVE SUMMARY:\nSample shows capability XYZ.\nRECOMMENDATIONS:\nReview manually."))
    summary, recs = write_narrative(state, _verdict("suspicious", 0.5), router=router)
    assert router.calls[0]["label"] == "grounded_findings"
    assert "Rejected narrative claim" not in router.calls[0]["text"]
    assert "XYZ" in router.calls[0]["text"]


def test_falls_back_to_grounded_findings_when_no_narrative_present():
    state = AnalysisState(run_id="r1", sample=_sample())
    state.findings = [Finding(finding_id="f1", claim="Capability detected: XYZ",
                              category="capability", severity="medium", confidence=0.7,
                              evidence=["ev1"], grounded=True)]
    router = _RecordingRouter(response_text=(
        "EXECUTIVE SUMMARY:\nSample shows capability XYZ.\nRECOMMENDATIONS:\nReview manually."))
    summary, recs = write_narrative(state, _verdict("suspicious", 0.5), router=router)
    assert summary == "Sample shows capability XYZ."
    assert router.calls[0]["label"] == "grounded_findings"


def test_model_unavailable_falls_back_to_templated():
    state = AnalysisState(run_id="r1", sample=_sample())
    router = _RecordingRouter(always_none=True)
    summary, recs = write_narrative(state, _verdict("benign", 0.55), router=router)
    assert "verdict record" in summary.lower()
    assert "monitoring" in recs.lower()


def test_malformed_model_response_degrades_to_whole_text_plus_templated_recommendation():
    state = AnalysisState(run_id="r1", sample=_sample())
    router = _RecordingRouter(response_text="This model ignored the requested format entirely.")
    summary, recs = write_narrative(state, _verdict("suspicious", 0.5), router=router)
    assert summary == "This model ignored the requested format entirely."
    assert "escalate" in recs.lower()


def test_templated_recommendations_vary_by_verdict():
    state = AnalysisState(run_id="r1", sample=_sample())
    _, malicious_recs = write_narrative(state, _verdict("malicious", 0.9), router=None)
    _, benign_recs = write_narrative(state, _verdict("benign", 0.55), router=None)
    assert malicious_recs != benign_recs
    assert "contain" in malicious_recs.lower() or "escalate" in malicious_recs.lower()
