"""verifier_critic fact-checks the behavioral_analyst narrative against its
cited evidence -- the architecture doc's originally-named 'Verifier/Critic'
differentiator (MalAgentArchitecture.md Agent Role 6), distinct from
verifier_agent's evidence-linkage-only check (does it have an evidence ID
at all, no semantics)."""
from __future__ import annotations
from malagent.agents import make_verifier_critic
from malagent.contracts import AnalysisState, EvidenceRecord, Finding, Provenance, Sample


def _sample():
    return Sample(sha256="a" * 64, md5="b" * 32, path="/tmp/x.malz",
                  file_type="PE", size=10, provenance=Provenance())


def _state_with(findings, evidence):
    s = AnalysisState(run_id="r1", sample=_sample())
    s.findings = findings
    s.evidence = evidence
    return s


def _narrative_finding(evidence=None):
    return Finding(finding_id="behavioral_r1",
                   claim="This sample injects code and exfiltrates data.",
                   category="behavior", severity="info", confidence=0.5,
                   evidence=evidence or ["ev1"], source_stage="behavioral_analyst",
                   grounded=True)


class _FakeResponse:
    def __init__(self, text="SUPPORTED"):
        self.text = text
        self.provider = "fake"
        self.location = "local"


class _RecordingRouter:
    def __init__(self, response=None, always_none=False):
        self.calls = []
        self._response = response or _FakeResponse()
        self._always_none = always_none

    def analyze(self, *, system, untrusted_label, untrusted_text, escalate=False,
                artifact_class="derived"):
        self.calls.append({"text": untrusted_text})
        return None if self._always_none else self._response


def test_skipped_when_no_narrative_present():
    state = _state_with([], [])
    router = _RecordingRouter()
    agent = make_verifier_critic(router=router)
    agent(state)
    assert router.calls == []
    stage = [sr for sr in state.stage_results if sr.stage == "verifier_critic"][0]
    assert stage.status == "skipped"


def test_no_router_downgrades_narrative_to_ungrounded():
    narrative = _narrative_finding()
    ev = EvidenceRecord(evidence_id="ev1", artifact_id="a1", locator="x", excerpt="x", trust="tool")
    state = _state_with([narrative], [ev])
    agent = make_verifier_critic(router=None)
    agent(state)
    stage = [sr for sr in state.stage_results if sr.stage == "verifier_critic"][0]
    assert stage.status == "skipped"
    assert narrative.grounded is False


def test_supported_verdict_keeps_narrative_grounded():
    narrative = _narrative_finding()
    ev = EvidenceRecord(evidence_id="ev1", artifact_id="a1",
                        locator="capa:load-code:inject dll reflectively",
                        excerpt="inject dll reflectively", trust="tool")
    state = _state_with([narrative], [ev])
    router = _RecordingRouter(response=_FakeResponse("SUPPORTED"))
    agent = make_verifier_critic(router=router)
    agent(state)
    assert narrative.grounded is True
    stage = [sr for sr in state.stage_results if sr.stage == "verifier_critic"][0]
    assert stage.status == "ok"
    assert not stage.unresolved


def test_unsupported_verdict_downgrades_narrative_grounding():
    narrative = _narrative_finding()
    ev = EvidenceRecord(evidence_id="ev1", artifact_id="a1",
                        locator="capa:load-code:inject dll reflectively",
                        excerpt="inject dll reflectively", trust="tool")
    state = _state_with([narrative], [ev])
    router = _RecordingRouter(response=_FakeResponse(
        "UNSUPPORTED: narrative claims data exfiltration but no such evidence was cited"))
    agent = make_verifier_critic(router=router)
    agent(state)
    assert narrative.grounded is False
    stage = [sr for sr in state.stage_results if sr.stage == "verifier_critic"][0]
    assert any("failed independent fact-checking" in u for u in stage.unresolved)


def test_prompt_includes_narrative_and_cited_evidence_excerpts():
    narrative = _narrative_finding(evidence=["ev1"])
    ev = EvidenceRecord(evidence_id="ev1", artifact_id="a1",
                        locator="capa:load-code:inject dll reflectively",
                        excerpt="inject dll reflectively", trust="tool")
    state = _state_with([narrative], [ev])
    router = _RecordingRouter()
    agent = make_verifier_critic(router=router)
    agent(state)
    sent = router.calls[0]["text"]
    assert "injects code and exfiltrates data" in sent
    assert "inject dll reflectively" in sent


def test_model_unavailable_downgrades_narrative_and_reports_partial():
    narrative = _narrative_finding()
    ev = EvidenceRecord(evidence_id="ev1", artifact_id="a1", locator="x", excerpt="x", trust="tool")
    state = _state_with([narrative], [ev])
    router = _RecordingRouter(always_none=True)
    agent = make_verifier_critic(router=router)
    agent(state)
    stage = [sr for sr in state.stage_results if sr.stage == "verifier_critic"][0]
    assert stage.status == "partial"
    assert stage.unresolved
    assert narrative.grounded is False
