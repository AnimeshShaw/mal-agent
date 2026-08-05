"""behavioral_analyst synthesizes every grounded finding accumulated so far
into one coherent narrative Finding, grounded in the union of everything it
drew on. It never influences reporter.build_verdict()'s deterministic score
(severity is always "info") -- see test_llm_agents_never_score.py for the
regression guard on that specific principle."""
from __future__ import annotations
from malagent.agents import make_behavioral_analyst
from malagent.contracts import AnalysisState, Finding, Provenance, Sample


def _sample():
    return Sample(sha256="a" * 64, md5="b" * 32, path="/tmp/x.malz",
                  file_type="PE", size=10, provenance=Provenance())


def _state_with_findings(findings):
    s = AnalysisState(run_id="r1", sample=_sample())
    s.findings = findings
    return s


def _grounded(fid, claim, evidence):
    return Finding(finding_id=fid, claim=claim, category="capability",
                   severity="medium", confidence=0.7, evidence=evidence)


class _FakeResponse:
    def __init__(self, text="This sample appears to inject code into remote processes."):
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
        self.calls.append({"system": system, "label": untrusted_label, "text": untrusted_text,
                           "escalate": escalate, "artifact_class": artifact_class})
        return None if self._always_none else self._response


def test_skipped_when_no_router():
    state = _state_with_findings([_grounded("f1", "x", ["ev1"])])
    agent = make_behavioral_analyst(router=None)
    agent(state)
    stage = [sr for sr in state.stage_results if sr.stage == "behavioral_analyst"]
    assert len(stage) == 1
    assert stage[0].status == "skipped"


def test_skipped_when_no_grounded_findings():
    state = _state_with_findings([])
    router = _RecordingRouter()
    agent = make_behavioral_analyst(router=router)
    agent(state)
    assert router.calls == []
    stage = [sr for sr in state.stage_results if sr.stage == "behavioral_analyst"][0]
    assert stage.status == "skipped"


def test_produces_grounded_synthesis_finding_from_all_prior_findings():
    findings = [
        _grounded("f1", "Capability detected: inject dll reflectively", ["ev1"]),
        _grounded("f2", "Capability detected: create or open mutex on Windows", ["ev2"]),
    ]
    state = _state_with_findings(findings)
    router = _RecordingRouter(response=_FakeResponse("Synthesized narrative text."))
    agent = make_behavioral_analyst(router=router)
    agent(state)
    synth = [f for f in state.findings if f.source_stage == "behavioral_analyst"]
    assert len(synth) == 1
    assert synth[0].claim == "Synthesized narrative text."
    assert synth[0].severity == "info"
    assert sorted(synth[0].evidence) == ["ev1", "ev2"]


def test_synthesis_prompt_includes_all_finding_claims():
    findings = [_grounded("f1", "Capability detected: XYZ marker", ["ev1"])]
    state = _state_with_findings(findings)
    router = _RecordingRouter()
    agent = make_behavioral_analyst(router=router)
    agent(state)
    assert "XYZ marker" in router.calls[0]["text"]
    assert router.calls[0]["artifact_class"] == "derived"


def test_system_prompt_grounded_with_retrieved_tactic_context_when_present():
    """The M4 'true RAG' milestone: when grounded findings carry real
    attack_tactics (from capa's own live ATT&CK match), the retrieved real
    MITRE tactic description is included in the SYSTEM prompt (trusted
    analyst-supplied grounding), not folded into the untrusted findings
    blob -- it's our own static reference corpus, not sample-derived
    content, so it doesn't need injection wrapping."""
    findings = [
        Finding(finding_id="f1", claim="Capability detected: deobfuscate data",
               category="capability", severity="medium", confidence=0.7,
               evidence=["ev1"], attack_tactics=["Defense Evasion"]),
    ]
    state = _state_with_findings(findings)
    router = _RecordingRouter()
    agent = make_behavioral_analyst(router=router)
    agent(state)
    system = router.calls[0]["system"]
    assert "Defense Evasion" in system
    assert "avoid being detected" in system


def test_system_prompt_unchanged_shape_when_no_tactics_present():
    """No attack_tactics on any grounded finding -> no retrieved-context
    section added; system prompt stays exactly as before this feature."""
    findings = [_grounded("f1", "Capability detected: read file", ["ev1"])]
    state = _state_with_findings(findings)
    router = _RecordingRouter()
    agent = make_behavioral_analyst(router=router)
    agent(state)
    assert "Relevant ATT&CK tactics" not in router.calls[0]["system"]


def test_system_prompt_requests_kill_chain_sequencing_and_forbids_verdict_word():
    """TODO Phase 6 item 1: richer cross-tool correlation -- kill-chain
    tactic sequencing instead of a flat summary, explicit malicious-vs-
    benign evidence separation, and an explicit instruction not to state
    a final verdict word (reinforces the structural severity='info'
    guarantee at the prompt level, on top of it, not instead of it)."""
    findings = [_grounded("f1", "Capability detected: read file", ["ev1"])]
    state = _state_with_findings(findings)
    router = _RecordingRouter()
    agent = make_behavioral_analyst(router=router)
    agent(state)
    system = router.calls[0]["system"]
    assert "kill-chain" in system.lower()
    assert "malicious interpretation" in system.lower() or "supports a malicious" in system.lower()
    assert "do not state a final verdict word" in system.lower()


def test_reports_partial_when_model_unavailable():
    findings = [_grounded("f1", "x", ["ev1"])]
    state = _state_with_findings(findings)
    router = _RecordingRouter(always_none=True)
    agent = make_behavioral_analyst(router=router)
    agent(state)
    stage = [sr for sr in state.stage_results if sr.stage == "behavioral_analyst"][0]
    assert stage.status == "partial"
    assert stage.unresolved
    assert not any(f.source_stage == "behavioral_analyst" for f in state.findings)
