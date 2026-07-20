"""Policy-driven escalation trigger tests (M1): static_agent must only escalate
to cloud when a fired trigger is present in EgressPolicy.escalation_triggers,
not unconditionally."""
from __future__ import annotations
from malagent.agents import determine_escalation_trigger, make_static_agent
from malagent.contracts import AnalysisState, EgressPolicy, Finding, Provenance, Sample


def _sample():
    return Sample(sha256="a" * 64, md5="b" * 32, path="/tmp/x.malz",
                  file_type="PE", size=10, provenance=Provenance())


def _state(findings, triggers=None):
    s = AnalysisState(run_id="r1", sample=_sample())
    if triggers is not None:
        s.policy = EgressPolicy(escalation_triggers=triggers)
    s.findings = findings
    return s


def test_no_grounded_findings_triggers_ambiguous_decompile():
    state = _state(findings=[])
    assert determine_escalation_trigger(state) == "ambiguous_decompile"


def test_high_severity_grounded_finding_triggers_security_critical():
    f = Finding(finding_id="f1", claim="x", category="capability",
                severity="high", confidence=0.9, evidence=["ev1"])
    state = _state(findings=[f])
    assert determine_escalation_trigger(state) == "security_critical"


def test_low_confidence_grounded_finding_triggers_low_confidence():
    f = Finding(finding_id="f1", claim="x", category="capability",
                severity="low", confidence=0.3, evidence=["ev1"])
    state = _state(findings=[f])
    assert determine_escalation_trigger(state) == "low_confidence"


def test_solid_grounded_findings_trigger_nothing():
    f = Finding(finding_id="f1", claim="x", category="capability",
                severity="medium", confidence=0.9, evidence=["ev1"])
    state = _state(findings=[f])
    assert determine_escalation_trigger(state) is None


class _FakeResponse:
    def __init__(self, text="ok"):
        self.text = text
        self.provider = "fake"
        self.location = "local"


class _RecordingRouter:
    """Stands in for ModelRouter; records the `escalate` flag it was called with."""
    def __init__(self):
        self.calls = []

    def analyze(self, *, system, untrusted_label, untrusted_text, escalate=False,
                artifact_class="derived"):
        self.calls.append(escalate)
        return _FakeResponse()


def test_static_agent_does_not_escalate_when_trigger_not_in_policy():
    f = Finding(finding_id="f1", claim="x", category="capability",
                severity="high", confidence=0.9, evidence=["ev1"])
    # security_critical WILL fire, but policy only allows low_confidence -> must not escalate
    state = _state(findings=[f], triggers=["low_confidence"])
    router = _RecordingRouter()
    agent = make_static_agent(router)
    agent(state)
    assert router.calls == [False]


def test_static_agent_escalates_when_trigger_is_in_policy():
    f = Finding(finding_id="f1", claim="x", category="capability",
                severity="high", confidence=0.9, evidence=["ev1"])
    state = _state(findings=[f], triggers=["security_critical"])
    router = _RecordingRouter()
    agent = make_static_agent(router)
    agent(state)
    assert router.calls == [True]
