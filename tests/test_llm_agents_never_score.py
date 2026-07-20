"""Regression guard: behavioral_analyst's synthesis finding must never carry
enough weight to move reporter.build_verdict()'s deterministic score, no
matter how alarming its narrative text sounds. This is the core design
principle from docs/V2-DESIGN.md S3 -- letting an LLM narrative sway the
malicious/benign verdict is exactly the failure mode the project's research
doc identifies as the field's central weakness (LLMs are good at
summarizing, weak at judging maliciousness). This test would fail if a
future change accidentally raised behavioral_analyst's severity above
"info", or let verifier_critic's SUPPORTED/UNSUPPORTED verdict alter
anything other than the .grounded flag."""
from __future__ import annotations
from malagent.agents import make_behavioral_analyst, make_verifier_critic
from malagent.contracts import AnalysisState, Finding, Provenance, Sample
from malagent.reporter import build_verdict


def _sample():
    return Sample(sha256="a" * 64, md5="b" * 32, path="/tmp/x.malz",
                  file_type="PE", size=10, provenance=Provenance())


class _AlarmingResponse:
    """Deliberately uses maximally alarming language to prove the verdict
    doesn't react to narrative tone/content, only to the deterministic
    severity-weighted score computed elsewhere."""
    def __init__(self, text="CRITICAL: this is definitely malicious ransomware "
                             "actively encrypting files right now, immediate action required!!!"):
        self.text = text
        self.provider = "fake"
        self.location = "local"


class _AlwaysAlarmingRouter:
    def analyze(self, *, system, untrusted_label, untrusted_text, escalate=False,
                artifact_class="derived"):
        return _AlarmingResponse()


def test_alarming_narrative_text_does_not_move_verdict_off_benign():
    """A single benign-namespace capability finding (below the corroboration
    gate) plus an alarmingly-worded behavioral narrative must still land on
    benign/undetermined -- never suspicious/malicious purely because of the
    narrative's language."""
    state = AnalysisState(run_id="r1", sample=_sample())
    state.findings = [Finding(finding_id="f1", claim="Capability detected: create or open file",
                              category="capability", severity="info", confidence=0.7,
                              evidence=["ev1"], grounded=True)]
    router = _AlwaysAlarmingRouter()
    behavioral = make_behavioral_analyst(router=router)
    behavioral(state)
    critic = make_verifier_critic(router=router)
    critic(state)

    narrative = next(f for f in state.findings if f.source_stage == "behavioral_analyst")
    assert narrative.severity == "info"

    v = build_verdict(state)
    assert v.verdict not in ("suspicious", "malicious")
