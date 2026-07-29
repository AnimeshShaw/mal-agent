"""Efficiency-table instrumentation: ModelRouter times each provider.complete()
call (purely observational -- never influences the verdict) and records it on
the ModelCall it appends to state.model_calls."""
from __future__ import annotations
import time
from malagent.contracts import AnalysisState, EgressPolicy, Provenance, Sample, StepBudget
from malagent.models import ModelRouter


def _state() -> AnalysisState:
    sample = Sample(sha256="a" * 64, md5="b" * 32, path="/tmp/x.malz",
                    file_type="PE", size=1, provenance=Provenance())
    return AnalysisState(run_id="r1", sample=sample, policy=EgressPolicy(), budget=StepBudget())


class _SlowLocalProvider:
    name = "fake_local"
    location = "local"
    model = "fake-model"

    def complete(self, system: str, prompt: str) -> str:
        time.sleep(0.05)
        return "ok"


class _FailingLocalProvider:
    name = "fake_local"
    location = "local"
    model = "fake-model"

    def complete(self, system: str, prompt: str) -> str:
        raise RuntimeError("boom")


def test_analyze_records_real_duration_ms_on_success():
    state = _state()
    router = ModelRouter(state, local=_SlowLocalProvider())
    resp = router.analyze(system="s", untrusted_label="l", untrusted_text="t")
    assert resp is not None
    assert len(state.model_calls) == 1
    duration = state.model_calls[0].duration_ms
    assert duration is not None
    # slept ~50ms; allow generous scheduling slack, just prove it's real timing
    assert duration >= 30.0


def test_analyze_records_duration_even_when_provider_errors():
    state = _state()
    router = ModelRouter(state, local=_FailingLocalProvider())
    resp = router.analyze(system="s", untrusted_label="l", untrusted_text="t")
    assert resp is None
    assert len(state.model_calls) == 1
    assert state.model_calls[0].duration_ms is not None
    assert state.model_calls[0].duration_ms >= 0.0


def test_analyze_records_no_duration_when_egress_blocked_before_any_call():
    """The fail-closed egress-blocked path never calls a provider at all --
    there's nothing to time, so duration_ms must stay None (not 0), which
    would falsely claim a measurement was taken."""
    state = _state()
    state.policy = EgressPolicy(allow_cloud=False)

    class _Escalation:
        name = "fake_cloud"
        location = "cloud"
        model = "fake-cloud-model"
        def complete(self, system, prompt):
            raise AssertionError("must not be called when egress is blocked")

    router = ModelRouter(state, local=_SlowLocalProvider(), escalation=_Escalation())
    resp = router.analyze(system="s", untrusted_label="l", untrusted_text="t", escalate=True)
    assert resp is None
    assert len(state.model_calls) == 1
    assert state.model_calls[0].duration_ms is None
