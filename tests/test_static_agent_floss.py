"""static_agent must run FlossTool as part of the static stage, merging its
StageResult regardless of whether a model router is configured -- same
pattern as GhidraTool, since FLOSS's deobfuscation is deterministic and
independent of the LLM layer entirely."""
from __future__ import annotations
from malagent.agents import make_static_agent
from malagent.contracts import AnalysisState, Finding, Provenance, Sample, StageResult


def _sample():
    return Sample(sha256="a" * 64, md5="b" * 32, path="/tmp/x.malz",
                  file_type="PE", size=10, provenance=Provenance())


def _state():
    return AnalysisState(run_id="r1", sample=_sample())


class _FakeGhidra:
    def run(self, state):
        return StageResult(stage="static", status="skipped", notes="ghidra not configured")


class _FakeFloss:
    def __init__(self, result: StageResult):
        self._result = result

    def run(self, state):
        return self._result


def test_floss_result_merged_with_no_router_configured():
    floss_finding = Finding(finding_id="f_floss", claim="floss recovered 3 string(s)",
                            category="capability", severity="info", confidence=0.6,
                            evidence=[], source_stage="static")
    floss_result = StageResult(stage="static", status="ok", findings=[floss_finding])
    agent = make_static_agent(router=None, ghidra=_FakeGhidra(), floss=_FakeFloss(floss_result))
    state = agent(_state())
    assert any(f.finding_id == "f_floss" for f in state.findings)


def test_floss_runs_even_when_ghidra_produced_no_functions():
    """FLOSS's value is independent of Ghidra -- it must still run and its
    findings must still surface even on the whole-sample-narrative fallback
    path (no decompiled functions available)."""
    floss_finding = Finding(finding_id="f_floss2", claim="floss recovered 1 string(s)",
                            category="capability", severity="info", confidence=0.6,
                            evidence=[], source_stage="static")
    floss_result = StageResult(stage="static", status="ok", findings=[floss_finding])
    agent = make_static_agent(router=None, ghidra=_FakeGhidra(), floss=_FakeFloss(floss_result))
    state = agent(_state())
    assert any(f.finding_id == "f_floss2" for f in state.findings)
