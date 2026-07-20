"""static_agent must run GhidraTool (D12) as part of the static stage, merging
its StageResult regardless of whether a model router is configured, and must
feed any decompiled-function findings into the model narrative prompt when a
router is available."""
from __future__ import annotations
from malagent.agents import make_static_agent
from malagent.contracts import AnalysisState, Finding, Provenance, Sample, StageResult


def _sample():
    return Sample(sha256="a" * 64, md5="b" * 32, path="/tmp/x.malz",
                  file_type="PE", size=10, provenance=Provenance())


def _state():
    return AnalysisState(run_id="r1", sample=_sample())


class _FakeGhidra:
    def __init__(self, result: StageResult):
        self._result = result

    def run(self, state):
        return self._result


class _FakeResponse:
    def __init__(self, text="ok"):
        self.text = text
        self.provider = "fake"
        self.location = "local"


class _RecordingRouter:
    def __init__(self):
        self.calls = []

    def analyze(self, *, system, untrusted_label, untrusted_text, escalate=False,
                artifact_class="derived"):
        self.calls.append(untrusted_text)
        return _FakeResponse()


def test_static_agent_merges_ghidra_result_without_router():
    ghidra_sr = StageResult(stage="static", status="skipped",
                            unresolved=["Headless Ghidra decompilation not run: Ghidra not found."])
    state = _state()
    agent = make_static_agent(router=None, ghidra=_FakeGhidra(ghidra_sr))
    agent(state)
    stages = [sr for sr in state.stage_results if sr.stage == "static"]
    assert any("Ghidra not found" in u for sr in stages for u in sr.unresolved)
    assert any("No model configured" in u for sr in stages for u in sr.unresolved)


def test_static_agent_feeds_ghidra_findings_into_narrative_prompt():
    f = Finding(finding_id="gf1", claim="Decompiled function@0x401000; allocates RWX memory.",
                category="behavior", severity="info", confidence=0.5,
                evidence=["ev1"], source_stage="static")
    ghidra_sr = StageResult(stage="static", status="ok", findings=[f],
                            notes="functions_decompiled=1")
    state = _state()
    router = _RecordingRouter()
    agent = make_static_agent(router=router, ghidra=_FakeGhidra(ghidra_sr))
    agent(state)
    assert any("Decompiled function@0x401000" in text for text in router.calls)
