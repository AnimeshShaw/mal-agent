"""M1 completion: static_agent should summarize decompiled functions
individually (per-function loop) when Ghidra evidence is present, rather than
folding everything into one whole-sample capability narrative. Falling back
to the whole-sample narrative when no functions were decompiled (e.g. Ghidra
unavailable) is covered by the existing tests/test_escalation.py suite, which
runs the real GhidraTool() and must keep passing unmodified."""
from __future__ import annotations
from malagent.agents import make_static_agent
from malagent.contracts import (AnalysisState, EvidenceRecord, Finding, Provenance,
                                Sample, StageResult)


def _sample():
    return Sample(sha256="a" * 64, md5="b" * 32, path="/tmp/x.malz",
                  file_type="PE", size=10, provenance=Provenance())


def _state():
    return AnalysisState(run_id="r1", sample=_sample())


def _ghidra_result(n: int) -> StageResult:
    findings, evidence = [], []
    for i in range(n):
        addr = f"0x40{1000 + i:04x}"
        ev = EvidenceRecord(evidence_id=f"gev{i}", artifact_id="art1",
                            locator=f"function@{addr}",
                            excerpt=f"void FUN_{addr}(void) {{ /* body {i} */ }}", trust="tool")
        evidence.append(ev)
        findings.append(Finding(finding_id=f"gf{i}",
                                claim=f"Decompiled function@{addr}; pseudo-code available for review.",
                                category="behavior", severity="info", confidence=0.5,
                                evidence=[ev.evidence_id], source_stage="static"))
    return StageResult(stage="static", status="ok", findings=findings, evidence=evidence,
                       notes=f"functions_decompiled={n}")


class _FakeGhidra:
    def __init__(self, result: StageResult):
        self._result = result

    def run(self, state):
        return self._result


class _FakeResponse:
    def __init__(self, text):
        self.text = text
        self.provider = "fake"
        self.location = "local"


class _RecordingRouter:
    def __init__(self, responses=None, always_none=False):
        self.calls = []
        self._responses = responses or []
        self._always_none = always_none
        self._i = 0

    def analyze(self, *, system, untrusted_label, untrusted_text, escalate=False,
                artifact_class="derived"):
        self.calls.append({"label": untrusted_label, "text": untrusted_text,
                           "escalate": escalate, "artifact_class": artifact_class})
        if self._always_none:
            return None
        resp = _FakeResponse(self._responses[self._i])
        self._i += 1
        return resp


def test_summarizes_each_decompiled_function_individually():
    ghidra_sr = _ghidra_result(2)
    router = _RecordingRouter(responses=["summary of fn0", "summary of fn1"])
    state = _state()
    agent = make_static_agent(router=router, ghidra=_FakeGhidra(ghidra_sr))
    agent(state)

    # exactly one router call per decompiled function, none for a whole-sample narrative
    assert len(router.calls) == 2
    assert all(c["label"] != "capability_evidence" for c in router.calls)

    per_fn = [f for f in state.findings if f.source_stage == "static"
             and f.claim.startswith("summary of fn")]
    assert len(per_fn) == 2
    assert sorted(tuple(f.evidence) for f in per_fn) == [("gev0",), ("gev1",)]


def test_per_function_calls_use_pseudocode_artifact_class():
    ghidra_sr = _ghidra_result(1)
    router = _RecordingRouter(responses=["summary"])
    state = _state()
    agent = make_static_agent(router=router, ghidra=_FakeGhidra(ghidra_sr))
    agent(state)
    assert router.calls[0]["artifact_class"] == "pseudocode"
    assert "FUN_0x4003e8" in router.calls[0]["text"]


def test_per_function_finding_is_grounded_in_the_ghidra_evidence():
    ghidra_sr = _ghidra_result(1)
    router = _RecordingRouter(responses=["fn0 allocates RWX memory"])
    state = _state()
    agent = make_static_agent(router=router, ghidra=_FakeGhidra(ghidra_sr))
    agent(state)
    summary = next(f for f in state.findings if f.claim == "fn0 allocates RWX memory")
    assert summary.evidence == ["gev0"]


def test_reports_partial_when_all_per_function_calls_fail_closed():
    ghidra_sr = _ghidra_result(2)
    router = _RecordingRouter(always_none=True)
    state = _state()
    agent = make_static_agent(router=router, ghidra=_FakeGhidra(ghidra_sr))
    agent(state)
    static_stages = [sr for sr in state.stage_results if sr.stage == "static"]
    assert any(sr.status == "partial" and sr.unresolved for sr in static_stages)
