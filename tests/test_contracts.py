"""Contract tests: the real safety net. If these break, a refactor has corrupted
the frozen boundaries."""
from malagent.contracts import (AnalysisState, EgressPolicy, Finding, ModelCall, Sample,
                                Verdict, Provenance)


def _sample():
    return Sample(sha256="a" * 64, md5="b" * 32, path="/tmp/x.malz",
                  file_type="PE", size=10)


def test_state_roundtrip():
    s = AnalysisState(run_id="r1", sample=_sample())
    j = s.model_dump_json()
    s2 = AnalysisState.model_validate_json(j)
    assert s2.run_id == "r1"
    assert s2.sample.sha256 == "a" * 64


def test_egress_defaults_fail_closed():
    p = EgressPolicy()
    assert p.allow_raw_bytes_egress is False
    assert p.allow_pseudocode_egress is False


def test_finding_requires_category():
    f = Finding(finding_id="f1", claim="x", category="capability")
    assert f.grounded is False
    assert f.evidence == []


def test_verdict_default_undetermined():
    v = Verdict(sample_sha256="a" * 64)
    assert v.verdict == "undetermined"
    assert v.evidence_complete is False


def test_analysis_state_has_stage_durations_ms_defaulting_empty():
    """Efficiency-table instrumentation: per-stage wall-clock time, keyed by
    the pipeline stage name (triage/static/dynamic/ttp/behavioral_analyst/
    verify/verifier_critic), populated by the orchestrator -- not by
    individual tools/agents, since a single named stage can append several
    StageResult records (see agents.triage_agent)."""
    s = AnalysisState(run_id="r1", sample=_sample())
    assert s.stage_durations_ms == {}


def test_model_call_duration_ms_defaults_to_none():
    """No timing recorded is represented honestly as None, not 0 -- 0 would
    claim a real (fast) measurement that never happened."""
    mc = ModelCall(provider="ollama", model="qwen2.5-coder:7b", location="local",
                   prompt_hash="abc123", egress_allowed=True)
    assert mc.duration_ms is None


def test_model_call_records_duration_ms_when_provided():
    mc = ModelCall(provider="ollama", model="qwen2.5-coder:7b", location="local",
                   prompt_hash="abc123", egress_allowed=True, duration_ms=123.4)
    assert mc.duration_ms == 123.4
