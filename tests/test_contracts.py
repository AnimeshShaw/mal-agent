"""Contract tests: the real safety net. If these break, a refactor has corrupted
the frozen boundaries."""
from malagent.contracts import (AnalysisState, EgressPolicy, Finding, Sample,
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
