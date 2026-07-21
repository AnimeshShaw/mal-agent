"""triage_agent must run KnownGoodTool alongside the other triage tools, so
a known-good hash match is available as early as possible -- before the
orchestrator decides whether to run the expensive stages at all."""
from __future__ import annotations
from malagent.agents import triage_agent
from malagent.contracts import AnalysisState, Provenance, Sample, StepBudget


def _state(tmp_path, sha256="a" * 64):
    sample_file = tmp_path / "sample.bin"
    sample_file.write_bytes(b"MZ" + b"\x00" * 62)
    sample = Sample(sha256=sha256, md5="b" * 64, path=str(sample_file),
                    file_type="PE", size=64, provenance=Provenance())
    return AnalysisState(run_id="r1", sample=sample, budget=StepBudget())


def test_triage_agent_includes_known_good_check(monkeypatch, tmp_path):
    hashes_file = tmp_path / "hashes.txt"
    hashes_file.write_text("a" * 64 + "\n")
    monkeypatch.setenv("KNOWN_GOOD_HASHES_PATH", str(hashes_file))
    state = triage_agent(_state(tmp_path))
    assert any(f.category == "verdict_factor" for f in state.findings)


def test_triage_agent_without_allowlist_configured_has_no_verdict_factor(monkeypatch, tmp_path):
    monkeypatch.delenv("KNOWN_GOOD_HASHES_PATH", raising=False)
    state = triage_agent(_state(tmp_path))
    assert not any(f.category == "verdict_factor" for f in state.findings)


def test_triage_agent_includes_authenticode_check(monkeypatch, tmp_path):
    monkeypatch.setattr("os.name", "nt")
    monkeypatch.setattr("subprocess.run", lambda *a, **kw: type(
        "R", (), {"stdout": '{"Status": 2, "StatusMessage": "not signed", "Signer": null}',
                  "stderr": ""})())
    state = triage_agent(_state(tmp_path))
    assert any("Authenticode" in f.claim for f in state.findings)


def test_triage_agent_skips_remaining_tools_on_known_good_match(monkeypatch, tmp_path):
    """A known-good hash match already decides the verdict outright
    (reporter.build_verdict()'s verdict_factor short-circuit) -- running
    StaticFeaturesTool/PEHeaderTool/CapaTool/AuthenticodeTool afterward is
    pure wasted work, and capa specifically can take 100+ seconds on a real
    binary. Live-verified: certutil.exe with its real hash allowlisted
    still ran the full capa analysis (80 rules matched) before this fix,
    for a verdict that was already decided before capa even started."""
    hashes_file = tmp_path / "hashes.txt"
    hashes_file.write_text("a" * 64 + "\n")
    monkeypatch.setenv("KNOWN_GOOD_HASHES_PATH", str(hashes_file))
    state = triage_agent(_state(tmp_path))
    assert len(state.stage_results) == 1
    assert state.stage_results[0].notes == "known-good hash match"


def test_triage_agent_runs_remaining_tools_when_no_known_good_match(monkeypatch, tmp_path):
    """Backward compatibility: without a match (or without an allowlist
    configured at all), every other triage tool must still run exactly as
    before -- only a real match skips them."""
    monkeypatch.delenv("KNOWN_GOOD_HASHES_PATH", raising=False)
    state = triage_agent(_state(tmp_path))
    assert len(state.stage_results) > 1
