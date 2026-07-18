"""Orchestrator must skip the expensive stages (static: Ghidra+LLM, dynamic)
when triage found a known-good hash match -- that's the actual "before full
analysis" saving, not just a cosmetic verdict override. triage/ttp/verify
still run: verify is what grounds findings at all, and ttp/verify are cheap."""
from __future__ import annotations
from pathlib import Path
from malagent.contracts import AnalysisState, Provenance, Sample, StepBudget
from malagent.orchestrator import run_linear


def _state(tmp_path: Path, sha256: str) -> AnalysisState:
    sample_file = tmp_path / "sample.bin"
    sample_file.write_bytes(b"MZ" + b"\x00" * 62)
    sample = Sample(sha256=sha256, md5="b" * 64, path=str(sample_file),
                    file_type="PE", size=64, provenance=Provenance())
    return AnalysisState(run_id="r1", sample=sample, budget=StepBudget())


def test_skips_static_and_dynamic_on_known_good_match(monkeypatch, tmp_path):
    """Distinguishes the orchestrator's known-good short-circuit from
    static_agent's own default 'no model configured' skip (which would also
    show status='skipped' but for an unrelated reason, and must not make
    this test pass for the wrong reason)."""
    hashes_file = tmp_path / "hashes.txt"
    hashes_file.write_text("a" * 64 + "\n")
    monkeypatch.setenv("KNOWN_GOOD_HASHES_PATH", str(hashes_file))
    state = run_linear(_state(tmp_path, "a" * 64))
    static_results = [sr for sr in state.stage_results if sr.stage == "static"]
    assert len(static_results) == 1
    assert static_results[0].status == "skipped"
    assert "known-good" in (static_results[0].notes or "").lower()
    assert "verify" in {sr.stage for sr in state.stage_results}
    assert "ttp" in {sr.stage for sr in state.stage_results}


def test_runs_static_and_dynamic_normally_without_a_match(monkeypatch, tmp_path):
    monkeypatch.delenv("KNOWN_GOOD_HASHES_PATH", raising=False)
    state = run_linear(_state(tmp_path, "a" * 64))
    static_results = [sr for sr in state.stage_results if sr.stage == "static"]
    # static ran for real (Ghidra unavailable in this env -> its own honest
    # skip/partial, not the orchestrator's known-good short-circuit note)
    assert static_results
    assert not any("known-good" in (sr.notes or "") for sr in static_results)
