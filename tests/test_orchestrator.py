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


def test_progress_cb_receives_the_same_lines_that_get_printed(monkeypatch, tmp_path, capsys):
    """The web UI streams these lines to the
    browser via SSE -- progress_cb must see exactly what the CLI prints,
    and printing must be unaffected whether or not a callback is given."""
    monkeypatch.delenv("KNOWN_GOOD_HASHES_PATH", raising=False)
    received = []
    run_linear(_state(tmp_path, "a" * 64), progress_cb=received.append)
    printed = capsys.readouterr().out
    assert received, "progress_cb should have received at least one line"
    assert any("stage 'triage'" in line for line in received)
    for line in received:
        assert line in printed


def test_progress_cb_is_optional_and_does_not_change_behavior_when_absent(monkeypatch, tmp_path):
    monkeypatch.delenv("KNOWN_GOOD_HASHES_PATH", raising=False)
    state = run_linear(_state(tmp_path, "a" * 64))  # no progress_cb -- must not raise
    assert state.status == "complete"


def test_pipeline_order_places_behavioral_analyst_and_verifier_critic_correctly(monkeypatch, tmp_path):
    """behavioral_analyst runs after ttp; verify runs after behavioral_analyst
    (so it grounds the narrative too); verifier_critic runs last (after
    verify, not before -- otherwise verify's unconditional grounded=True
    for any finding with evidence would clobber verifier_critic's
    downgrade decision)."""
    monkeypatch.delenv("KNOWN_GOOD_HASHES_PATH", raising=False)
    state = run_linear(_state(tmp_path, "a" * 64))
    order = [sr.stage for sr in state.stage_results]
    assert order.index("ttp") < order.index("behavioral_analyst")
    assert order.index("behavioral_analyst") < order.index("verify")
    assert order.index("verify") < order.index("verifier_critic")


def test_skips_behavioral_analyst_and_verifier_critic_on_known_good_match(monkeypatch, tmp_path):
    hashes_file = tmp_path / "hashes.txt"
    hashes_file.write_text("a" * 64 + "\n")
    monkeypatch.setenv("KNOWN_GOOD_HASHES_PATH", str(hashes_file))
    state = run_linear(_state(tmp_path, "a" * 64))
    ba_results = [sr for sr in state.stage_results if sr.stage == "behavioral_analyst"]
    vc_results = [sr for sr in state.stage_results if sr.stage == "verifier_critic"]
    assert len(ba_results) == 1 and ba_results[0].status == "skipped"
    assert "known-good" in (ba_results[0].notes or "").lower()
    assert len(vc_results) == 1 and vc_results[0].status == "skipped"
    assert "known-good" in (vc_results[0].notes or "").lower()


def test_records_wall_clock_duration_per_named_pipeline_stage(monkeypatch, tmp_path):
    """Efficiency-table instrumentation: the orchestrator times each named
    stage's agent() call and records it on state.stage_durations_ms, keyed
    by the same stage names build_pipeline() uses."""
    monkeypatch.delenv("KNOWN_GOOD_HASHES_PATH", raising=False)
    state = run_linear(_state(tmp_path, "a" * 64))
    expected_stages = {"triage", "static", "dynamic", "ttp",
                       "behavioral_analyst", "verify", "verifier_critic"}
    assert expected_stages <= set(state.stage_durations_ms.keys())
    for stage, duration in state.stage_durations_ms.items():
        assert isinstance(duration, float)
        assert duration >= 0.0


def test_known_good_skip_records_zero_duration_for_skipped_stages(monkeypatch, tmp_path):
    """A stage that's skipped outright by the orchestrator's known-good
    short-circuit never runs its agent() function at all, so 0.0ms is the
    honest measurement -- not a missing/omitted key."""
    hashes_file = tmp_path / "hashes.txt"
    hashes_file.write_text("a" * 64 + "\n")
    monkeypatch.setenv("KNOWN_GOOD_HASHES_PATH", str(hashes_file))
    state = run_linear(_state(tmp_path, "a" * 64))
    for stage in ("static", "dynamic", "behavioral_analyst", "verifier_critic"):
        assert state.stage_durations_ms[stage] == 0.0
