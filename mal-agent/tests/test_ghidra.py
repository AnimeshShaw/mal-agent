"""Headless-Ghidra adapter (M2). Ghidra is a heavy external tool; this suite
tests the pure logic (availability detection, function ranking, output
parsing) without requiring a real Ghidra install, and confirms the tool
degrades gracefully -- same pattern as CapaTool/PEHeaderTool -- when Ghidra
isn't present."""
from __future__ import annotations
import os
import stat
from malagent.ghidra_tool import GhidraTool, find_headless_ghidra, rank_functions_from_capa
from malagent.contracts import AnalysisState, Provenance, Sample, StepBudget


def _sample():
    return Sample(sha256="a" * 64, md5="b" * 32, path="/tmp/x.malz",
                  file_type="PE", size=10, provenance=Provenance())


def _state(**kw):
    return AnalysisState(run_id="r1", sample=_sample(), **kw)


# ---------- find_headless_ghidra ----------

def test_find_headless_ghidra_absent_returns_none(monkeypatch):
    monkeypatch.delenv("GHIDRA_HOME", raising=False)
    monkeypatch.setenv("PATH", "")
    assert find_headless_ghidra() is None


def test_find_headless_ghidra_via_ghidra_home(monkeypatch, tmp_path):
    support = tmp_path / "support"
    support.mkdir()
    script_name = "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"
    script = support / script_name
    script.write_text("echo fake ghidra")
    if os.name != "nt":
        script.chmod(script.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("GHIDRA_HOME", str(tmp_path))
    found = find_headless_ghidra()
    assert found == str(script)


# ---------- rank_functions_from_capa ----------

def test_rank_functions_from_capa_orders_by_match_count_and_caps_at_limit():
    capa_doc = {
        "rules": {
            "rule_a": {"meta": {}, "matches": [
                [{"type": "absolute", "value": 0x401000}, {}],
                [{"type": "absolute", "value": 0x401200}, {}],
            ]},
            "rule_b": {"meta": {}, "matches": [
                [{"type": "absolute", "value": 0x401000}, {}],
            ]},
            "rule_c_file_scope": {"meta": {}, "matches": [
                [{"type": "no address"}, {}],
            ]},
        }
    }
    ranked = rank_functions_from_capa(capa_doc, limit=5)
    assert ranked == [0x401000, 0x401200]

    capped = rank_functions_from_capa(capa_doc, limit=1)
    assert capped == [0x401000]


def test_rank_functions_from_capa_empty_doc_returns_empty():
    assert rank_functions_from_capa({}, limit=5) == []


# ---------- GhidraTool.run graceful degradation ----------

def test_ghidra_tool_skips_when_unavailable(monkeypatch):
    monkeypatch.delenv("GHIDRA_HOME", raising=False)
    monkeypatch.setenv("PATH", "")
    state = _state(budget=StepBudget())
    result = GhidraTool().run(state)
    assert result.status == "skipped"
    assert result.stage == "static"
    assert any("Ghidra" in u for u in result.unresolved)


def test_ghidra_tool_reports_capa_present_but_failed_distinctly(monkeypatch):
    """capa can be on PATH and still fail (bad rules path, malformed input,
    timeout). That must not be reported as 'capa not on PATH' -- the two
    honest failure modes need distinct, accurate messages."""
    tool = GhidraTool()
    monkeypatch.setattr("malagent.ghidra_tool.find_headless_ghidra", lambda: "fake-headless")
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/capa" if name == "capa" else None)

    def fake_run(*a, **kw):
        raise RuntimeError("capa: default embedded rules not found!")

    monkeypatch.setattr("subprocess.run", fake_run)
    state = _state(budget=StepBudget())
    result = tool.run(state)
    assert result.status == "partial"
    assert any("not on PATH" not in u for u in result.unresolved)
    assert any("capa: default embedded rules not found" in u for u in result.unresolved)


def test_ghidra_tool_passes_ghidra_home_to_decompile(monkeypatch):
    """_decompile drives pyghidra directly (in-process), which needs the Ghidra
    install dir (GHIDRA_HOME), not the analyzeHeadless script path that
    find_headless_ghidra() returns for the availability check."""
    tool = GhidraTool()
    monkeypatch.setenv("GHIDRA_HOME", "C:\\FakeGhidra")
    monkeypatch.setattr("malagent.ghidra_tool.find_headless_ghidra",
                        lambda: "C:\\FakeGhidra\\support\\analyzeHeadless.bat")
    capa_doc = {"rules": {"r": {"meta": {}, "matches": [
        [{"type": "absolute", "value": 0x1000}, {}],
    ]}}}
    monkeypatch.setattr(tool, "_load_capa_doc", lambda path: (capa_doc, None))
    seen = {}

    def fake_decompile(ghidra_home, sample_path, addrs):
        seen["ghidra_home"] = ghidra_home
        return {hex(a): "// stub" for a in addrs}

    monkeypatch.setattr(tool, "_decompile", fake_decompile)
    state = _state(budget=StepBudget())
    result = tool.run(state)
    assert seen["ghidra_home"] == "C:\\FakeGhidra"
    assert result.status == "ok"


def test_ghidra_tool_honors_step_budget(monkeypatch):
    """rank_functions_from_capa must be called with StepBudget.max_functions_decompiled
    as the cap, end to end through GhidraTool.run."""
    tool = GhidraTool()
    monkeypatch.setattr("malagent.ghidra_tool.find_headless_ghidra", lambda: "fake-headless")
    capa_doc = {"rules": {"r": {"meta": {}, "matches": [
        [{"type": "absolute", "value": a}, {}] for a in (0x1000, 0x2000, 0x3000)
    ]}}}
    monkeypatch.setattr(tool, "_load_capa_doc", lambda path: (capa_doc, None))
    seen = {}

    def fake_decompile(headless, sample_path, addrs):
        seen["addrs"] = addrs
        return {hex(a): "// stub" for a in addrs}

    monkeypatch.setattr(tool, "_decompile", fake_decompile)
    state = _state(budget=StepBudget(max_functions_decompiled=2))
    result = tool.run(state)
    assert len(seen["addrs"]) == 2
    assert result.status == "ok"
    assert len(result.findings) == 2
