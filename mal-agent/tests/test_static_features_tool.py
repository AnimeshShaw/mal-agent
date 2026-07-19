"""Wide/Unicode (UTF-16LE) string extraction -- Windows PEs routinely carry
these, and the existing ASCII-only extractor misses them entirely."""
from __future__ import annotations
from malagent.contracts import AnalysisState, Provenance, Sample
from malagent.tools import StaticFeaturesTool


def _state_for(tmp_path, data: bytes) -> AnalysisState:
    p = tmp_path / "sample.bin"
    p.write_bytes(data)
    sample = Sample(sha256="a" * 64, md5="b" * 32, path=str(p),
                    file_type="PE", size=len(data), provenance=Provenance())
    return AnalysisState(run_id="r1", sample=sample)


def test_wide_string_suspicious_marker_detected(tmp_path):
    data = b"MZ" + b"\x00" * 62 + "cmd.exe".encode("utf-16-le") + b"\x00" * 32
    sr = StaticFeaturesTool().run(_state_for(tmp_path, data))
    wide = [f for f in sr.findings if f.claim.startswith("Suspicious wide")]
    assert len(wide) == 1
    assert "cmd.exe" in wide[0].claim


def test_wide_string_finding_has_correct_locator(tmp_path):
    data = b"MZ" + b"\x00" * 62 + "WinExec".encode("utf-16-le") + b"\x00" * 32
    sr = StaticFeaturesTool().run(_state_for(tmp_path, data))
    wide_ev = [e for e in sr.evidence if e.locator == "widestring:WinExec"]
    assert len(wide_ev) == 1


def test_no_wide_strings_present_produces_no_wide_findings(tmp_path):
    data = b"MZ" + b"\x00" * 126
    sr = StaticFeaturesTool().run(_state_for(tmp_path, data))
    assert not any(f.claim.startswith("Suspicious wide") for f in sr.findings)
