"""die (Detect It Easy, https://github.com/horsicq/DIE-engine)
packer/compiler identification. Deliberately
NOT live-verified against a real `diec` installation: there is no `die`
binary in this development environment, and installing/running an
unfamiliar third-party executable autonomously (rather than a
pip-installable library like pyelftools/yara-python) isn't a call to
make without the user present. Same honest-limitation discipline as
MachoTool. JSON output shape modeled on DIE's documented `-j` format;
if the real schema differs, this needs a real-installation pass to
correct, same as MachoTool's segment/import heuristics need a real
macOS sample."""
from __future__ import annotations
import json
from malagent.contracts import AnalysisState, Provenance, Sample
from malagent.die_tool import DieTool


def _sample():
    return Sample(sha256="a" * 64, md5="b" * 32, path="/tmp/x.malz",
                  file_type="PE", size=10, provenance=Provenance())


def _state():
    return AnalysisState(run_id="r1", sample=_sample())


def test_skips_when_die_not_on_path(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: None)
    sr = DieTool().run(_state())
    assert sr.status == "skipped"


def test_packer_detection_produces_finding(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/diec" if name == "diec" else None)
    doc = {"detects": [{"filetype": "PE64", "values": [
        {"type": "Packer", "name": "UPX", "version": "3.96", "info": ""},
    ]}]}

    def fake_run(cmd, capture_output=True, timeout=30):
        class R:
            stdout = json.dumps(doc).encode()
            returncode = 0
        return R()

    monkeypatch.setattr("subprocess.run", fake_run)
    sr = DieTool().run(_state())
    assert sr.status == "ok"
    assert any("UPX" in f.claim for f in sr.findings)


def test_no_packer_detected_produces_no_findings(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/diec" if name == "diec" else None)
    doc = {"detects": [{"filetype": "PE64", "values": [
        {"type": "Compiler", "name": "Microsoft Visual C++", "version": "2019", "info": ""},
    ]}]}

    def fake_run(cmd, capture_output=True, timeout=30):
        class R:
            stdout = json.dumps(doc).encode()
            returncode = 0
        return R()

    monkeypatch.setattr("subprocess.run", fake_run)
    sr = DieTool().run(_state())
    assert sr.status == "ok"
    assert sr.findings == []


def test_malformed_output_reports_error_not_crash(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/diec" if name == "diec" else None)

    def fake_run(cmd, capture_output=True, timeout=30):
        class R:
            stdout = b"not json"
            returncode = 0
        return R()

    monkeypatch.setattr("subprocess.run", fake_run)
    sr = DieTool().run(_state())
    assert sr.status == "error"


def test_subprocess_failure_reports_error_not_crash(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/diec" if name == "diec" else None)

    def fake_run(cmd, capture_output=True, timeout=30):
        raise TimeoutError("die timed out")

    monkeypatch.setattr("subprocess.run", fake_run)
    sr = DieTool().run(_state())
    assert sr.status == "error"


def test_multiple_packer_detections_all_reported(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/diec" if name == "diec" else None)
    doc = {"detects": [{"filetype": "PE64", "values": [
        {"type": "Packer", "name": "UPX", "version": "3.96", "info": ""},
        {"type": "Protector", "name": "VMProtect", "version": "", "info": ""},
    ]}]}

    def fake_run(cmd, capture_output=True, timeout=30):
        class R:
            stdout = json.dumps(doc).encode()
            returncode = 0
        return R()

    monkeypatch.setattr("subprocess.run", fake_run)
    sr = DieTool().run(_state())
    assert len(sr.findings) == 1  # one combined finding, not one per detection
    assert "UPX" in sr.findings[0].claim and "VMProtect" in sr.findings[0].claim
