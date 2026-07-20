"""CapaTool severity assignment (calibration fix). Previously every capa rule
match was hardcoded severity="medium", so a completely benign binary with
many mundane capabilities (read file, create directory, ...) scored as high
as one with a handful of genuinely attacker-relevant capabilities -- verified
live against notepad.exe, which capa correctly recognizes as having 35
capabilities, and the old scoring called MALICIOUS at 0.9 confidence.

capa's own rule corpus organizes rules under a real, stable namespace
taxonomy (confirmed against the downloaded capa-rules-9.4.0 checkout):
anti-analysis, collection, communication, compiler, data-manipulation,
executable, exploitation, host-interaction, impact, internal, lib, linking,
load-code, malware-family, nursery, persistence, runtime, targeting. Only a
subset of these are inherently attacker-relevant on their own; the rest
(host-interaction, linking, executable, compiler, ...) describe ordinary
program behavior present in virtually all software."""
from __future__ import annotations
import json as _json
from malagent.contracts import AnalysisState, Provenance, Sample
from malagent.tools import CapaTool


def _sample():
    return Sample(sha256="a" * 64, md5="b" * 32, path="/tmp/x.malz",
                  file_type="PE", size=10, provenance=Provenance())


def _state():
    return AnalysisState(run_id="r1", sample=_sample())


def _fake_capa_run(rules: dict):
    class _Result:
        stdout = _json.dumps({"rules": rules}).encode()

    def run(*a, **kw):
        return _Result()
    return run


def test_high_signal_namespace_gets_medium_severity(monkeypatch):
    rules = {
        "execute anti-debugging instructions": {
            "meta": {"namespace": "anti-analysis/anti-debugging/debugger-detection", "attack": []},
            "matches": [],
        }
    }
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/capa")
    monkeypatch.setattr("subprocess.run", _fake_capa_run(rules))
    sr = CapaTool().run(_state())
    assert sr.findings[0].severity == "medium"


def test_generic_namespace_gets_info_severity(monkeypatch):
    rules = {
        "read file on Windows": {
            "meta": {"namespace": "host-interaction/file-system/read", "attack": []},
            "matches": [],
        }
    }
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/capa")
    monkeypatch.setattr("subprocess.run", _fake_capa_run(rules))
    sr = CapaTool().run(_state())
    assert sr.findings[0].severity == "info"


def test_missing_namespace_defaults_to_info_severity(monkeypatch):
    rules = {"some rule": {"meta": {"attack": []}, "matches": []}}
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/capa")
    monkeypatch.setattr("subprocess.run", _fake_capa_run(rules))
    sr = CapaTool().run(_state())
    assert sr.findings[0].severity == "info"


def test_evidence_locator_embeds_top_level_namespace(monkeypatch):
    rules = {
        "execute anti-debugging instructions": {
            "meta": {"namespace": "anti-analysis/anti-debugging/debugger-detection", "attack": []},
            "matches": [],
        },
        "read file on Windows": {
            "meta": {"namespace": "host-interaction/file-system/read", "attack": []},
            "matches": [],
        },
    }
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/capa")
    monkeypatch.setattr("subprocess.run", _fake_capa_run(rules))
    sr = CapaTool().run(_state())
    locators = {ev.locator for ev in sr.evidence}
    assert "capa:anti-analysis:execute anti-debugging instructions" in locators
    assert "capa:host-interaction:read file on Windows" in locators


def test_real_notepad_rule_set_does_not_all_score_medium(monkeypatch):
    """Regression test using the real namespace values looked up from the
    capa-rules-9.4.0 corpus for the rules that actually matched notepad.exe
    live. Most must be 'info'; only the anti-analysis/collection ones stay
    'medium'."""
    rules = {
        "link function at runtime on Windows": {"meta": {"namespace": "linking/runtime-linking", "attack": []}, "matches": []},
        "create or open file": {"meta": {"namespace": "host-interaction/file-system", "attack": []}, "matches": []},
        "create process on Windows": {"meta": {"namespace": "host-interaction/process/create", "attack": []}, "matches": []},
        "hide graphical window": {"meta": {"namespace": "host-interaction/gui/window/hide", "attack": []}, "matches": []},
        "execute anti-debugging instructions": {"meta": {"namespace": "anti-analysis/anti-debugging/debugger-detection", "attack": []}, "matches": []},
        "get geographical location": {"meta": {"namespace": "collection", "attack": []}, "matches": []},
        "reference analysis tools strings": {"meta": {"namespace": "anti-analysis", "attack": []}, "matches": []},
        "parse PE header": {"meta": {"namespace": "load-code/pe", "attack": []}, "matches": []},
        "enumerate PE sections": {"meta": {"namespace": "load-code/pe", "attack": []}, "matches": []},
    }
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/capa")
    monkeypatch.setattr("subprocess.run", _fake_capa_run(rules))
    sr = CapaTool().run(_state())
    by_claim = {f.claim: f.severity for f in sr.findings}
    assert by_claim["Capability detected: link function at runtime on Windows"] == "info"
    assert by_claim["Capability detected: create or open file"] == "info"
    assert by_claim["Capability detected: create process on Windows"] == "info"
    assert by_claim["Capability detected: hide graphical window"] == "info"
    assert by_claim["Capability detected: execute anti-debugging instructions"] == "medium"
    assert by_claim["Capability detected: get geographical location"] == "medium"
    assert by_claim["Capability detected: reference analysis tools strings"] == "medium"
    assert by_claim["Capability detected: parse PE header"] == "info"
    assert by_claim["Capability detected: enumerate PE sections"] == "info"


def test_load_code_pe_structural_rules_are_low_signal(monkeypatch):
    """load-code/pe mixes benign PE-structure introspection (matched by
    notepad.exe itself, live) with genuinely risky manual-loading behavior.
    Verified against the real capa-rules-9.4.0 corpus: only a specific few
    load-code/pe rules describe actual manual code-loading/injection."""
    rules = {
        "access PE header": {"meta": {"namespace": "load-code/pe", "attack": []}, "matches": []},
        "resolve function by parsing PE exports": {"meta": {"namespace": "load-code/pe", "attack": []}, "matches": []},
        "inject DLL reflectively": {"meta": {"namespace": "load-code/pe", "attack": []}, "matches": []},
        "inspect section memory permissions": {"meta": {"namespace": "load-code/pe", "attack": []}, "matches": []},
        "rebuild import table": {"meta": {"namespace": "load-code/pe", "attack": []}, "matches": []},
    }
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/capa")
    monkeypatch.setattr("subprocess.run", _fake_capa_run(rules))
    sr = CapaTool().run(_state())
    by_claim = {f.claim: f.severity for f in sr.findings}
    assert by_claim["Capability detected: access PE header"] == "info"
    assert by_claim["Capability detected: resolve function by parsing PE exports"] == "info"
    assert by_claim["Capability detected: inject DLL reflectively"] == "medium"
    assert by_claim["Capability detected: inspect section memory permissions"] == "medium"
    assert by_claim["Capability detected: rebuild import table"] == "medium"


def test_load_code_dotnet_powershell_shellcode_stay_high_signal(monkeypatch):
    """Only load-code/pe is the mixed-signal subcategory -- the other
    load-code subcategories (dynamic runtime loading, shellcode execution)
    are consistently high-risk and unaffected by the pe-specific carve-out."""
    rules = {
        "run PowerShell expression": {"meta": {"namespace": "load-code/powershell", "attack": []}, "matches": []},
        "execute shellcode via Windows fibers": {"meta": {"namespace": "load-code/shellcode", "attack": []}, "matches": []},
    }
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/capa")
    monkeypatch.setattr("subprocess.run", _fake_capa_run(rules))
    sr = CapaTool().run(_state())
    by_claim = {f.claim: f.severity for f in sr.findings}
    assert by_claim["Capability detected: run PowerShell expression"] == "medium"
    assert by_claim["Capability detected: execute shellcode via Windows fibers"] == "medium"


def test_mbc_ids_appended_to_claim_when_present(monkeypatch):
    rules = {
        "encrypt data using rc4": {
            "meta": {
                "namespace": "data-manipulation/encryption/rc4",
                "attack": [],
                "mbc": [
                    {"id": "C0028.002", "objective": "Data Micro-behavior",
                     "behavior": "Encrypt Data", "method": "RC4"},
                ],
            },
            "matches": [],
        }
    }
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/capa")
    monkeypatch.setattr("subprocess.run", _fake_capa_run(rules))
    sr = CapaTool().run(_state())
    assert sr.findings[0].claim == "Capability detected: encrypt data using rc4 (MBC: C0028.002)"


def test_multiple_mbc_ids_sorted_and_comma_joined(monkeypatch):
    rules = {
        "some rule": {
            "meta": {
                "namespace": "host-interaction/file-system",
                "attack": [],
                "mbc": [{"id": "C0002.002"}, {"id": "C0002.001"}],
            },
            "matches": [],
        }
    }
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/capa")
    monkeypatch.setattr("subprocess.run", _fake_capa_run(rules))
    sr = CapaTool().run(_state())
    assert sr.findings[0].claim == "Capability detected: some rule (MBC: C0002.001, C0002.002)"


def test_no_mbc_data_leaves_claim_unchanged(monkeypatch):
    rules = {"some rule": {"meta": {"namespace": "host-interaction/file-system", "attack": []},
                           "matches": []}}
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/capa")
    monkeypatch.setattr("subprocess.run", _fake_capa_run(rules))
    sr = CapaTool().run(_state())
    assert sr.findings[0].claim == "Capability detected: some rule"
