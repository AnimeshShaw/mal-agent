"""Authenticode signature check: a complementary "genuine software" signal
to the known-good hash allowlist -- answers "is this signed by a real
publisher" for files that AREN'T byte-identical to a known reference.

Deliberately kept informational (category='capability', zero-weight
severity='info'), not wired into any verdict short-circuit like the hash
allowlist: a valid signature is corroborating context, not proof of
benignity -- stolen/abused code-signing certificates are a well-documented
real attack vector (Stuxnet, SolarWinds, and many others shipped validly
signed malware). Treating "signed" as automatically trustworthy would
introduce a new false-negative risk this project has no reputation/publisher
database to responsibly calibrate against."""
from __future__ import annotations
import json
from malagent.contracts import AnalysisState, Provenance, Sample
from malagent.tools import AuthenticodeTool


def _sample():
    return Sample(sha256="a" * 64, md5="b" * 32, path=r"C:\fake\sample.exe",
                  file_type="PE", size=10, provenance=Provenance())


def _state():
    return AnalysisState(run_id="r1", sample=_sample())


def _fake_run(payload: dict):
    class _Result:
        stdout = json.dumps(payload)
        stderr = ""
    def run(*a, **kw):
        return _Result()
    return run


def test_valid_signature_reported_as_informational_finding(monkeypatch):
    monkeypatch.setattr("os.name", "nt")
    monkeypatch.setattr("subprocess.run", _fake_run(
        {"Status": 0, "StatusMessage": "Signature verified.",
         "Signer": "CN=Microsoft Windows, O=Microsoft Corporation"}))
    sr = AuthenticodeTool().run(_state())
    assert sr.status == "ok"
    assert len(sr.findings) == 1
    f = sr.findings[0]
    assert f.category == "capability"
    assert f.severity == "info"
    assert "Microsoft Windows" in f.claim
    assert "valid" in f.claim.lower()


def test_unsigned_file_reported_honestly_not_as_suspicious(monkeypatch):
    monkeypatch.setattr("os.name", "nt")
    monkeypatch.setattr("subprocess.run", _fake_run(
        {"Status": 2, "StatusMessage": "File is not digitally signed.", "Signer": None}))
    sr = AuthenticodeTool().run(_state())
    assert sr.status == "ok"
    f = sr.findings[0]
    assert f.severity == "info"
    assert "not" in f.claim.lower()


def test_never_short_circuits_verdict_like_known_good(monkeypatch):
    """Regression guard: Authenticode findings must never use category
    'verdict_factor' -- that category is reserved for dispositive signals
    (known-good hash match) and reporter.build_verdict short-circuits on it.
    A valid signature is corroborating, not dispositive."""
    monkeypatch.setattr("os.name", "nt")
    monkeypatch.setattr("subprocess.run", _fake_run(
        {"Status": 0, "StatusMessage": "Signature verified.", "Signer": "CN=Microsoft Windows"}))
    sr = AuthenticodeTool().run(_state())
    assert all(f.category != "verdict_factor" for f in sr.findings)


def test_skips_gracefully_on_non_windows(monkeypatch):
    monkeypatch.setattr("os.name", "posix")
    sr = AuthenticodeTool().run(_state())
    assert sr.status == "skipped"


def test_degrades_honestly_on_powershell_failure(monkeypatch):
    monkeypatch.setattr("os.name", "nt")

    def fail(*a, **kw):
        raise RuntimeError("powershell not found")
    monkeypatch.setattr("subprocess.run", fail)
    sr = AuthenticodeTool().run(_state())
    assert sr.status == "error"
    assert sr.unresolved
