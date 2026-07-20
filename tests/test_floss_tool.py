"""FLOSS integration: recovers strings constructed/decoded at runtime
(stack strings, tight strings, decoded strings) that plain byte-pattern
string extraction (StaticFeaturesTool) can't see. Deliberately narrow:
only native PE samples under a size cap -- live-verified against real
samples that FLOSS's own emulation-based approach (a) explicitly does not
support .NET deobfuscation at all (confirmed: 0 results + an explicit
upstream warning on a real AgentTesla .NET sample) and (b) is genuinely
slow even on small native files (~57s for a 104KB real LockBit DLL), so
skipping .NET and large files isn't a missed opportunity -- it avoids
wasted subprocess time for either a guaranteed-empty result or an
unbounded pipeline stall."""
from __future__ import annotations
import json
import subprocess
import pefile
from malagent.contracts import AnalysisState, Provenance, Sample
from malagent import floss_tool
from malagent.floss_tool import FlossTool, _is_dotnet_pe, find_floss


def _sample(size=1000):
    return Sample(sha256="a" * 64, md5="b" * 32, path="/tmp/x.malz",
                  file_type="PE", size=size, provenance=Provenance())


def _state(size=1000):
    return AnalysisState(run_id="r1", sample=_sample(size))


# ---------- find_floss ----------

def test_find_floss_absent_returns_none(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: None)
    assert find_floss() is None


def test_find_floss_present_returns_path(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/floss")
    assert find_floss() == "/usr/bin/floss"


# ---------- _is_dotnet_pe ----------

class _FakeDataDirectory:
    def __init__(self, va):
        self.VirtualAddress = va


class _FakeOptionalHeader:
    def __init__(self, com_descriptor_va):
        self.DATA_DIRECTORY = [_FakeDataDirectory(0)] * 14 + [_FakeDataDirectory(com_descriptor_va)]


class _FakePE:
    def __init__(self, path, fast_load=True):
        self._com_va = getattr(_FakePE, "_next_com_va", 0)

    @property
    def OPTIONAL_HEADER(self):
        return _FakeOptionalHeader(self._com_va)


def test_is_dotnet_pe_true_when_com_descriptor_present(monkeypatch):
    _FakePE._next_com_va = 0x2000
    monkeypatch.setattr(pefile, "PE", _FakePE)
    assert _is_dotnet_pe("/fake/path.exe") is True


def test_is_dotnet_pe_false_when_no_com_descriptor(monkeypatch):
    _FakePE._next_com_va = 0
    monkeypatch.setattr(pefile, "PE", _FakePE)
    assert _is_dotnet_pe("/fake/path.exe") is False


def test_is_dotnet_pe_none_when_not_a_parseable_pe(monkeypatch):
    class _RaisingPE:
        def __init__(self, path, fast_load=True):
            raise Exception("not a PE")
    monkeypatch.setattr(pefile, "PE", _RaisingPE)
    assert _is_dotnet_pe("/fake/path.exe") is None


# ---------- FlossTool.run() ----------

def test_skips_when_floss_not_on_path(monkeypatch):
    monkeypatch.setattr(floss_tool, "find_floss", lambda: None)
    sr = FlossTool().run(_state())
    assert sr.status == "skipped"
    assert "not on PATH" in sr.notes


def test_skips_when_sample_exceeds_size_cap(monkeypatch):
    monkeypatch.setattr(floss_tool, "find_floss", lambda: "/usr/bin/floss")
    sr = FlossTool().run(_state(size=floss_tool._MAX_SIZE_BYTES + 1))
    assert sr.status == "skipped"
    assert "size cap" in sr.notes


def test_skips_dotnet_assemblies(monkeypatch):
    monkeypatch.setattr(floss_tool, "find_floss", lambda: "/usr/bin/floss")
    monkeypatch.setattr(floss_tool, "_is_dotnet_pe", lambda path: True)
    sr = FlossTool().run(_state())
    assert sr.status == "skipped"
    assert ".NET" in sr.notes


def test_skips_non_pe_files(monkeypatch):
    monkeypatch.setattr(floss_tool, "find_floss", lambda: "/usr/bin/floss")
    monkeypatch.setattr(floss_tool, "_is_dotnet_pe", lambda path: None)
    sr = FlossTool().run(_state())
    assert sr.status == "skipped"
    assert "PE format" in sr.notes


def _fake_floss_json(strings_by_kind):
    payload = {"strings": {k: [{"string": s} for s in v] for k, v in strings_by_kind.items()}}
    return json.dumps(payload).encode("utf-8")


def test_recovers_strings_and_extracts_iocs(monkeypatch):
    monkeypatch.setattr(floss_tool, "find_floss", lambda: "/usr/bin/floss")
    monkeypatch.setattr(floss_tool, "_is_dotnet_pe", lambda path: False)

    class _FakeProc:
        returncode = 0
        stdout = _fake_floss_json({
            "stack_strings": ["Default", "http://evil.example.top/gate.php"],
            "tight_strings": ["Global\\%.8x%.8x"],
            "decoded_strings": ["SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"],
        })
        stderr = b""

    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: _FakeProc())
    sr = FlossTool().run(_state())
    assert sr.status == "ok"
    urls = [i for i in sr.iocs if i.type == "url"]
    assert len(urls) == 1
    assert urls[0].value == "http://evil.example.top/gate.php"
    assert len(sr.findings) == 1
    assert "4 string" in sr.findings[0].claim


def test_no_strings_recovered_is_still_ok_not_an_error(monkeypatch):
    monkeypatch.setattr(floss_tool, "find_floss", lambda: "/usr/bin/floss")
    monkeypatch.setattr(floss_tool, "_is_dotnet_pe", lambda path: False)

    class _FakeProc:
        returncode = 0
        stdout = _fake_floss_json({})
        stderr = b""

    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: _FakeProc())
    sr = FlossTool().run(_state())
    assert sr.status == "ok"
    assert sr.findings == []


def test_timeout_reported_honestly_not_silently_dropped(monkeypatch):
    monkeypatch.setattr(floss_tool, "find_floss", lambda: "/usr/bin/floss")
    monkeypatch.setattr(floss_tool, "_is_dotnet_pe", lambda path: False)

    def _raise_timeout(*a, **kw):
        raise subprocess.TimeoutExpired(cmd="floss", timeout=120)

    monkeypatch.setattr(subprocess, "run", _raise_timeout)
    sr = FlossTool().run(_state())
    assert sr.status == "partial"
    assert any("did not complete" in u for u in sr.unresolved)


def test_nonzero_exit_reported_honestly(monkeypatch):
    monkeypatch.setattr(floss_tool, "find_floss", lambda: "/usr/bin/floss")
    monkeypatch.setattr(floss_tool, "_is_dotnet_pe", lambda path: False)

    class _FakeFailedProc:
        returncode = 1
        stdout = b""
        stderr = b"floss: some error"

    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: _FakeFailedProc())
    sr = FlossTool().run(_state())
    assert sr.status == "partial"
    assert any("exited with an error" in u for u in sr.unresolved)
