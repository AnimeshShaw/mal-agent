"""Mach-O header identification. Deliberately
narrower than ElfTool: no segment/section entropy or import-table
heuristics here, because there is no real Mach-O binary available in this
environment (Windows) to live-verify them against -- the project's own
established discipline is not to ship heuristics that can't be checked
against real data (see ElfTool's docstring on why .rodata entropy was
excluded, found by testing against a real file). Header parsing via
Python's struct module is exact per the public Mach-O spec and needs no
live sample to validate; segment-level heuristics are left as a
documented gap rather than guessed at."""
from __future__ import annotations
import struct
from malagent.contracts import AnalysisState, Provenance, Sample
from malagent.macho_tool import MachoTool


def _sample(file_type="Mach-O"):
    return Sample(sha256="a" * 64, md5="b" * 32, path="/tmp/x.malz",
                  file_type=file_type, size=10, provenance=Provenance())


def _state(file_type="Mach-O"):
    return AnalysisState(run_id="r1", sample=_sample(file_type))


def _macho64_header(cputype, filetype, magic=0xFEEDFACF):
    # mach_header_64: magic, cputype, cpusubtype, filetype, ncmds,
    # sizeofcmds, flags, reserved -- all uint32/int32, little-endian on
    # disk for the magic value actually used (0xfeedfacf).
    return struct.pack("<IiIIIII", magic, cputype, 0, filetype, 0, 0, 0) + b"\x00" * 4


def test_skips_non_macho_samples():
    sr = MachoTool().run(_state(file_type="PE"))
    assert sr.status == "skipped"


def test_identifies_64bit_executable(tmp_path):
    p = tmp_path / "sample.malz"
    # CPU_TYPE_X86_64 = 0x01000007, MH_EXECUTE = 0x2
    p.write_bytes(_macho64_header(cputype=0x01000007, filetype=0x2))
    state = _state()
    state.sample = state.sample.model_copy(update={"path": str(p)})
    sr = MachoTool().run(state)
    assert sr.status == "ok"
    assert "x86_64" in (sr.notes or "").lower()
    assert "executable" in (sr.notes or "").lower()


def test_arm64_dylib_identified(tmp_path):
    p = tmp_path / "sample.malz"
    # CPU_TYPE_ARM64 = 0x0100000C, MH_DYLIB = 0x6
    p.write_bytes(_macho64_header(cputype=0x0100000C, filetype=0x6))
    state = _state()
    state.sample = state.sample.model_copy(update={"path": str(p)})
    sr = MachoTool().run(state)
    assert sr.status == "ok"
    assert "arm64" in (sr.notes or "").lower()
    assert "dylib" in (sr.notes or "").lower()


def test_truncated_file_reports_error_not_crash(tmp_path):
    p = tmp_path / "sample.malz"
    p.write_bytes(b"\xfe\xed\xfa\xcf\x00")  # magic only, header incomplete
    state = _state()
    state.sample = state.sample.model_copy(update={"path": str(p)})
    sr = MachoTool().run(state)
    assert sr.status == "error"


def test_no_findings_are_scored_this_is_identification_only():
    """Deliberate scope limit: header identification produces informational
    evidence, never a scored capability Finding -- there is no behavioral
    signal in "this is an x86_64 executable" on its own, unlike ElfTool's
    risky-import/entropy findings which DO score (severity=medium)."""
    import inspect
    from malagent import macho_tool
    src = inspect.getsource(macho_tool)
    assert 'severity="medium"' not in src
    assert 'severity="high"' not in src
