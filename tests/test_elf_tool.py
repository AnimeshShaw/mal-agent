"""ELF format-specific triage (docs/TODO.md Phase 2): ELF/Mach-O samples
previously only got generic string/entropy findings from
StaticFeaturesTool -- no structural parsing at all, unlike PE's
PEHeaderTool. Uses pyelftools (already a transitive dependency here;
added as an explicit optional extra)."""
from __future__ import annotations
from malagent.contracts import AnalysisState, Provenance, Sample
from malagent.elf_tool import ElfTool


def _sample(file_type="ELF"):
    return Sample(sha256="a" * 64, md5="b" * 32, path="/tmp/x.malz",
                  file_type=file_type, size=10, provenance=Provenance())


def _state(file_type="ELF"):
    return AnalysisState(run_id="r1", sample=_sample(file_type))


def test_skips_non_elf_samples():
    sr = ElfTool().run(_state(file_type="PE"))
    assert sr.status == "skipped"


class _Sym:
    def __init__(self, name, type_="STT_FUNC", shndx="SHN_UNDEF"):
        self.name = name
        self._d = {"st_info": {"type": type_}, "st_shndx": shndx}

    def __getitem__(self, k):
        return self._d[k]


class _DynsymSection:
    def __init__(self, symbols):
        self._symbols = symbols

    def iter_symbols(self):
        return iter(self._symbols)


class _Section:
    def __init__(self, name, data):
        self.name = name
        self._data = data

    def data(self):
        return self._data


class _FakeELFFile:
    def __init__(self, stream):
        self._sections = []
        self._dynsym = None

    def num_sections(self):
        return len(self._sections)

    def iter_sections(self):
        return iter(self._sections)

    def get_section_by_name(self, name):
        if name == ".dynsym":
            return self._dynsym
        return None


def _fake_elf(sections=None, dynsym_symbols=None):
    def factory(stream):
        elf = _FakeELFFile(stream)
        elf._sections = sections or []
        if dynsym_symbols is not None:
            elf._dynsym = _DynsymSection(dynsym_symbols)
        return elf
    return factory


def _patch_elffile(monkeypatch, factory):
    import malagent.elf_tool as elf_mod
    monkeypatch.setattr(elf_mod, "_ELFFile", factory)


def test_risky_dynamic_import_flagged(monkeypatch, tmp_path):
    p = tmp_path / "sample.malz"
    p.write_bytes(b"\x7fELF" + b"\x00" * 60)
    state = _state()
    state.sample = state.sample.model_copy(update={"path": str(p)})
    symbols = [_Sym("ptrace"), _Sym("memset")]
    _patch_elffile(monkeypatch, _fake_elf(dynsym_symbols=symbols))
    sr = ElfTool().run(state)
    assert any("ptrace" in f.claim for f in sr.findings)
    assert not any("memset" in f.claim for f in sr.findings)


def test_defined_symbol_not_treated_as_import(monkeypatch, tmp_path):
    """Only SHN_UNDEF (unresolved-at-link-time) symbols are real imports --
    a locally-defined function that happens to share a risky name (e.g. the
    binary implements its own 'system' wrapper) isn't calling libc's."""
    p = tmp_path / "sample.malz"
    p.write_bytes(b"\x7fELF" + b"\x00" * 60)
    state = _state()
    state.sample = state.sample.model_copy(update={"path": str(p)})
    symbols = [_Sym("system", shndx=5)]  # defined locally, not SHN_UNDEF
    _patch_elffile(monkeypatch, _fake_elf(dynsym_symbols=symbols))
    sr = ElfTool().run(state)
    assert not any("system" in f.claim for f in sr.findings)


def test_nonstandard_section_high_entropy_flagged(monkeypatch, tmp_path):
    """A section name outside the well-known ELF set is a much stronger
    packing signal than entropy on a standard section (see .rodata below)
    -- packers like UPX rename/collapse the section table drastically."""
    import os
    p = tmp_path / "sample.malz"
    p.write_bytes(b"\x7fELF" + b"\x00" * 60)
    state = _state()
    state.sample = state.sample.model_copy(update={"path": str(p)})
    sections = [_Section("UPX1", os.urandom(512))]
    _patch_elffile(monkeypatch, _fake_elf(sections=sections))
    sr = ElfTool().run(state)
    assert any("UPX1" in f.claim and "entropy" in f.claim.lower() for f in sr.findings)


def test_standard_rodata_section_not_flagged_despite_high_entropy():
    """Real false positive, found live on a real system .so
    (libigd12umd64.so): .rodata legitimately measured entropy 7.84/8.0 --
    read-only data sections commonly hold string tables and packed
    constant data, indistinguishable from packing by entropy alone.
    Confirmed empirically against a real, completely benign ELF shared
    object before writing this test."""
    import os
    from malagent.elf_tool import ElfTool as _ET
    # exercise the real classification helper directly
    assert _ET._is_standard_section(".rodata") is True
    assert _ET._is_standard_section(".text") is True
    assert _ET._is_standard_section("UPX1") is False


def test_no_pyelftools_installed_degrades_gracefully(monkeypatch, tmp_path):
    import malagent.elf_tool as elf_mod
    monkeypatch.setattr(elf_mod, "_ELFFile", None)
    p = tmp_path / "sample.malz"
    p.write_bytes(b"\x7fELF" + b"\x00" * 60)
    state = _state()
    state.sample = state.sample.model_copy(update={"path": str(p)})
    sr = ElfTool().run(state)
    assert sr.status == "skipped"


def test_parse_failure_reports_error_not_crash(monkeypatch, tmp_path):
    def factory(stream):
        raise ValueError("not a valid ELF")
    _patch_elffile(monkeypatch, factory)
    p = tmp_path / "sample.malz"
    p.write_bytes(b"not an elf")
    state = _state()
    state.sample = state.sample.model_copy(update={"path": str(p)})
    sr = ElfTool().run(state)
    assert sr.status == "error"
