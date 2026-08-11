"""ELF structural triage (docs/TODO.md Phase 2): before this, ELF/Mach-O
samples only got generic string/entropy findings from StaticFeaturesTool
-- no structural parsing at all, unlike PE's PEHeaderTool. Uses
pyelftools; module-level `_ELFFile` (rather than importing inside the
function) so tests can monkeypatch it the same way tests/test_pe_header_tool.py
monkeypatches pefile.PE."""
from __future__ import annotations

from .contracts import AnalysisState, EvidenceRecord, Finding, StageResult
from .tools import _artifact, _id, _shannon

try:
    from elftools.elf.elffile import ELFFile as _ELFFile
except Exception:
    _ELFFile = None

# Linux/libc equivalents of PEHeaderTool's risky-import list: anti-debug
# (ptrace), process execution/injection, dynamic loading (common in
# loaders/packers), and memory-protection changes (common in shellcode /
# self-modifying code).
_RISKY_ELF_IMPORTS = {
    "ptrace", "execve", "execl", "execlp", "execle", "execv", "execvp",
    "system", "dlopen", "dlsym", "mprotect", "fork", "setuid", "memfd_create",
}

# Standard ELF/GNU/toolchain section names -- present in virtually every
# real-world binary, including entirely benign ones. Confirmed live: a
# real, completely benign ELF shared object (a Windows-bundled Intel
# graphics driver .so) measured .rodata at entropy 7.84/8.0 -- read-only
# data sections commonly hold string tables and packed constant data,
# indistinguishable from packing by entropy alone. A section name OUTSIDE
# this set is a much stronger packing signal (UPX and most ELF packers
# rename/collapse the section table drastically) than entropy on a
# standard section ever is.
_STANDARD_ELF_SECTIONS = {
    ".text", ".data", ".rodata", ".bss", ".comment", ".dynamic", ".dynsym",
    ".dynstr", ".symtab", ".strtab", ".init", ".fini", ".plt", ".plt.got",
    ".got", ".got.plt", ".hash", ".gnu.hash", ".gnu.version", ".gnu.version_r",
    ".eh_frame", ".eh_frame_hdr", ".gcc_except_table", ".init_array",
    ".fini_array", ".data.rel.ro", ".interp", ".shstrtab", ".note.gnu.build-id",
    ".note.abi-tag", ".rela.dyn", ".rela.plt", ".rel.dyn", ".rel.plt",
}


class ElfTool:
    """Triage-stage tool: ELF header/section/dynamic-symbol structure,
    mirroring PEHeaderTool's role for PE. Skips non-ELF samples; degrades
    gracefully (skipped, not error) when pyelftools isn't installed."""
    name = "elf_header"

    @staticmethod
    def _is_standard_section(name: str) -> bool:
        return name in _STANDARD_ELF_SECTIONS

    def run(self, state: AnalysisState) -> StageResult:
        if state.sample.file_type != "ELF":
            return StageResult(stage="triage", status="skipped", notes="not an ELF file")
        if _ELFFile is None:
            return StageResult(stage="triage", status="skipped",
                               unresolved=["ELF structural analysis not performed: "
                                           "'pyelftools' not installed."],
                               notes="install with: pip install pyelftools")

        input_ref = state.sample.sha256
        findings: list[Finding] = []
        evidence: list[EvidenceRecord] = []
        try:
            with open(state.sample.path, "rb") as fh:
                elf = _ELFFile(fh)
                findings, evidence = self._analyze(elf, input_ref)
        except Exception as e:
            return StageResult(stage="triage", status="error",
                               unresolved=[f"ELF parse failed: {e}"])

        art = _artifact(self.name, input_ref, input_ref.encode())
        return StageResult(stage="triage", status="ok", findings=findings,
                           artifacts=[art], evidence=evidence,
                           notes=f"sections={len(evidence)} evidence items")

    def _analyze(self, elf, input_ref: str) -> tuple[list[Finding], list[EvidenceRecord]]:
        findings: list[Finding] = []
        evidence: list[EvidenceRecord] = []
        art_id = _id("art", input_ref, "elf")

        dynsym = elf.get_section_by_name(".dynsym")
        if dynsym is not None:
            for sym in dynsym.iter_symbols():
                name = sym.name
                if not name or name not in _RISKY_ELF_IMPORTS:
                    continue
                if sym["st_info"]["type"] != "STT_FUNC" or sym["st_shndx"] != "SHN_UNDEF":
                    continue  # only real imports (undefined at link time), not local definitions
                ev = EvidenceRecord(evidence_id=_id("ev", input_ref, "elfimp", name),
                                    artifact_id=art_id, locator=f"elf_import:{name}",
                                    excerpt=name, trust="tool")
                evidence.append(ev)
                findings.append(Finding(
                    finding_id=_id("f", input_ref, "elfimp", name),
                    claim=f"Imports {name}, commonly used for "
                          f"{'anti-debugging' if name == 'ptrace' else 'process execution/injection or dynamic loading'}.",
                    category="capability", severity="medium", confidence=0.6,
                    evidence=[ev.evidence_id], source_stage="triage"))

        for sec in elf.iter_sections():
            name = getattr(sec, "name", "") or "<unnamed>"
            if self._is_standard_section(name):
                continue
            try:
                data = sec.data()
            except Exception:
                continue
            if not data or len(data) < 64:
                continue
            ent = _shannon(data)
            if ent <= 7.2:
                continue
            ev = EvidenceRecord(evidence_id=_id("ev", input_ref, "elfsec", name),
                                artifact_id=art_id, locator=f"elf_section:{name}:entropy",
                                excerpt=f"{ent:.2f}", trust="tool")
            evidence.append(ev)
            findings.append(Finding(
                finding_id=_id("f", input_ref, "elfsec", name),
                claim=f"Non-standard high-entropy section {name!r} ({ent:.2f}/8.0) "
                      f"suggests packed or encrypted content.",
                category="capability", severity="medium", confidence=0.6,
                evidence=[ev.evidence_id], source_stage="triage"))

        return findings, evidence
