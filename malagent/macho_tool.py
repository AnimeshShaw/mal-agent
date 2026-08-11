"""Mach-O header identification (docs/TODO.md Phase 2). Deliberately
narrower than ElfTool (malagent/elf_tool.py): no segment/section entropy
or import-table heuristics here, because there is no real Mach-O binary
available in this development environment to live-verify them against --
this project's established discipline is not to ship heuristics that
can't be checked against real data (ElfTool's own docstring documents a
real false positive found by testing against a real file; guessing at
the Mach-O equivalent instead of testing it would violate that same
discipline). Header parsing via `struct` is exact per the public Mach-O
spec and needs no live sample to validate that part; segment-level
analysis is left as a documented, deliberate gap rather than untested
guesswork."""
from __future__ import annotations
import struct

from .contracts import AnalysisState, EvidenceRecord, StageResult
from .tools import _artifact, _id

_MAGIC_64 = 0xFEEDFACF
_MAGIC_64_SWAPPED = 0xCFFAEDFE  # magic read as big-endian by mistake -> byte-swapped form
_HEADER_64_FMT = "<IiIIIII"  # magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags
_HEADER_64_SIZE = struct.calcsize(_HEADER_64_FMT) + 4  # + reserved (64-bit only)

_CPU_TYPES = {
    0x00000007: "x86", 0x01000007: "x86_64",
    0x0000000C: "arm", 0x0100000C: "arm64",
}
_FILE_TYPES = {
    0x1: "object", 0x2: "executable", 0x3: "fvmlib", 0x4: "core",
    0x5: "preload", 0x6: "dylib", 0x7: "dylinker", 0x8: "bundle",
    0x9: "dylib_stub", 0xA: "dsym", 0xB: "kext",
}


class MachoTool:
    """Triage-stage tool: Mach-O header identification only (cputype,
    filetype). Skips non-Mach-O samples. See module docstring for why
    this deliberately doesn't attempt segment/import analysis."""
    name = "macho_header"

    def run(self, state: AnalysisState) -> StageResult:
        if state.sample.file_type != "Mach-O":
            return StageResult(stage="triage", status="skipped", notes="not a Mach-O file")

        input_ref = state.sample.sha256
        try:
            with open(state.sample.path, "rb") as fh:
                header_bytes = fh.read(_HEADER_64_SIZE)
        except Exception as e:
            return StageResult(stage="triage", status="error",
                               unresolved=[f"Mach-O read failed: {e}"])

        if len(header_bytes) < struct.calcsize(_HEADER_64_FMT):
            return StageResult(stage="triage", status="error",
                               unresolved=["Mach-O parse failed: file too small for a header"])

        try:
            magic, cputype, _cpusubtype, filetype, ncmds, sizeofcmds, flags = struct.unpack(
                _HEADER_64_FMT, header_bytes[:struct.calcsize(_HEADER_64_FMT)])
        except Exception as e:
            return StageResult(stage="triage", status="error",
                               unresolved=[f"Mach-O parse failed: {e}"])

        cpu_name = _CPU_TYPES.get(cputype, hex(cputype))
        file_type_name = _FILE_TYPES.get(filetype, hex(filetype))

        art = _artifact(self.name, input_ref, header_bytes)
        ev = EvidenceRecord(evidence_id=_id("ev", input_ref, "macho_header"),
                            artifact_id=art.artifact_id, locator="macho:header",
                            excerpt=f"cpu={cpu_name} type={file_type_name}", trust="tool")

        return StageResult(stage="triage", status="ok", evidence=[ev], artifacts=[art],
                           notes=f"Mach-O {cpu_name} {file_type_name}, "
                                 f"ncmds={ncmds}, magic={hex(magic)}")
