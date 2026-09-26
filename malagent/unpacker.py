"""Container unpacking (ML classifier plan, Phase 2). ZIP and ISO 9660 are
the two real container formats found in this project's own dataset while
auditing why the deterministic gate abstains so often: a ZIP wrapping an
ISO 9660 image wrapping a real PE payload, and a ZIP bundling a
legitimate-looking exe with real Microsoft runtime DLLs plus a couple of
oddly-named ones -- a DLL-sideloading kit. Neither ever reached any
classifier before this, since nothing unpacked containers; every other
tool operates on the outer container's raw bytes, which don't parse as a
PE at all.

ISO-in-ZIP specifically is a documented real evasion technique: ISO
mounting historically didn't propagate the Windows Mark-of-the-Web flag
the way ZIP extraction does. Recursion is depth- and size-bounded (a
zip-bomb is a real DoS risk for any tool that extracts nested archives)."""
from __future__ import annotations
import io
import zipfile
from dataclasses import dataclass

from .contracts import AnalysisState, EvidenceRecord, Finding, StageResult
from .tools import _artifact, _id

try:
    import pefile
except Exception:
    pefile = None

try:
    import pycdlib
except Exception:
    pycdlib = None

# Same risky-import set PEHeaderTool checks -- kept in sync deliberately
# (duplicated rather than imported, since PEHeaderTool's copy is a private
# module-level constant not meant as a shared public API).
_RISKY_IMPORTS = {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
                  "SetWindowsHookEx", "GetAsyncKeyState", "URLDownloadToFile",
                  "WinExec", "ShellExecuteA", "CryptEncrypt"}

_MAX_DEPTH = 5
_MAX_TOTAL_BYTES = 200 * 1024 * 1024  # zip-bomb guard
_MAX_FILES = 200


def _is_zip(data: bytes) -> bool:
    return data[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")


def _is_office_openxml(data: bytes) -> bool:
    """Office Open XML formats (.xlsx/.docx/.pptx) ARE zip archives under
    the hood -- confirmed by reading a real .xlsx entry out of a real
    sample in this project's own dataset. Without this check, a plain
    ordinary spreadsheet bundled alongside an exe (extremely common --
    any ZIP that bundles a report with its data) gets recursed into and
    misreported as a suspicious nested container. The root marker
    '[Content_Types].xml' is specific to this format and never appears
    in a genuine evasion-shaped nested ISO/ZIP-wrapping-an-executable."""
    if not _is_zip(data):
        return False
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            return "[Content_Types].xml" in zf.namelist()
    except Exception:
        return False


def _is_iso9660(data: bytes) -> bool:
    return len(data) >= 0x8006 and data[0x8001:0x8006] == b"CD001"


@dataclass
class _Budget:
    total_bytes: int = 0
    total_files: int = 0
    depth_exceeded: bool = False


@dataclass
class _ExtractedFile:
    path: str  # slash-joined path showing container nesting, e.g. "invoice.iso/payload.exe"
    data: bytes


def _iter_zip_entries(data: bytes):
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            yield info.filename, zf.read(info)


def _iter_iso_entries(data: bytes):
    iso = pycdlib.PyCdlib()
    iso.open_fp(io.BytesIO(data))
    try:
        has_joliet = iso.has_joliet()
        walk_kwargs = {"joliet_path": "/"} if has_joliet else {"iso_path": "/"}
        for dirname, _dirlist, filelist in iso.walk(**walk_kwargs):
            for fname in filelist:
                full = dirname.rstrip("/") + "/" + fname
                buf = io.BytesIO()
                if has_joliet:
                    iso.get_file_from_iso_fp(buf, joliet_path=full)
                else:
                    iso.get_file_from_iso_fp(buf, iso_path=full)
                yield fname, buf.getvalue()
    finally:
        iso.close()


def _walk(name: str, data: bytes, depth: int, budget: _Budget,
          extracted: list[_ExtractedFile], nested_container_seen: list[bool]) -> None:
    if depth > _MAX_DEPTH:
        budget.depth_exceeded = True
        return
    if budget.total_bytes > _MAX_TOTAL_BYTES or budget.total_files > _MAX_FILES:
        return

    if _is_zip(data):
        if depth > 0:
            nested_container_seen[0] = True
        for inner_name, inner_data in _iter_zip_entries(data):
            budget.total_bytes += len(inner_data)
            budget.total_files += 1
            if budget.total_bytes > _MAX_TOTAL_BYTES or budget.total_files > _MAX_FILES:
                return
            child_path = f"{name}/{inner_name}"
            if _is_office_openxml(inner_data):
                extracted.append(_ExtractedFile(path=child_path, data=inner_data))
            elif _is_zip(inner_data) or _is_iso9660(inner_data):
                _walk(child_path, inner_data, depth + 1, budget, extracted, nested_container_seen)
            else:
                extracted.append(_ExtractedFile(path=child_path, data=inner_data))
        return

    if _is_iso9660(data):
        if pycdlib is None:
            return
        if depth > 0:
            nested_container_seen[0] = True
        for inner_name, inner_data in _iter_iso_entries(data):
            budget.total_bytes += len(inner_data)
            budget.total_files += 1
            if budget.total_bytes > _MAX_TOTAL_BYTES or budget.total_files > _MAX_FILES:
                return
            child_path = f"{name}/{inner_name}"
            if _is_zip(inner_data) or _is_iso9660(inner_data):
                _walk(child_path, inner_data, depth + 1, budget, extracted, nested_container_seen)
            else:
                extracted.append(_ExtractedFile(path=child_path, data=inner_data))
        return

    extracted.append(_ExtractedFile(path=name, data=data))


def extract_files(data: bytes) -> list[tuple[str, bytes]]:
    """Public, best-effort flattening of a ZIP/ISO container into
    (nested_path, bytes) pairs, with the same depth/size budget UnpackerTool
    uses. Returns [] for non-containers or anything that fails to parse --
    callers (e.g. EmberClassifierTool scoring PE payloads) treat "nothing
    extracted" as "no extra evidence", never as a verdict."""
    if not (_is_zip(data) or (_is_iso9660(data) and pycdlib is not None)):
        return []
    extracted: list[_ExtractedFile] = []
    try:
        _walk("", data, 0, _Budget(), extracted, [False])
    except Exception:
        return []
    return [(ef.path.lstrip("/"), ef.data) for ef in extracted]


def _risky_imports_in_pe(data: bytes) -> list[str]:
    if pefile is None:
        return []
    try:
        pe = pefile.PE(data=data)
        pe.parse_data_directories()
    except Exception:
        return []
    found = []
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    name = imp.name.decode("latin1")
                    if name in _RISKY_IMPORTS:
                        found.append(name)
    return sorted(set(found))


class UnpackerTool:
    """Recursively unpacks ZIP/ISO 9660 containers, surfacing what's
    inside as real evidence. Extracted PE payloads get the same
    risky-import check PEHeaderTool runs, directly on the in-memory
    bytes -- no temp file needed (pefile.PE(data=...) accepts raw
    bytes)."""
    name = "unpacker"

    def run(self, state: AnalysisState) -> StageResult:
        with open(state.sample.path, "rb") as fh:
            data = fh.read()

        if not (_is_zip(data) or _is_iso9660(data)):
            return StageResult(stage="triage", status="skipped",
                               notes="not a recognized container format (ZIP/ISO 9660)")

        if _is_iso9660(data) and not _is_zip(data) and pycdlib is None:
            return StageResult(
                stage="triage", status="skipped",
                unresolved=["ISO 9660 unpacking skipped: 'pycdlib' not installed."],
                notes="install with: pip install pycdlib")

        input_ref = state.sample.sha256
        budget = _Budget()
        extracted: list[_ExtractedFile] = []
        nested_container_seen = [False]
        try:
            _walk("", data, 0, budget, extracted, nested_container_seen)
        except Exception as e:
            return StageResult(stage="triage", status="error",
                               unresolved=[f"Container unpacking failed: {e}"])

        art = _artifact(self.name, input_ref,
                        "\n".join(ef.path for ef in extracted).encode())
        findings: list[Finding] = []
        evidence: list[EvidenceRecord] = []
        unresolved: list[str] = []

        for ef in extracted:
            display = ef.path.lstrip("/")
            ev = EvidenceRecord(evidence_id=_id("ev", input_ref, "unpack", display),
                                artifact_id=art.artifact_id, locator=f"unpacker:contains:{display}",
                                excerpt=f"{display} ({len(ef.data)} bytes)", trust="tool")
            evidence.append(ev)

            if ef.data[:2] == b"MZ":
                risky = _risky_imports_in_pe(ef.data)
                if risky:
                    findings.append(Finding(
                        finding_id=_id("f", input_ref, "unpack_risky", display),
                        claim=f"Extracted payload {display} imports {', '.join(risky)}, "
                              f"commonly used for process injection or remote execution.",
                        category="capability", severity="medium", confidence=0.6,
                        evidence=[ev.evidence_id], source_stage="triage"))

        if nested_container_seen[0]:
            findings.append(Finding(
                finding_id=_id("f", input_ref, "unpack_nested"),
                claim="Sample is a container nested inside another container "
                      "(e.g. a ZIP wrapping an ISO 9660 image) before reaching an "
                      "executable payload -- a documented delivery/evasion pattern "
                      "(ISO mounting historically bypassed the Mark-of-the-Web flag "
                      "that ZIP extraction sets).",
                category="capability", severity="medium", confidence=0.6,
                evidence=[e.evidence_id for e in evidence], source_stage="triage"))

        if budget.depth_exceeded:
            unresolved.append(f"Container unpacking stopped at max recursion depth "
                              f"({_MAX_DEPTH}); some contents may be unexamined.")
        if budget.total_bytes > _MAX_TOTAL_BYTES or budget.total_files > _MAX_FILES:
            unresolved.append(f"Container unpacking stopped: exceeded safety limits "
                              f"({_MAX_TOTAL_BYTES} bytes / {_MAX_FILES} files) -- "
                              f"possible zip-bomb; some contents may be unexamined.")

        return StageResult(stage="triage", status="ok", findings=findings,
                           artifacts=[art], evidence=evidence, unresolved=unresolved,
                           notes=f"unpacked {len(extracted)} file(s)")
