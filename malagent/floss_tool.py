"""FLOSS (FLARE Obfuscated String Solver) integration: recovers strings
that are constructed or decoded at runtime -- stack strings, tight
strings, decoded strings -- invisible to StaticFeaturesTool's plain
byte-pattern extraction, which only sees strings already sitting
literally in the file.

Deliberately narrow in scope, based on live testing against real samples:
- FLOSS explicitly does not support .NET deobfuscation at all (confirmed
  live: 0 results plus an explicit upstream warning on a real AgentTesla
  .NET sample). A large fraction of commodity malware (AgentTesla,
  RedLineStealer, AsyncRAT, ...) is .NET, so this is a real, structural
  gap in what this tool can add for those families -- not a bug here.
- FLOSS's code-emulation approach is genuinely slow even on small native
  files (~57s live for a 104KB real LockBit DLL) and does not scale
  gracefully to large ones. A conservative size cap plus a hard subprocess
  timeout keep this from silently stalling the pipeline.
"""
from __future__ import annotations
import json
import shutil
import subprocess
from typing import Optional
from .contracts import AnalysisState, EvidenceRecord, Finding, IOC, StageResult
from .tools import _IOC_RX, _artifact, _id

_MAX_SIZE_BYTES = 3 * 1024 * 1024  # 3MB -- conservative; emulation cost scales with
                                   # function count, not just file size, but this keeps
                                   # worst-case pipeline stall bounded
_TIMEOUT_SECONDS = 120
_STRING_KINDS = ("stack_strings", "tight_strings", "decoded_strings")


def find_floss() -> Optional[str]:
    return shutil.which("floss")


def _is_dotnet_pe(path: str) -> Optional[bool]:
    """True if this is a .NET assembly (FLOSS can't deobfuscate these);
    False if it's a native PE; None if the file isn't a parseable PE at
    all (mirrors PEHeaderTool's fast_load approach)."""
    try:
        import pefile
    except ImportError:
        return None
    try:
        pe = pefile.PE(path, fast_load=True)
    except Exception:
        return None
    try:
        com_descriptor = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
        return com_descriptor.VirtualAddress != 0
    except (AttributeError, IndexError):
        return False


class FlossTool:
    name = "floss"

    def run(self, state: AnalysisState) -> StageResult:
        path = state.sample.path

        floss_bin = find_floss()
        if not floss_bin:
            return StageResult(stage="static", status="skipped",
                               notes="floss not on PATH -- deobfuscated string extraction "
                                     "disabled (pip install flare-floss)")

        if state.sample.size > _MAX_SIZE_BYTES:
            return StageResult(stage="static", status="skipped",
                               notes=f"sample ({state.sample.size} bytes) exceeds floss's "
                                     f"practical size cap ({_MAX_SIZE_BYTES} bytes) -- "
                                     f"emulation-based deobfuscation does not scale to large "
                                     f"files in reasonable time")

        is_dotnet = _is_dotnet_pe(path)
        if is_dotnet is None:
            return StageResult(stage="static", status="skipped",
                               notes="sample is not a parseable PE -- floss only supports PE "
                                     "format for string decoding/stackstrings")
        if is_dotnet:
            return StageResult(stage="static", status="skipped",
                               notes="sample is a .NET assembly -- floss does not support .NET "
                                     "deobfuscation (confirmed live: 0 results, explicit "
                                     "upstream warning)")

        try:
            proc = subprocess.run([floss_bin, path, "-j", "--only", "stack", "tight", "decoded"],
                                  capture_output=True, timeout=_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            return StageResult(stage="static", status="partial",
                               unresolved=[f"floss did not complete within {_TIMEOUT_SECONDS}s -- "
                                          f"deobfuscated strings not available for this sample"])

        if proc.returncode != 0:
            return StageResult(stage="static", status="partial",
                               unresolved=[f"floss exited with an error: "
                                          f"{proc.stderr.decode('utf-8', 'replace')[:300]}"])

        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError:
            return StageResult(stage="static", status="partial",
                               unresolved=["floss did not return parseable JSON output"])

        recovered: list[str] = []
        for kind in _STRING_KINDS:
            for entry in data.get("strings", {}).get(kind, []):
                s = entry.get("string", "")
                if s:
                    recovered.append(s)

        if not recovered:
            return StageResult(stage="static", status="ok",
                               notes="floss ran, found no additional stack/tight/decoded strings")

        input_ref = state.sample.sha256
        art = _artifact(self.name, input_ref, "\n".join(recovered)[:4096].encode("utf-8", "replace"))
        evidence: list[EvidenceRecord] = []
        iocs: list[IOC] = []
        seen: set[tuple[str, str]] = set()
        joined = "\n".join(recovered).encode("utf-8", "replace")
        for kind, rx in _IOC_RX.items():
            for m in rx.findall(joined)[:50]:
                val = m.decode("latin1")
                if (kind, val) in seen:
                    continue
                seen.add((kind, val))
                ev = EvidenceRecord(evidence_id=_id("ev", input_ref, "floss", kind, val),
                                    artifact_id=art.artifact_id,
                                    locator=f"floss:ioc:{kind}", excerpt=val, trust="tool")
                evidence.append(ev)
                iocs.append(IOC(type=kind, value=val, evidence=[ev.evidence_id]))

        summary_ev = EvidenceRecord(evidence_id=_id("ev", input_ref, "floss", "summary"),
                                    artifact_id=art.artifact_id, locator="floss:recovered_strings",
                                    excerpt="; ".join(recovered[:20]), trust="tool")
        evidence.append(summary_ev)
        summary_finding = Finding(
            finding_id=_id("f", input_ref, "floss", "summary"),
            claim=f"floss recovered {len(recovered)} string(s) hidden from plain static "
                  f"scanning (constructed or decoded at runtime).",
            category="capability", severity="info", confidence=0.6,
            evidence=[summary_ev.evidence_id], source_stage="static")

        return StageResult(stage="static", status="ok", findings=[summary_finding],
                           artifacts=[art], evidence=evidence, iocs=iocs,
                           notes=f"floss recovered {len(recovered)} additional string(s) "
                                 f"({len(iocs)} matched IOC patterns)")
