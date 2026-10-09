"""die (Detect It Easy, https://github.com/horsicq/DIE-engine) packer/
compiler identification. Degrades gracefully --
same pattern as CapaTool/FlossTool -- when `diec` (the CLI binary) isn't
on PATH.

NOT live-verified against a real `diec` installation: unlike
pyelftools/yara-python (pip-installable libraries this session did
install and test against), `die` ships as a standalone third-party
executable, and downloading + running an unfamiliar binary autonomously
isn't a call to make without the user present -- same discipline as
MachoTool's deliberately-scoped-down segment/import heuristics. The
JSON parsing here is modeled on DIE's documented `-j` output shape; if
the real schema differs, this needs a real-installation pass to
correct."""
from __future__ import annotations
import json
import shutil
import subprocess

from .contracts import AnalysisState, EvidenceRecord, Finding, StageResult
from .tools import _artifact, _id

# DIE classifies each detection under a `type` field; these are the ones
# that indicate the file itself has been packed/protected (as opposed to
# e.g. "Compiler", "Linker", "Installer", which are just build metadata).
_PACKING_TYPES = {"packer", "protector", "cryptor"}


class DieTool:
    """Triage-stage tool: packer/protector identification via `diec -j`.
    See module docstring for why this isn't live-verified."""
    name = "die"

    def run(self, state: AnalysisState) -> StageResult:
        if not shutil.which("diec"):
            return StageResult(
                stage="triage", status="skipped",
                unresolved=["Packer/compiler identification not performed: 'diec' "
                            "(Detect It Easy) not on PATH."],
                notes="install from https://github.com/horsicq/DIE-engine")

        try:
            result = subprocess.run(["diec", "-j", state.sample.path],
                                    capture_output=True, timeout=30)
            doc = json.loads(result.stdout.decode("utf-8", "ignore"))
        except Exception as e:
            return StageResult(stage="triage", status="error",
                               unresolved=[f"die failed: {e}"])

        input_ref = state.sample.sha256
        packers: list[str] = []
        for detect in doc.get("detects", []) or []:
            for value in detect.get("values", []) or []:
                if str(value.get("type", "")).lower() in _PACKING_TYPES:
                    name = value.get("name", "unknown")
                    version = value.get("version", "")
                    packers.append(f"{name} {version}".strip())

        art = _artifact(self.name, input_ref, json.dumps(doc, sort_keys=True).encode())
        findings: list[Finding] = []
        evidence: list[EvidenceRecord] = []
        if packers:
            packer_list = ", ".join(dict.fromkeys(packers))  # dedupe, preserve order
            ev = EvidenceRecord(evidence_id=_id("ev", input_ref, "die_packer"),
                                artifact_id=art.artifact_id, locator="die:packer",
                                excerpt=packer_list, trust="tool")
            evidence.append(ev)
            findings.append(Finding(
                finding_id=_id("f", input_ref, "die_packer"),
                claim=f"Identified as packed/protected with: {packer_list}.",
                category="capability", severity="medium", confidence=0.65,
                evidence=[ev.evidence_id], source_stage="triage"))

        return StageResult(stage="triage", status="ok", findings=findings,
                           artifacts=[art], evidence=evidence,
                           notes=f"{len(doc.get('detects', []) or [])} detection group(s)")
