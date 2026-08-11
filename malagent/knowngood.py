"""Known-good hash allowlist. If a sample's SHA256 matches a trusted
reference hash (an NSRL RDS export, a curated vendor-binary list, an
organization's own known-good corpus), the sample IS -- byte for byte --
something already known to be trusted. That's a categorically stronger
signal than heuristic capability scoring, and lets the orchestrator skip the
expensive stages (Ghidra decompilation, LLM summarization) entirely rather
than run them on a file that's already resolved. Pluggable via
KNOWN_GOOD_HASHES_PATH; unset means "not configured," not "not trusted" --
absence of an allowlist is reported honestly (skipped), never silently
treated as a match either way."""
from __future__ import annotations
import os
from pathlib import Path

from .contracts import AnalysisState, EvidenceRecord, Finding, StageResult
from .tools import _id


def load_known_good_hashes(path: str) -> set[str]:
    """Reads a plain hash-per-line file or a simple 'hash,name' CSV. Missing
    file degrades to an empty set -- the caller reports that honestly via
    StageResult, it isn't an error to not have an allowlist configured."""
    p = Path(path)
    if not p.is_file():
        return set()
    hashes: set[str] = set()
    for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        first_field = line.split(",", 1)[0].strip()
        if first_field:
            hashes.add(first_field.lower())
    return hashes


class KnownGoodTool:
    """Triage-stage tool: checks the sample's SHA256 against a local
    known-good allowlist before the expensive stages run."""
    name = "known_good"

    def run(self, state: AnalysisState) -> StageResult:
        path = os.getenv("KNOWN_GOOD_HASHES_PATH")
        if not path:
            return StageResult(
                stage="triage", status="skipped",
                unresolved=["Known-good hash allowlist not configured: set "
                            "KNOWN_GOOD_HASHES_PATH to enable early exit for "
                            "trusted binaries."],
                notes="no allowlist configured")

        hashes = load_known_good_hashes(path)
        sha256 = state.sample.sha256.lower()
        if sha256 not in hashes:
            return StageResult(stage="triage", status="ok",
                               notes=f"not in known-good allowlist ({len(hashes)} entries loaded)")

        ev = EvidenceRecord(evidence_id=_id("ev", sha256, "known_good"),
                            artifact_id=_id("art", sha256, "known_good"),
                            locator="known_good:sha256", excerpt=sha256, trust="tool")
        finding = Finding(
            finding_id=_id("f", sha256, "known_good"),
            claim="Sample SHA256 matches a known-good reference hash; treated as a "
                  "trusted, previously-identified file rather than analyzed as unknown.",
            category="verdict_factor", severity="info", confidence=0.97,
            evidence=[ev.evidence_id], source_stage="triage")
        return StageResult(stage="triage", status="ok", findings=[finding], evidence=[ev],
                           notes="known-good hash match")


def is_known_good_match(state: AnalysisState) -> bool:
    """Used by the orchestrator to decide whether to skip the expensive
    stages. Category 'verdict_factor' is reserved in the frozen contracts
    for exactly this kind of dispositive, non-heuristic signal."""
    return any(f.category == "verdict_factor" for f in state.findings)
