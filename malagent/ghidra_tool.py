"""Headless Ghidra adapter (M2, D12). Decompiles top-N capa-ranked functions
via `pyghidra` (in-process Python API), emitting per-function evidence.
Degrades gracefully -- same pattern as CapaTool/PEHeaderTool -- when Ghidra
isn't installed: a skipped StageResult with an explicit unresolved note, never
a silent no-op or a false 'benign'.

Ghidra >=11 no longer bundles Jython for `.py` postScripts by default (`.py`
now routes through PyGhidra, which needs a real launched Python bridge) --
confirmed live against Ghidra 12.1.2, where a subprocess+Jython-postScript
approach fails with "Ghidra was not started with PyGhidra. Python is not
available". `pyghidra` (pip-installable, named in the architecture doc
alongside `analyzeHeadless`) drives Ghidra's Java API directly from this
process instead, which is both simpler and the currently-supported path."""
from __future__ import annotations
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

from .contracts import AnalysisState, EvidenceRecord, Finding, StageResult
from .tools import _artifact, _capa_command, _id


def find_headless_ghidra() -> Optional[str]:
    """Locate analyzeHeadless via GHIDRA_HOME (preferred, explicit) or PATH.
    Used purely as an availability probe -- "is a full Ghidra install here" --
    even though the actual decompilation now goes through pyghidra rather than
    invoking this script directly."""
    home = os.getenv("GHIDRA_HOME")
    if home:
        script_name = "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"
        candidate = Path(home) / "support" / script_name
        if candidate.is_file():
            return str(candidate)
    return shutil.which("analyzeHeadless")


def rank_functions_from_capa(capa_doc: dict, limit: int) -> list[int]:
    """Rank function addresses by how many capa rules matched at that address
    (descending), breaking ties by address (ascending) for determinism.
    File-scoped matches (no address) are ignored -- there's no function to
    decompile. Returns at most `limit` addresses."""
    counts: dict[int, int] = {}
    for rule in (capa_doc or {}).get("rules", {}).values():
        for match in rule.get("matches", []) or []:
            if not match:
                continue
            location = match[0] if isinstance(match, (list, tuple)) else None
            if not isinstance(location, dict):
                continue
            if location.get("type") != "absolute":
                continue
            addr = location.get("value")
            if isinstance(addr, int):
                counts[addr] = counts.get(addr, 0) + 1
    ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    return [addr for addr, _ in ranked[: max(limit, 0)]]


class GhidraTool:
    """Static-stage tool: headless-Ghidra decompilation of top-N capa-ranked
    functions. Requires `capa` (for ranking) and Ghidra (GHIDRA_HOME) both
    present; missing either degrades to an honest `skipped`/`partial` result."""
    name = "ghidra"

    def run(self, state: AnalysisState) -> StageResult:
        if state.sample.file_type not in ("PE", "ELF", "Mach-O"):
            return StageResult(
                stage="static", status="skipped",
                notes=f"not a native executable (file type {state.sample.file_type!r}): "
                      f"nothing to decompile")
        headless = find_headless_ghidra()
        if not headless:
            return StageResult(
                stage="static", status="skipped",
                unresolved=["Headless Ghidra decompilation not run: Ghidra not found "
                            "(set GHIDRA_HOME or add analyzeHeadless to PATH)."],
                notes="install Ghidra and set GHIDRA_HOME to enable per-function decompilation")

        capa_doc, capa_error = self._load_capa_doc(state.sample.path)
        if capa_doc is None:
            if capa_error is None:
                unresolved = ["Ghidra is available but function ranking needs capa, which is "
                              "not on PATH: per-function decompilation targets could not be "
                              "selected."]
                notes = "install flare-capa to enable capa-ranked function selection"
            else:
                unresolved = [f"Ghidra is available but capa (needed for function ranking) "
                              f"failed: {capa_error}"]
                notes = "capa is on PATH but did not produce usable output"
            return StageResult(stage="static", status="partial", unresolved=unresolved, notes=notes)

        limit = state.budget.max_functions_decompiled
        addrs = rank_functions_from_capa(capa_doc, limit)
        if not addrs:
            return StageResult(
                stage="static", status="partial",
                unresolved=["capa produced no function-scoped matches: no decompilation "
                            "targets identified."])

        ghidra_home = os.getenv("GHIDRA_HOME")
        try:
            decompiled = self._decompile(ghidra_home, state.sample.path, addrs)
        except Exception as e:
            return StageResult(stage="static", status="error",
                               unresolved=[f"Headless Ghidra run failed: {e}"])

        input_ref = state.sample.sha256
        art = _artifact(self.name, input_ref, json.dumps(decompiled, sort_keys=True).encode())
        findings: list[Finding] = []
        evidence: list[EvidenceRecord] = []
        for addr_hex, info in decompiled.items():
            pseudocode = info.get("pseudocode", "")
            locator = f"function@{addr_hex}"
            ev = EvidenceRecord(evidence_id=_id("ev", input_ref, "ghidra", addr_hex),
                                artifact_id=art.artifact_id, locator=locator,
                                excerpt=pseudocode[:2000], trust="tool")
            evidence.append(ev)
            claim = f"Decompiled {locator} (capa-ranked); pseudo-code available for review."
            # Cross-reference tracing: top-N functions were previously decompiled
            # in isolation -- N unrelated snippets with no structural
            # relationship visible to the downstream Behavioral Analyst. Calls
            # restricted to OTHER addresses in this same ranked set, since a
            # caller/callee outside it has no summary to correlate with.
            callers = info.get("callers") or []
            callees = info.get("callees") or []
            if callers:
                claim += f" Called by: {', '.join(f'function@{c}' for c in callers)}."
            if callees:
                claim += f" Calls: {', '.join(f'function@{c}' for c in callees)}."
            findings.append(Finding(
                finding_id=_id("f", input_ref, "ghidra", addr_hex),
                claim=claim, category="behavior", severity="info", confidence=0.5,
                evidence=[ev.evidence_id], source_stage="static"))

        return StageResult(stage="static", status="ok", findings=findings,
                           artifacts=[art], evidence=evidence,
                           notes=f"functions_decompiled={len(decompiled)}")

    def _load_capa_doc(self, sample_path: str) -> tuple[Optional[dict], Optional[str]]:
        """Returns (doc, error). error is None only when capa genuinely isn't on
        PATH -- distinct from capa being present but failing (bad rules path,
        malformed input, timeout), which must be reported honestly rather than
        collapsed into the same 'not on PATH' message."""
        if not shutil.which("capa"):
            return None, None
        try:
            out = subprocess.run(_capa_command(sample_path),
                                 capture_output=True, timeout=300)
            return json.loads(out.stdout.decode("utf-8", "ignore")), None
        except Exception as e:
            return None, str(e)[:300]

    def _decompile(self, ghidra_home: Optional[str], sample_path: str,
                   addrs: list[int]) -> dict[str, dict]:
        """Drives Ghidra's decompiler directly via pyghidra, in-process --
        no subprocess, no script-provider version coupling. Uses an explicit
        scratch project location rather than pyghidra's default ("same
        directory as the binary"): the sample's own directory may not be
        writable (confirmed live -- fails with WinError 5 against a system
        directory), and even when it is, it's the quarantine dir, which
        shouldn't accumulate Ghidra project files alongside samples.

        Also traces call-graph edges (callers/callees) between functions in
        `addrs` -- top-N capa-ranked functions were previously decompiled in
        isolation, N unrelated snippets with no visible structural
        relationship to the downstream Behavioral Analyst. Edges to
        addresses outside `addrs` are dropped: there's no summary for the
        Behavioral Analyst to correlate an undecompiled function with.

        Returns {addr_hex: {"pseudocode": str, "callers": [addr_hex, ...],
        "callees": [addr_hex, ...]}}."""
        import pyghidra
        pyghidra.start(install_dir=ghidra_home)
        from ghidra.app.decompiler import DecompInterface
        from ghidra.util.task import ConsoleTaskMonitor

        results: dict[str, dict] = {}
        with tempfile.TemporaryDirectory(prefix="malagent_ghidra_") as project_dir, \
             pyghidra.open_program(sample_path, project_location=project_dir) as flat_api:
            program = flat_api.getCurrentProgram()
            fm = program.getFunctionManager()
            addr_factory = program.getAddressFactory()
            decompiler = DecompInterface()
            decompiler.openProgram(program)
            monitor = ConsoleTaskMonitor()
            ranked_hex = {hex(a) for a in addrs}
            try:
                for addr in addrs:
                    addr_hex = hex(addr)
                    entry = {"pseudocode": "", "callers": [], "callees": []}
                    try:
                        gaddr = addr_factory.getAddress(addr_hex)
                        func = fm.getFunctionAt(gaddr) or fm.getFunctionContaining(gaddr)
                        if func is None:
                            entry["pseudocode"] = "// no function found at this address"
                            results[addr_hex] = entry
                            continue
                        res = decompiler.decompileFunction(func, 60, monitor)
                        if res is not None and res.decompileCompleted():
                            entry["pseudocode"] = res.getDecompiledFunction().getC()
                        else:
                            entry["pseudocode"] = "// decompilation failed or timed out"
                        entry["callers"] = self._xref_hex_addrs(
                            func.getCallingFunctions(monitor), ranked_hex)
                        entry["callees"] = self._xref_hex_addrs(
                            func.getCalledFunctions(monitor), ranked_hex)
                    except Exception as e:
                        entry["pseudocode"] = f"// error: {e}"
                    results[addr_hex] = entry
            finally:
                decompiler.dispose()
        return results

    @staticmethod
    def _xref_hex_addrs(functions, ranked_hex: set) -> list[str]:
        """Converts a Ghidra FunctionSet (from getCallingFunctions/
        getCalledFunctions) into sorted hex address strings, restricted to
        addresses actually in this run's ranked/decompiled set."""
        out = []
        for f in functions or []:
            try:
                addr_hex = hex(f.getEntryPoint().getOffset())
            except Exception:
                continue
            if addr_hex in ranked_hex:
                out.append(addr_hex)
        return sorted(out)
