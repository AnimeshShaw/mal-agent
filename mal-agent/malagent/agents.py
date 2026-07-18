"""Agents: pure-ish functions (AnalysisState) -> AnalysisState (D8). The
orchestration substrate (LangGraph or linear) is therefore swappable."""
from __future__ import annotations
from typing import Optional
from .attck_reference import technique_name
from .contracts import AnalysisState, EvidenceRecord, Finding, StageResult
from .ghidra_tool import GhidraTool
from .knowngood import KnownGoodTool
from .models import ModelRouter
from .security import scan_for_injection
from .tools import StaticFeaturesTool, PEHeaderTool, CapaTool, AuthenticodeTool, _id


def _merge(state: AnalysisState, sr: StageResult) -> None:
    state.stage_results.append(sr)
    state.findings.extend(sr.findings)
    state.evidence.extend(sr.evidence)
    state.iocs.extend(sr.iocs)


def triage_agent(state: AnalysisState) -> AnalysisState:
    # KnownGoodTool runs first: a hash match is the strongest, cheapest
    # signal available, and needs to land in state.findings before the
    # orchestrator decides whether to run the expensive stages at all.
    for tool in (KnownGoodTool(), StaticFeaturesTool(), PEHeaderTool(), CapaTool(), AuthenticodeTool()):
        _merge(state, tool.run(state))
    return state


def determine_escalation_trigger(state: AnalysisState) -> Optional[str]:
    """Decide which escalation trigger (if any) the current triage evidence fires.
    Mirrors EgressPolicy.escalation_triggers's vocabulary: low_confidence,
    security_critical, ambiguous_decompile. Returns None if nothing fires."""
    grounded = [f for f in state.findings if f.evidence]
    if not grounded:
        return "ambiguous_decompile"     # nothing concrete for the local model to reason over
    if any(f.severity in ("high", "critical") for f in grounded):
        return "security_critical"
    if any(f.confidence < 0.6 for f in grounded):
        return "low_confidence"
    return None


def _ghidra_functions(state: AnalysisState) -> list[tuple[Finding, EvidenceRecord]]:
    """Findings produced by GhidraTool are identifiable structurally: static-stage
    findings whose evidence points at a `function@0x...` locator (real decompiled
    pseudo-code), as opposed to the whole-sample narrative Finding below (no
    evidence) or triage findings (different locators)."""
    ev_by_id = {e.evidence_id: e for e in state.evidence}
    pairs = []
    for f in state.findings:
        if f.source_stage != "static":
            continue
        for eid in f.evidence:
            ev = ev_by_id.get(eid)
            if ev and ev.locator.startswith("function@"):
                pairs.append((f, ev))
    return pairs


def make_static_agent(router: Optional[ModelRouter] = None, ghidra: Optional[object] = None):
    """Static reasoning stage. Runs headless-Ghidra decompilation (D12) of
    top-N capa-ranked functions first -- this works with no model configured
    at all. With a model configured and functions decompiled, it summarizes
    each function *individually*, grounding each summary in that function's own
    decompile evidence. Without decompiled functions (Ghidra unavailable) it
    falls back to a whole-sample narrative over triage capabilities; without a
    model at all it honestly reports what it could not determine."""
    ghidra = ghidra if ghidra is not None else GhidraTool()

    def static_agent(state: AnalysisState) -> AnalysisState:
        _merge(state, ghidra.run(state))

        if router is None:
            _merge(state, StageResult(
                stage="static", status="skipped",
                unresolved=["No model configured: per-function semantic analysis not performed. "
                            "Verdict rests on triage capabilities only."]))
            return state

        trigger = determine_escalation_trigger(state)
        escalate = trigger is not None and trigger in state.policy.escalation_triggers

        functions = _ghidra_functions(state)
        if functions:
            summaries: list[Finding] = []
            for gfinding, ev in functions:
                resp = router.analyze(
                    system=("You are reviewing decompiled pseudo-code from a malware sample. "
                            "Describe what this specific function does and flag anything "
                            "suspicious. Be explicit about uncertainty."),
                    untrusted_label=f"decompiled_{ev.locator}", untrusted_text=ev.excerpt or "",
                    escalate=escalate, artifact_class="pseudocode")
                if resp is None:
                    continue
                summaries.append(Finding(
                    finding_id=_id("static", state.run_id, ev.locator),
                    claim=resp.text.strip()[:1200], category="behavior", severity="info",
                    confidence=0.5, evidence=[ev.evidence_id], source_stage="static"))
            if summaries:
                _merge(state, StageResult(
                    stage="static", status="ok", findings=summaries,
                    notes=f"per-function semantic summaries: {len(summaries)}/{len(functions)}"))
            else:
                _merge(state, StageResult(
                    stage="static", status="partial",
                    unresolved=["Per-function semantic analysis unavailable for all decompiled "
                                "functions (local model down and cloud egress blocked by policy). "
                                "Treated as undetermined, not benign."]))
            return state

        # No decompiled functions (Ghidra unavailable/no targets) -> fall back to a
        # whole-sample narrative over triage capabilities.
        cap_summary = "\n".join(f"- {f.claim}" for f in state.findings[:30]) or "no capabilities found"
        resp = router.analyze(
            system=("You are a malware triage analyst. Summarize likely behavior and intent "
                    "from the capability evidence. Be explicit about uncertainty. "
                    "If evidence is insufficient, say so."),
            untrusted_label="capability_evidence", untrusted_text=cap_summary,
            escalate=escalate, artifact_class="derived")
        if resp is None:
            _merge(state, StageResult(
                stage="static", status="partial",
                unresolved=["Semantic analysis unavailable (local model down and cloud egress "
                            "blocked by policy). Treated as undetermined, not benign."]))
            return state
        f = Finding(finding_id=f"static_{state.run_id[:8]}", claim=resp.text.strip()[:1200],
                    category="behavior", severity="info", confidence=0.5,
                    evidence=[], source_stage="static")
        _merge(state, StageResult(stage="static", status="ok", findings=[f],
                                  notes=f"semantic summary via {resp.provider}/{resp.location}"))
        return state
    return static_agent


def dynamic_agent(state: AnalysisState) -> AnalysisState:
    """STUB (static-only v1). Contract present so CAPE/Cuckoo slots in later."""
    _merge(state, StageResult(
        stage="dynamic", status="skipped",
        unresolved=["Dynamic detonation not run (static-only v1). Behaviors that only "
                    "appear at runtime were not observed."]))
    return state


def ttp_agent(state: AnalysisState) -> AnalysisState:
    """Groups findings by ATT&CK technique and resolves each ID to a
    human-readable name via the local reference table (M4, deterministic
    slice -- no RAG index yet). Each technique becomes its own Finding,
    grounded in the same evidence as the findings that referenced it, so it
    survives the verifier without inventing new claims. Unknown IDs are
    reported honestly rather than silently dropped."""
    by_technique: dict[str, list[str]] = {}
    for f in state.findings:
        for t in f.attack_techniques:
            by_technique.setdefault(t, []).extend(f.evidence)
    techniques = sorted(by_technique)

    findings: list[Finding] = []
    unresolved: list[str] = []
    labels: list[str] = []
    for t in techniques:
        name = technique_name(t)
        ev_ids = sorted(set(by_technique[t]))
        if name:
            claim = f"{t} ({name}): capability evidence maps to this ATT&CK technique."
            labels.append(f"{t} ({name})")
        else:
            claim = f"{t}: capability evidence maps to this ATT&CK technique (name not in local reference table)."
            labels.append(t)
            unresolved.append(f"ATT&CK technique {t} not found in the local reference table; "
                              f"name could not be resolved.")
        findings.append(Finding(finding_id=_id("ttp", state.run_id, t), claim=claim,
                                category="ttp", severity="info", confidence=0.6,
                                evidence=ev_ids, attack_techniques=[t], source_stage="ttp"))

    notes = f"ATT&CK techniques aggregated: {len(techniques)}"
    if labels:
        notes += " :: " + ", ".join(labels)
    _merge(state, StageResult(stage="ttp", status="ok", findings=findings,
                              unresolved=unresolved, notes=notes))
    return state


def verifier_agent(state: AnalysisState) -> AnalysisState:
    """Grounding gate (D7) + injection scan (D11). Tool-derived findings need >=1
    evidence ref to survive; model-derived claims with no evidence are flagged."""
    kept: list[Finding] = []
    dropped = 0
    injection_hits: list[str] = []
    for f in state.findings:
        for ev_id in f.evidence:
            ev = next((e for e in state.evidence if e.evidence_id == ev_id), None)
            if ev and ev.excerpt:
                injection_hits += scan_for_injection(ev.excerpt)
        if f.evidence:
            f.grounded = True
            kept.append(f)
        elif f.source_stage == "static":
            f.grounded = False           # model narrative: keep but mark ungrounded
            kept.append(f)
        else:
            dropped += 1
    state.findings = kept
    sr = StageResult(stage="verify", status="ok",
                     notes=f"grounded={sum(1 for f in kept if f.grounded)}, "
                           f"ungrounded_kept={sum(1 for f in kept if not f.grounded)}, dropped={dropped}")
    if injection_hits:
        sr.unresolved.append(
            f"Possible prompt-injection markers found in extracted strings: "
            f"{sorted(set(injection_hits))}. Model-derived conclusions treated with low trust.")
    state.stage_results.append(sr)
    return state
