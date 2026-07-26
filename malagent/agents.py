"""Agents: pure-ish functions (AnalysisState) -> AnalysisState (D8). The
orchestration substrate (LangGraph or linear) is therefore swappable."""
from __future__ import annotations
from typing import Optional
from .attck_reference import technique_name
from .contracts import AnalysisState, EvidenceRecord, Finding, StageResult
from .floss_tool import FlossTool
from .ghidra_tool import GhidraTool
from .elf_tool import ElfTool
from .ioc_reputation import IocReputationTool
from .knowngood import KnownGoodTool, is_known_good_match
from .models import ModelRouter
from .security import scan_for_injection
from .tools import StaticFeaturesTool, PEHeaderTool, CapaTool, AuthenticodeTool, _id


def _merge(state: AnalysisState, sr: StageResult) -> None:
    state.stage_results.append(sr)
    state.findings.extend(sr.findings)
    state.evidence.extend(sr.evidence)
    state.iocs.extend(sr.iocs)


def triage_agent(state: AnalysisState) -> AnalysisState:
    # KnownGoodTool runs first and alone: a hash match already decides the
    # verdict outright via reporter.build_verdict()'s verdict_factor
    # short-circuit, so running the remaining tools afterward is pure
    # wasted work -- live-verified: a real, allowlisted certutil.exe still
    # ran the full capa analysis (80 rules matched, 100+ seconds) for a
    # verdict that was already decided before capa even started, because
    # the orchestrator's known-good skip list only covers stages AFTER
    # triage, not triage's own remaining tools.
    _merge(state, KnownGoodTool().run(state))
    if is_known_good_match(state):
        return state
    for tool in (StaticFeaturesTool(), IocReputationTool(), PEHeaderTool(), ElfTool(),
                 CapaTool(), AuthenticodeTool()):
        _merge(state, tool.run(state))
    return state


def determine_escalation_trigger(state: AnalysisState) -> Optional[str]:
    """Decide which escalation trigger (if any) the current triage evidence fires.
    Mirrors EgressPolicy.escalation_triggers's vocabulary: low_confidence,
    security_critical, ambiguous_decompile. Returns None if nothing fires.

    Excludes behavioral_analyst's own narrative Finding: it hardcodes
    confidence=0.5 (severity="info", deliberately kept out of verdict
    scoring), but this function is also called by verifier_critic right
    after that narrative is added to state.findings. Without this
    exclusion, the narrative's own placeholder confidence value
    unconditionally self-triggers "low_confidence" for its own
    fact-check, regardless of how solid the underlying evidence actually
    is -- live-verified this meant verifier_critic ALWAYS attempted
    escalation and failed closed to "ungrounded" whenever cloud wasn't
    configured, even when the local model would say SUPPORTED."""
    grounded = [f for f in state.findings
               if f.evidence and f.source_stage != "behavioral_analyst"]
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


def make_static_agent(router: Optional[ModelRouter] = None, ghidra: Optional[object] = None,
                      floss: Optional[object] = None):
    """Static reasoning stage. Runs headless-Ghidra decompilation (D12) of
    top-N capa-ranked functions first -- this works with no model configured
    at all. With a model configured and functions decompiled, it summarizes
    each function *individually*, grounding each summary in that function's own
    decompile evidence. Without decompiled functions (Ghidra unavailable) it
    falls back to a whole-sample narrative over triage capabilities; without a
    model at all it honestly reports what it could not determine. FlossTool
    also runs here, unconditionally and independent of Ghidra/the model
    layer -- it recovers runtime-constructed strings that plain byte-pattern
    scanning misses, deterministically, so it belongs alongside Ghidra rather
    than gated behind --enable-models."""
    ghidra = ghidra if ghidra is not None else GhidraTool()
    floss = floss if floss is not None else FlossTool()

    def static_agent(state: AnalysisState) -> AnalysisState:
        _merge(state, ghidra.run(state))
        _merge(state, floss.run(state))

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


def make_behavioral_analyst(router: Optional[ModelRouter] = None):
    """Synthesizes every grounded finding accumulated by the time ttp_agent
    finishes (triage capabilities, per-function Ghidra summaries, ATT&CK
    techniques) into one coherent narrative Finding. Its evidence is the
    sorted union of every finding it drew on -- the same grounding trick
    ttp_agent already uses -- so it survives verify as genuinely grounded,
    not a bare LLM claim. severity="info" always: this narrative must never
    influence reporter.build_verdict()'s deterministic score."""
    def behavioral_analyst(state: AnalysisState) -> AnalysisState:
        if router is None:
            _merge(state, StageResult(
                stage="behavioral_analyst", status="skipped",
                unresolved=["No model configured: behavioral synthesis not performed."]))
            return state

        grounded_so_far = [f for f in state.findings if f.evidence]
        if not grounded_so_far:
            _merge(state, StageResult(
                stage="behavioral_analyst", status="skipped",
                unresolved=["No grounded findings available to synthesize a behavioral "
                            "narrative from."]))
            return state

        trigger = determine_escalation_trigger(state)
        escalate = trigger is not None and trigger in state.policy.escalation_triggers

        summary = "\n".join(f"- [{f.category}] {f.claim}" for f in grounded_so_far[:50])
        resp = router.analyze(
            system=("You are a senior malware analyst. Given this evidence (capabilities, "
                    "decompiled function summaries, ATT&CK techniques), write a coherent "
                    "narrative describing what this sample likely does and why. Be explicit "
                    "about uncertainty; do not claim more than the evidence supports."),
            untrusted_label="all_findings", untrusted_text=summary,
            escalate=escalate, artifact_class="derived")
        if resp is None:
            _merge(state, StageResult(
                stage="behavioral_analyst", status="partial",
                unresolved=["Behavioral synthesis unavailable (local model down and cloud "
                            "egress blocked by policy)."]))
            return state

        all_evidence_ids = sorted({eid for f in grounded_so_far for eid in f.evidence})
        finding = Finding(
            finding_id=_id("behavioral", state.run_id), claim=resp.text.strip()[:2000],
            category="behavior", severity="info", confidence=0.5,
            evidence=all_evidence_ids, source_stage="behavioral_analyst")
        _merge(state, StageResult(
            stage="behavioral_analyst", status="ok", findings=[finding],
            notes=f"synthesized from {len(grounded_so_far)} findings via "
                  f"{resp.provider}/{resp.location}"))
        return state
    return behavioral_analyst


def make_verifier_critic(router: Optional[ModelRouter] = None):
    """The architecture doc's originally-named Verifier/Critic role (Agent
    Role 6, MalAgentArchitecture.md S4): fact-checks the behavioral_analyst
    narrative against the evidence it cites. Distinct from verifier_agent's
    evidence-*linkage* check (does it have an evidence ID at all, no
    semantics). Must run after verifier_agent in the pipeline so its
    downgrade decision isn't clobbered by the deterministic grounding pass
    (verifier_agent unconditionally sets grounded=True for any finding with
    non-empty evidence, which the narrative always has)."""
    def verifier_critic(state: AnalysisState) -> AnalysisState:
        narrative = next((f for f in state.findings
                          if f.source_stage == "behavioral_analyst"), None)
        if narrative is None:
            state.stage_results.append(StageResult(
                stage="verifier_critic", status="skipped",
                unresolved=["No behavioral narrative to verify (behavioral_analyst did not "
                            "produce one)."]))
            return state

        if router is None:
            narrative.grounded = False
            state.stage_results.append(StageResult(
                stage="verifier_critic", status="skipped",
                unresolved=["No model configured: the behavioral narrative could not be "
                            "independently verified against its evidence and is treated as "
                            "ungrounded, not silently trusted."]))
            return state

        ev_by_id = {e.evidence_id: e for e in state.evidence}
        cited = [ev_by_id[eid] for eid in narrative.evidence if eid in ev_by_id]
        evidence_text = "\n".join(f"- ({ev.locator}) {ev.excerpt}" for ev in cited if ev.excerpt)

        trigger = determine_escalation_trigger(state)
        escalate = trigger is not None and trigger in state.policy.escalation_triggers

        prompt = f"NARRATIVE:\n{narrative.claim}\n\nEVIDENCE IT CITES:\n{evidence_text}"
        resp = router.analyze(
            system=("You are a fact-checker reviewing a malware analyst's narrative against "
                    "the raw evidence it claims to be based on. Does every claim in the "
                    "narrative have real support in the evidence? Answer with exactly one "
                    "line: either 'SUPPORTED' or 'UNSUPPORTED: <reason>'."),
            untrusted_label="narrative_and_evidence", untrusted_text=prompt,
            escalate=escalate, artifact_class="derived")
        if resp is None:
            narrative.grounded = False
            state.stage_results.append(StageResult(
                stage="verifier_critic", status="partial",
                unresolved=["The behavioral narrative could not be independently verified "
                            "(local model down and cloud egress blocked by policy) and is "
                            "treated as ungrounded, not silently trusted."]))
            return state

        verdict_line = resp.text.strip()
        sr = StageResult(stage="verifier_critic", status="ok",
                         notes=f"fact-check via {resp.provider}/{resp.location}: {verdict_line[:200]}")
        if not verdict_line.upper().startswith("SUPPORTED"):
            narrative.grounded = False
            sr.unresolved.append(f"Behavioral narrative failed independent fact-checking: {verdict_line}")
        state.stage_results.append(sr)
        return state
    return verifier_critic


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
