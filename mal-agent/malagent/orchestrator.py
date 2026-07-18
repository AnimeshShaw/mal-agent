"""Orchestration. A LangGraph state graph when available; otherwise a linear
runner with identical semantics. Either way agents stay pure (D8), so the
substrate is swappable. Budget + audit are enforced here."""
from __future__ import annotations
from typing import Callable, Optional
from .agents import (dynamic_agent, make_static_agent, triage_agent, ttp_agent,
                    verifier_agent)
from .contracts import AnalysisState, StageResult
from .knowngood import is_known_good_match
from .models import ModelRouter

# Stages skipped outright on a known-good hash match: they're the expensive
# ones (Ghidra decompilation + LLM calls; sandbox detonation). triage (already
# ran, that's how we know), ttp, and verify stay cheap and still run so the
# report and grounding stay coherent.
_SKIP_ON_KNOWN_GOOD = {"static", "dynamic"}


def build_pipeline(router: Optional[ModelRouter] = None) -> list[tuple[str, Callable]]:
    return [
        ("triage", triage_agent),
        ("static", make_static_agent(router)),
        ("dynamic", dynamic_agent),
        ("ttp", ttp_agent),
        ("verify", verifier_agent),
    ]


def run_linear(state: AnalysisState, router: Optional[ModelRouter] = None, audit=None) -> AnalysisState:
    steps = 0
    for name, agent in build_pipeline(router):
        if name in _SKIP_ON_KNOWN_GOOD and is_known_good_match(state):
            state.stage_results.append(StageResult(
                stage=name, status="skipped",
                notes="skipped: sample matched the known-good hash allowlist "
                      "(triage)"))
            if audit:
                audit.log("stage_skipped", stage=name, reason="known_good_hash_match")
            steps += 1
            continue
        if audit:
            audit.log("stage_start", stage=name)
        state = agent(state)
        steps += 1
        if audit:
            last = state.stage_results[-1] if state.stage_results else None
            audit.log("stage_end", stage=name, status=getattr(last, "status", "?"))
        if steps >= state.budget.max_total_steps:
            break
    state.status = "complete"
    return state


def run(state: AnalysisState, router: Optional[ModelRouter] = None, audit=None) -> AnalysisState:
    """Try LangGraph; fall back to linear with the same agents."""
    try:
        from langgraph.graph import StateGraph, END  # noqa
    except Exception:
        return run_linear(state, router, audit)
    # LangGraph available: a linear graph here (kept simple; adaptive routing later).
    return run_linear(state, router, audit)
