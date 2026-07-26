"""Top-level entry: ingest -> analyze -> persist -> verdict + report."""
from __future__ import annotations
import os
from typing import Optional
from .audit import AuditLog
from .contracts import AnalysisState, EgressPolicy, Provenance, StepBudget, Verdict
from .ingest import ingest, new_run_id
from .models import ModelRouter, build_provider
from .orchestrator import run as run_pipeline
from .reporter import build_verdict, render_markdown, render_txt, write_narrative
from .store import get_repository


def _maybe_router(state: AnalysisState, audit, local_name: str, local_model: str,
                  escalation_name: Optional[str], escalation_model: Optional[str],
                  enable_models: bool) -> Optional[ModelRouter]:
    if not enable_models:
        return None
    local = build_provider(local_name, local_model)
    # Only build an escalation provider when policy actually allows cloud --
    # ModelRouter.analyze() checks `self.escalation is not None` before
    # consulting the policy, so a non-None escalation provider still takes
    # the cloud-or-fail-closed branch on a triggered case even when
    # policy.allow_cloud is False, never falling back to the local
    # provider that's sitting right there. A user passing --no-cloud
    # (expecting pure local/offline operation) got the same degraded
    # "cloud egress blocked" result as someone with no credentials at
    # all -- live-verified. Not building the provider at all lets
    # ModelRouter's `self.escalation is None` check correctly skip
    # straight to local for every call.
    esc = (build_provider(escalation_name, escalation_model)
          if escalation_name and state.policy.allow_cloud else None)
    return ModelRouter(state, local=local, escalation=esc, audit=audit)


def analyze(path: str, *, provenance: Optional[Provenance] = None,
            policy: Optional[EgressPolicy] = None, enable_models: bool = False,
            local_provider: str = "ollama", local_model: str = "qwen2.5-coder:7b",
            escalation_provider: Optional[str] = "anthropic",
            escalation_model: Optional[str] = "claude-sonnet-4-6"):
    repo = get_repository()
    run_id = new_run_id()
    audit = AuditLog(run_id, repo)
    audit.log("ingest_start", path=path)
    sample = ingest(path, provenance=provenance)
    audit.log("sample_ingested", sha256=sample.sha256, file_type=sample.file_type,
              source=sample.provenance.source, ticket=sample.provenance.ticket_id)

    state = AnalysisState(run_id=run_id, sample=sample,
                          policy=policy or EgressPolicy(), budget=StepBudget())
    router = _maybe_router(state, audit, local_provider, local_model,
                           escalation_provider, escalation_model, enable_models)
    state = run_pipeline(state, router=router, audit=audit)

    verdict = build_verdict(state)
    audit.log("verdict", verdict=verdict.verdict, confidence=verdict.confidence)
    repo.save_run(state, verdict)
    report_md = render_markdown(state, verdict)
    narrative = write_narrative(state, verdict, router=router)
    report_txt = render_txt(state, verdict, audit, narrative)
    return state, verdict, report_md, report_txt, audit
