"""M6 sub-task: deterministic-only vs. +LLM ablation across the FULL
pipeline. Distinct from critic_ablation.py, which isolates verifier_critic
alone against hand-written synthetic narrative fixtures -- this harness
runs each real labeled sample through pipeline.analyze() twice: once with
enable_models=False (pure deterministic tools -- capa/FLOSS/Ghidra/PE
header analysis, no LLM stage configured at all) and once with
enable_models=True (the local/cloud LLM stage enabled: triage/static
narrative synthesis, behavioral_analyst, and verifier_critic all run for
real).

The project's central architectural invariant (see docs/V2-DESIGN.md S3
and tests/test_llm_agents_never_score.py) is that reporter.build_verdict()
is 100% deterministic: LLMs narrate, never judge. This harness checks that
invariant empirically, against real analyze() runs, rather than only via
the unit-level fixture in test_llm_agents_never_score.py. It reports:

  (a) verdict label/score drift between the two conditions -- expected to
      be exactly zero. Any non-zero count here is a critical bug elsewhere
      in the codebase (most likely in reporter.py or the pipeline wiring),
      not a calibration nuance, and format_report() flags it loudly rather
      than averaging it into a summary statistic.
  (b) narrative/evidence richness the LLM path adds -- behavioral_analyst
      narrative length and stage-reported unresolved-item counts, compared
      per sample between conditions.
  (c) wall-clock overhead of enabling the LLM stage.

Errors analyzing an individual sample (e.g. a missing external tool) are
recorded on that sample's result rather than aborting the whole run, so a
single bad sample doesn't lose all the others' data."""
from __future__ import annotations
import time
import traceback
from dataclasses import dataclass, field
from typing import Callable, Optional
from .contracts import EgressPolicy, Provenance
from .evaluation import LabeledSample


@dataclass
class SampleAblationResult:
    sample: LabeledSample
    det_verdict: str = ""
    det_confidence: float = 0.0
    llm_verdict: str = ""
    llm_confidence: float = 0.0
    det_seconds: float = 0.0
    llm_seconds: float = 0.0
    det_narrative_chars: int = 0
    llm_narrative_chars: int = 0
    det_unresolved: int = 0
    llm_unresolved: int = 0
    verdict_changed: bool = False
    confidence_changed: bool = False
    error: Optional[str] = None


@dataclass
class LlmAblationReport:
    results: list = field(default_factory=list)

    @property
    def n(self) -> int:
        return len(self.results)

    @property
    def ok_results(self) -> list:
        return [r for r in self.results if r.error is None]

    @property
    def verdict_changes(self) -> list:
        return [r for r in self.results if r.verdict_changed]

    @property
    def confidence_changes(self) -> list:
        return [r for r in self.results if r.confidence_changed]

    @property
    def errors(self) -> list:
        return [r for r in self.results if r.error is not None]

    @property
    def total_det_seconds(self) -> float:
        return sum(r.det_seconds for r in self.ok_results)

    @property
    def total_llm_seconds(self) -> float:
        return sum(r.llm_seconds for r in self.ok_results)

    @property
    def mean_det_narrative_chars(self) -> float:
        ok = self.ok_results
        return sum(r.det_narrative_chars for r in ok) / len(ok) if ok else 0.0

    @property
    def mean_llm_narrative_chars(self) -> float:
        ok = self.ok_results
        return sum(r.llm_narrative_chars for r in ok) / len(ok) if ok else 0.0


def _narrative_chars(state) -> int:
    f = next((f for f in state.findings if f.source_stage == "behavioral_analyst"), None)
    return len(f.claim) if f is not None else 0


def _unresolved_count(state) -> int:
    return sum(len(sr.unresolved) for sr in state.stage_results)


def run_llm_ablation(samples: list, *, analyze_fn: Optional[Callable] = None,
                     local_model: str = "qwen2.5-coder:7b",
                     escalation_provider: Optional[str] = None,
                     escalation_model: Optional[str] = None,
                     no_cloud: bool = True) -> LlmAblationReport:
    """Runs each sample through analyze_fn twice (enable_models=False then
    True) and compares. escalation_provider defaults to None (no cloud
    provider configured at all) so the +LLM condition is reproducible with
    only a local Ollama model -- pass a provider name explicitly to also
    exercise cloud escalation."""
    if analyze_fn is None:
        from .pipeline import analyze as analyze_fn

    total = len(samples)
    results: list[SampleAblationResult] = []
    for i, sample in enumerate(samples, start=1):
        result = SampleAblationResult(sample=sample)
        policy = EgressPolicy(allow_cloud=not no_cloud)
        try:
            t0 = time.monotonic()
            det_state, det_verdict, *_ = analyze_fn(
                sample.path, provenance=Provenance(source="dataset"),
                policy=policy, enable_models=False)
            result.det_seconds = time.monotonic() - t0
            result.det_verdict = det_verdict.verdict
            result.det_confidence = det_verdict.confidence
            result.det_narrative_chars = _narrative_chars(det_state)
            result.det_unresolved = _unresolved_count(det_state)

            t0 = time.monotonic()
            llm_state, llm_verdict, *_ = analyze_fn(
                sample.path, provenance=Provenance(source="dataset"),
                policy=policy, enable_models=True, local_model=local_model,
                escalation_provider=escalation_provider, escalation_model=escalation_model)
            result.llm_seconds = time.monotonic() - t0
            result.llm_verdict = llm_verdict.verdict
            result.llm_confidence = llm_verdict.confidence
            result.llm_narrative_chars = _narrative_chars(llm_state)
            result.llm_unresolved = _unresolved_count(llm_state)

            result.verdict_changed = result.det_verdict != result.llm_verdict
            result.confidence_changed = result.det_confidence != result.llm_confidence
            print(f"[{i}/{total}] {sample.path} (label={sample.label}) -> "
                  f"det={result.det_verdict}({result.det_confidence}) "
                  f"llm={result.llm_verdict}({result.llm_confidence}) "
                  f"changed={result.verdict_changed}", flush=True)
        except Exception as e:
            result.error = f"{type(e).__name__}: {e}"
            print(f"[{i}/{total}] {sample.path} -> ERROR: {result.error}", flush=True)
            traceback.print_exc()
        results.append(result)

    return LlmAblationReport(results=results)


def format_report(report: LlmAblationReport) -> str:
    changes = report.verdict_changes
    lines = [
        "LLM ABLATION REPORT (deterministic-only vs. +LLM)",
        "=" * 50,
        f"Samples evaluated: {report.n}"
        + (f"  (errors: {len(report.errors)})" if report.errors else ""),
        "-" * 50,
    ]
    if changes:
        lines.append(f"CRITICAL: {len(changes)} sample(s) had a DIFFERENT verdict label "
                     f"between deterministic-only and +LLM runs. Per this project's core "
                     f"invariant (LLMs narrate, never judge -- reporter.build_verdict() must "
                     f"be 100% deterministic), this should NEVER happen. This indicates a bug "
                     f"elsewhere in the codebase, not a calibration nuance.")
        for r in changes:
            lines.append(f"  - {r.sample.path}: det={r.det_verdict} -> llm={r.llm_verdict}")
    else:
        lines.append("Verdict label changes between conditions: 0 "
                     "(invariant holds on this run).")
    lines.append("-" * 50)
    conf_changes = report.confidence_changes
    lines.append(f"Confidence value changes (same label): {len(conf_changes)}")
    for r in conf_changes:
        lines.append(f"  - {r.sample.path}: det_confidence={r.det_confidence} -> "
                     f"llm_confidence={r.llm_confidence}")
    lines.append("-" * 50)
    lines.append(f"Mean behavioral_analyst narrative length: "
                f"det={report.mean_det_narrative_chars:.1f} chars, "
                f"llm={report.mean_llm_narrative_chars:.1f} chars")
    lines.append(f"Total wall-clock time: det={report.total_det_seconds:.2f}s, "
                f"llm={report.total_llm_seconds:.2f}s "
                f"(overhead: {report.total_llm_seconds - report.total_det_seconds:+.2f}s)")
    if report.errors:
        lines.append("-" * 50)
        lines.append(f"Errors ({len(report.errors)}):")
        for r in report.errors:
            lines.append(f"  - {r.sample.path}: {r.error}")
    return "\n".join(lines)
