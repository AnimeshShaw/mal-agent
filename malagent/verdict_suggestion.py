"""Non-binding LLM verdict-suggestion harness -- a research artifact only.

Distinct from reporter.build_verdict(): this asks an LLM to look at ALL
gathered evidence (grounded findings, ATT&CK techniques, IOCs) for a
sample and holistically guess malicious/suspicious/benign/undetermined,
with reasoning. This suggestion is NEVER used to influence the actual
verdict -- the same "LLM narrates, never judges" invariant
tests/test_llm_agents_never_score.py protects for the live pipeline holds
here by construction: nothing in this module has a path into
reporter.py or AnalysisState's scoring.

The point is measurement: does an LLM's holistic judgment correlate with
ground truth better, worse, or about the same as the deterministic score?
That's a real, answerable research question -- this harness answers it
with numbers (reusing evaluation.py's exact confusion-matrix rule via
_Counters, so the two are directly comparable) instead of assumption."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Callable, Optional
from .contracts import AnalysisState, Provenance, Verdict
from .evaluation import EvaluationReport, LabeledSample, SampleResult, _Counters
from .models import ModelRouter

_VALID_SUGGESTIONS = {"malicious", "suspicious", "benign", "undetermined"}


@dataclass
class VerdictSuggestion:
    suggested_verdict: str
    reasoning: str
    raw_response: str


def _build_evidence_summary(state: AnalysisState, v: Verdict) -> str:
    lines: list[str] = []
    for f in state.findings:
        if f.grounded:
            lines.append(f"- [{f.severity}] ({f.category}) {f.claim}")
    if v.attack_techniques:
        lines.append(f"ATT&CK techniques: {', '.join(v.attack_techniques)}")
    if v.iocs:
        lines.append(f"IOCs: {', '.join(f'{i.type}={i.value}' for i in v.iocs[:20])}")
    return "\n".join(lines) if lines else "No grounded findings."


def suggest_verdict(state: AnalysisState, v: Verdict,
                    router: Optional[ModelRouter]) -> Optional[VerdictSuggestion]:
    """Ask the model to holistically judge the sample from its evidence.
    Returns None if no router is configured or the model doesn't respond
    -- honest absence, never a fabricated guess."""
    if router is None:
        return None
    summary = _build_evidence_summary(state, v)
    resp = router.analyze(
        system=("You are a malware analyst. Given this evidence gathered from static "
                "analysis of a file, decide whether the file is malicious, suspicious, "
                "benign, or undetermined (if the evidence is genuinely insufficient to "
                "decide). Respond in exactly this format:\n"
                "VERDICT: <malicious|suspicious|benign|undetermined>\n"
                "REASONING: <your reasoning>"),
        untrusted_label="all_evidence_for_holistic_judgment", untrusted_text=summary,
        escalate=False, artifact_class="derived")
    if resp is None:
        return None

    text = resp.text.strip()
    verdict_word = None
    reasoning = text
    if "VERDICT:" in text:
        after = text.split("VERDICT:", 1)[1]
        if "REASONING:" in after:
            verdict_part, reasoning = after.split("REASONING:", 1)
        else:
            verdict_part = after
        stripped = verdict_part.strip()
        verdict_word = stripped.split()[0].lower().rstrip(".,") if stripped else None

    if verdict_word not in _VALID_SUGGESTIONS:
        # Model ignored the requested format -- degrade honestly to
        # undetermined rather than guessing which word it meant.
        return VerdictSuggestion(suggested_verdict="undetermined", reasoning=text,
                                 raw_response=text)
    return VerdictSuggestion(suggested_verdict=verdict_word, reasoning=reasoning.strip(),
                             raw_response=text)


def evaluate_llm_suggestions(samples: list[LabeledSample], *, router: Optional[ModelRouter],
                             analyze_fn: Optional[Callable] = None,
                             **analyze_kwargs) -> EvaluationReport:
    """Runs the REAL pipeline (for real evidence) then asks the LLM to
    holistically guess a verdict from that evidence -- scored against
    ground truth using the exact same rule evaluate() uses, so the two
    reports are directly comparable."""
    if analyze_fn is None:
        from .pipeline import analyze as analyze_fn

    results: list[SampleResult] = []
    counters = _Counters()
    total = len(samples)

    for i, sample in enumerate(samples, start=1):
        state, verdict, _, _, _, _ = analyze_fn(
            sample.path, provenance=Provenance(source="dataset"), **analyze_kwargs)
        suggestion = suggest_verdict(state, verdict, router)
        predicted = suggestion.suggested_verdict if suggestion is not None else "undetermined"
        results.append(SampleResult(sample=sample, predicted_verdict=predicted, confidence=0.0))
        print(f"[{i}/{total}] {sample.path} (actual={sample.label}) -> "
              f"deterministic={verdict.verdict} llm_suggests={predicted}", flush=True)
        counters.classify(predicted, sample.label)

    return counters.to_report(results)


def format_report(report: EvaluationReport) -> str:
    from .evaluation import format_report as _format
    text = _format(report)
    return text.replace("M6 EVALUATION REPORT", "LLM VERDICT-SUGGESTION REPORT (non-binding)")
