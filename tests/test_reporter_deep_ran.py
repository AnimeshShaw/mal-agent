"""'benign' verdicts require deep_ran (enough analysis coverage to trust a
clean call) -- but deep_ran previously meant "did static/dynamic report
status=ok", and static's status can only become 'ok' via a model router
successfully responding (either summarizing decompiled functions, or the
whole-sample-narrative fallback). That's an availability question
(did an LLM happen to respond), not a coverage question (did our
deterministic tools actually analyze this sample) -- and it's exactly
what caused a real M6 evaluation run to report TN=0 across 21 genuinely
benign samples: --enable-models wasn't passed, so deep_ran was
structurally False for every single one, regardless of what triage found.

Fix: deep_ran should also be satisfied by capa (the deterministic tool
that sources the corroboration-gate signal itself) having actually run,
independent of any model. CapaTool always tags its RawArtifact tool="capa"
and reports status="ok" whether it matched 0 or N rules -- this is a
structural signal, not a notes-string match."""
from __future__ import annotations
from malagent.contracts import (AnalysisState, EvidenceRecord, Finding, Provenance,
                                RawArtifact, Sample, StageResult)
from malagent.reporter import build_verdict


def _sample():
    return Sample(sha256="a" * 64, md5="b" * 32, path="/tmp/x.malz",
                  file_type="PE", size=10, provenance=Provenance())


def _capa_triage_stage_result(matched=0):
    art = RawArtifact(artifact_id="art_capa", tool="capa", input_ref="a" * 64,
                      storage_ref="artifact://art_capa")
    return StageResult(stage="triage", status="ok", artifacts=[art],
                       notes=f"capa rules matched={matched}")


def _info_finding(fid="f1"):
    return Finding(finding_id=fid, claim="Capability detected: read file", category="capability",
                  severity="info", confidence=0.7, evidence=[f"ev_{fid}"], grounded=True)


def test_capa_ran_ok_alone_reaches_benign_with_no_llm_stage_at_all():
    """The exact real bug this fixes: no --enable-models, so no static/
    dynamic stage ever reports 'ok' -- but capa DID run (deterministically,
    no LLM needed), and found nothing attacker-relevant. That must be
    enough for an honest benign call."""
    state = AnalysisState(run_id="r1", sample=_sample())
    state.findings = [_info_finding()]
    state.stage_results = [_capa_triage_stage_result(matched=5)]
    v = build_verdict(state)
    assert v.verdict == "benign"


def test_capa_never_ran_and_no_static_dynamic_stays_undetermined():
    """If capa itself never ran (not installed) AND static/dynamic never
    ran either, there genuinely isn't enough deterministic coverage to
    assert benign -- must stay undetermined, not silently default to
    benign just because grounded findings exist from some other tool."""
    state = AnalysisState(run_id="r1", sample=_sample())
    state.findings = [_info_finding()]
    state.stage_results = [StageResult(stage="triage", status="skipped",
                                       notes="capa not on PATH")]
    v = build_verdict(state)
    assert v.verdict == "undetermined"


def test_capa_skipped_status_does_not_satisfy_deep_ran():
    state = AnalysisState(run_id="r1", sample=_sample())
    state.findings = [_info_finding()]
    art = RawArtifact(artifact_id="art_capa", tool="capa", input_ref="a" * 64,
                      storage_ref="artifact://art_capa")
    state.stage_results = [StageResult(stage="triage", status="skipped", artifacts=[art])]
    v = build_verdict(state)
    assert v.verdict == "undetermined"


def test_static_ok_with_real_artifact_still_satisfies_deep_ran():
    """A genuinely deterministic static-stage tool (Ghidra/FLOSS) that ran
    and produced a real artifact is still sufficient on its own -- same as
    before this fix, but now keyed on real tool output existing, not just
    the bare status string."""
    art = RawArtifact(artifact_id="art_ghidra", tool="ghidra", input_ref="a" * 64,
                      storage_ref="artifact://art_ghidra")
    state = AnalysisState(run_id="r1", sample=_sample())
    state.findings = [_info_finding()]
    state.stage_results = [StageResult(stage="static", status="ok", artifacts=[art])]
    v = build_verdict(state)
    assert v.verdict == "benign"


def test_static_ok_from_llm_narrative_alone_does_not_satisfy_deep_ran():
    """The second recurrence of the exact bug class fixed above, via a
    different path: static_agent's own whole-sample-narrative fallback
    (used when Ghidra/capa aren't available) reports its OWN separate
    StageResult(stage="static", status="ok", findings=[...]) purely because
    the local LLM happened to respond -- no artifacts, no evidence, nothing
    deterministic backing it. Live-verified during the M6-parallel LLM
    ablation study: this let turning the LLM stage on flip a real sample's
    verdict from undetermined to benign with zero change in deterministic
    coverage. deep_ran must require real tool output (artifacts or
    evidence), not just an LLM narrative Finding with no evidence."""
    state = AnalysisState(run_id="r1", sample=_sample())
    state.findings = [_info_finding()]
    state.stage_results = [StageResult(
        stage="static", status="ok",
        findings=[Finding(finding_id="static_narr", claim="Likely benign utility.",
                          category="behavior", severity="info", confidence=0.5,
                          evidence=[], source_stage="static")])]
    v = build_verdict(state)
    assert v.verdict == "undetermined"
