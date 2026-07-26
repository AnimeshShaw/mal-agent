"""Reporter: deterministic, transparent verdict scoring + Markdown render.
Scoring is heuristic and evidence-gated; real calibration arrives at M6."""
from __future__ import annotations
from typing import Optional
from .contracts import AnalysisState, Finding, Verdict
from .models import ModelRouter
from .tools import _HIGH_SIGNAL_NAMESPACES
from .yara_gen import generate_yara_rules

_SEV_W = {"info": 0.0, "low": 1.0, "medium": 2.5, "high": 4.0, "critical": 6.0}

# A pile of matches within just one or two capa namespace categories
# shouldn't alone convict a sample -- those categories can themselves be
# individually false-positive-prone (e.g. anti-debugging checks are also
# used by legitimate DRM/licensing code). Verified live: notepad.exe, a
# stock benign Windows binary, hit exactly 2 distinct high-signal categories
# (anti-analysis, collection) and scored MALICIOUS at 0.9 confidence before
# this gate existed. Requiring corroboration across >=3 distinct categories
# is a heuristic improvement grounded in real namespace data, not validated
# calibration (that needs labeled malware/benign data -- M6).
_MIN_HIGH_SIGNAL_CATEGORIES = 3


def _is_packing_locator(locator: str) -> bool:
    """PEHeaderTool's entropy/overlay findings are a real, independent
    signal (the file is packed/hiding data) that a human analyst would
    weigh alongside capa's capability detections -- found live during M6
    evaluation: a real AgentTesla sample had high file+section entropy but
    only 2 distinct high-signal capa categories, landing in 'undetermined'
    despite the packing signal effectively being a third one. File entropy,
    per-section entropy, overlay detection, and DieTool's packer/protector
    identification all indicate the SAME underlying phenomenon, so they
    map to one 'packing' category, not one each -- a single packed sample
    shouldn't inflate the category count just by having multiple tools
    detect the same fact."""
    return locator == "file:entropy" or locator == "overlay:size" or locator == "die:packer" or (
        locator.startswith("section:") and locator.endswith(":entropy"))


def _high_signal_categories(state: AnalysisState, grounded: list[Finding]) -> set[str]:
    """Distinct high-signal categories backing this sample's medium+
    findings -- capa namespace categories, plus a single synthetic
    'packing' category for entropy/overlay evidence, plus single
    synthetic 'ioc_reputation'/'yara_match' categories for
    IocReputationTool's local blocklist matches and YaraMatchTool's
    third-party rule matches respectively. Trusts each tool's own
    severity decision rather than re-deriving significance independently --
    e.g. CapaTool can demote a rule within an otherwise-high-signal
    namespace (load-code/pe's benign structural rules), and re-deriving
    membership here from the locator alone would silently ignore that
    demotion."""
    ev_by_id = {e.evidence_id: e for e in state.evidence}
    categories: set[str] = set()
    for f in grounded:
        if f.severity not in ("medium", "high", "critical"):
            continue
        for eid in f.evidence:
            ev = ev_by_id.get(eid)
            if not ev:
                continue
            if ev.locator.startswith("capa:"):
                _, ns, _ = ev.locator.split(":", 2)
                if ns in _HIGH_SIGNAL_NAMESPACES:
                    categories.add(ns)
            elif _is_packing_locator(ev.locator):
                categories.add("packing")
            elif ev.locator.startswith("ioc_reputation:"):
                categories.add("ioc_reputation")
            elif ev.locator.startswith("yara_match:"):
                categories.add("yara_match")
    return categories


def _is_validly_signed(grounded: list[Finding], state: AnalysisState) -> bool:
    """A valid Authenticode signature is corroborating context, never a
    trust shortcut (AuthenticodeTool's own docstring) -- stolen/abused
    code-signing certs are a real attack vector, so this must never
    single-handedly clear the gate. But live-verified with gemma4:12b:
    on real Windows admin LOLBins (schtasks.exe, powershell.exe,
    wmic.exe), the LLM correctly reasoned from this exact evidence to
    'benign', explicitly citing the Microsoft signature as outweighing
    the borderline capability evidence, while the deterministic gate
    scored 'malicious' 0.9 -- because AuthenticodeTool's finding is
    severity='info' and _high_signal_categories() only counts medium+
    findings, making a valid signature structurally inert to the score
    despite the tool's own docstring calling it "corroborating context".
    Raising the bar by one category (not a short-circuit) closes that
    gap: a forged/stolen signature still can't buy immunity, sufficiently
    broad capability evidence can still override it."""
    for f in grounded:
        if f.category != "capability" or "valid Authenticode signature" not in f.claim:
            continue
        for eid in f.evidence:
            if any(e.evidence_id == eid and e.locator == "authenticode:status"
                  for e in state.evidence):
                return True
    return False


def build_verdict(state: AnalysisState) -> Verdict:
    grounded = [f for f in state.findings if f.grounded]
    techniques = sorted({t for f in state.findings for t in f.attack_techniques})
    unresolved = [u for sr in state.stage_results for u in sr.unresolved]

    # Known-good hash match short-circuits everything else: a cryptographic
    # match to a trusted reference is evidence about this exact file, not a
    # heuristic inference from its capabilities, and shouldn't be out-voted
    # by weaker (and individually false-positive-prone) capability findings.
    known_good = next((f for f in grounded if f.category == "verdict_factor"), None)
    if known_good is not None:
        return Verdict(
            sample_sha256=state.sample.sha256, verdict="benign",
            confidence=round(known_good.confidence, 2),
            attack_techniques=techniques, iocs=state.iocs,
            yara_rules=generate_yara_rules(state),
            key_findings=[known_good.finding_id],
            unresolved=unresolved, evidence_complete=True)

    score = sum(_SEV_W[f.severity] * f.confidence for f in grounded)
    categories = _high_signal_categories(state, grounded)
    required_categories = _MIN_HIGH_SIGNAL_CATEGORIES + (
        1 if _is_validly_signed(grounded, state) else 0)
    corroborated = len(categories) >= required_categories

    # Coverage: did we do enough deterministic analysis to trust a benign
    # call? This must NOT depend on whether an LLM happened to respond --
    # that's an availability question, not a coverage one, and conflating
    # them is exactly what caused a real M6 evaluation run to report
    # TN=0 across 21 genuinely benign samples (deep_ran was structurally
    # False for all of them because --enable-models wasn't passed, not
    # because coverage was actually insufficient). capa is the tool that
    # sources the corroboration-gate signal itself; it running "ok"
    # (whether it matched 0 or N rules -- CapaTool reports "ok" either way)
    # is real, deterministic coverage on its own, independent of any model.
    #
    # A second recurrence of the same bug class, found via a live LLM
    # ablation run: static_agent's own whole-sample-narrative fallback (used
    # when Ghidra/capa aren't available) reports its OWN
    # StageResult(stage="static", status="ok", ...) purely because the local
    # LLM happened to respond, with no artifacts and no evidence backing
    # it -- an availability signal disguised as a coverage one, same as
    # before. A model-backed static/dynamic stage's genuine tool output
    # (GhidraTool's decompiled-function artifact, FlossTool's recovered
    # evidence) still counts and strengthens the claim, but the bare "ok"
    # status alone does not: require the StageResult to actually carry
    # artifacts or evidence, not just an LLM-authored Finding.
    capa_ran = any(sr.stage == "triage" and sr.status == "ok"
                  and any(a.tool == "capa" for a in sr.artifacts)
                  for sr in state.stage_results)
    deep_ran = capa_ran or any(sr.stage in ("static", "dynamic") and sr.status == "ok"
                              and (sr.artifacts or sr.evidence)
                              for sr in state.stage_results)

    if score >= 6 and corroborated:
        verdict, conf = "malicious", min(0.9, 0.5 + score / 20)
    elif score >= 2.5 and corroborated:
        verdict, conf = "suspicious", 0.5
    elif categories:
        # some attacker-relevant signal, but not enough distinct corroboration
        # to convict -- don't guess either way, per the project's own
        # "report where you succeed and fail, don't bluff" principle.
        verdict, conf = "undetermined", 0.35
    elif grounded and deep_ran:
        verdict, conf = "benign", 0.55
    else:
        # not enough evidence/coverage to assert benign -> honest fallback
        verdict, conf = "undetermined", 0.3

    evidence_complete = bool(grounded) and deep_ran

    return Verdict(
        sample_sha256=state.sample.sha256, verdict=verdict, confidence=round(conf, 2),
        attack_techniques=techniques, iocs=state.iocs,
        yara_rules=generate_yara_rules(state),
        key_findings=[f.finding_id for f in grounded][:25],
        unresolved=unresolved, evidence_complete=evidence_complete)


# ---- narrative prose for the mandatory .txt report (M4.6) ----
# Recommendations must exist even with no model configured at all, so this is
# a plain lookup keyed on the deterministic verdict, not model output.
_RECOMMENDATIONS_BY_VERDICT = {
    "malicious": "Contain and escalate immediately: isolate the affected host, block "
                 "associated indicators at the network boundary, and hand off to incident "
                 "response.",
    "suspicious": "Escalate for manual analyst review before taking action; evidence is "
                  "consistent with malicious behavior but not corroborated enough to convict "
                  "automatically.",
    "benign": "No action required; continue routine monitoring.",
    "undetermined": "Escalate for manual analyst review; automated evidence was insufficient "
                    "to reach a confident verdict either way.",
}


def _templated_recommendations(v: Verdict) -> str:
    return _RECOMMENDATIONS_BY_VERDICT.get(v.verdict, _RECOMMENDATIONS_BY_VERDICT["undetermined"])


def _templated_summary(state: AnalysisState, v: Verdict) -> str:
    findings_note = (f"{len(v.key_findings)} grounded finding(s) contributed to this verdict."
                     if v.key_findings else "No grounded findings contributed to this verdict.")
    return (f"No narrative model was available for this analysis; this summary is generated "
            f"directly from the deterministic verdict record. Verdict: {v.verdict.upper()} "
            f"(confidence {v.confidence}). {findings_note}")


def _split_narrative_response(text: str, v: Verdict) -> tuple[str, str]:
    """A well-formed model response has both section markers, summary before
    recommendations. Anything else (a model that ignored the requested
    format) degrades to the whole response as the summary plus a templated
    recommendation -- never drop the response outright, and never leave
    recommendations empty."""
    m_sum, m_rec = "EXECUTIVE SUMMARY:", "RECOMMENDATIONS:"
    if m_sum in text and m_rec in text and text.index(m_sum) < text.index(m_rec):
        summary = text.split(m_sum, 1)[1].split(m_rec, 1)[0].strip()
        recommendations = text.split(m_rec, 1)[1].strip()
        return summary, recommendations
    return text.strip(), _templated_recommendations(v)


def write_narrative(state: AnalysisState, v: Verdict,
                    router: Optional[ModelRouter] = None) -> tuple[str, str]:
    """Executive Summary + Recommendations prose for the mandatory txt report.
    Three-tier fallback, each tier strictly weaker than the last:
    1. behavioral_analyst's narrative, if verifier_critic left it grounded --
       already fact-checked against the evidence.
    2. a fresh router call over grounded findings directly, if no verified
       narrative exists (or the sample has ungrounded/no behavioral narrative).
    3. fully templated text from the Verdict record, if no router is
       configured or the model is unavailable. The mandatory report can never
       have a missing section because a model was down."""
    narrative = next((f for f in state.findings
                      if f.source_stage == "behavioral_analyst" and f.grounded), None)
    if narrative is not None:
        label, text = "behavioral_narrative", narrative.claim
    else:
        grounded = [f for f in state.findings if f.grounded]
        if grounded:
            label = "grounded_findings"
            text = "\n".join(f"- [{f.severity}] {f.claim}" for f in grounded)
        else:
            # No grounded data at all -- still give the model a chance to
            # phrase the bare verdict record; if it degrades, tier 3 catches it.
            label = "verdict_only"
            text = (f"Verdict: {v.verdict}, confidence {v.confidence}, "
                    f"key_findings={v.key_findings}, unresolved={v.unresolved}")

    if router is not None:
        resp = router.analyze(
            system=("You are writing the Executive Summary and Recommendations sections of "
                    "a malware analysis report for a human reviewer. Respond in exactly this "
                    "format:\nEXECUTIVE SUMMARY:\n<summary>\nRECOMMENDATIONS:\n<recommendations>"),
            untrusted_label=label, untrusted_text=text,
            escalate=False, artifact_class="derived")
        if resp is not None:
            return _split_narrative_response(resp.text.strip(), v)

    return _templated_summary(state, v), _templated_recommendations(v)


def render_txt(state: AnalysisState, v: Verdict, audit, narrative: tuple[str, str]) -> str:
    """Mandatory, unabridged detailed report -- written on every run, not
    gated behind --out. Both a narrative half (write_narrative's prose)
    and a full raw-data dump for archival/compliance: every finding, every
    evidence excerpt, the complete audit log, all model calls -- nothing
    truncated the way report.md's summary view is."""
    exec_summary, recommendations = narrative
    bar = "=" * 80
    thin = "-" * 80
    L: list[str] = []

    L.append(bar)
    L.append("MAL-AGENT DETAILED ANALYSIS REPORT")
    L.append(bar)
    L.append(f"Run ID:      {state.run_id}")
    L.append(f"Generated:   {v.generated_at.isoformat()}")
    L.append(f"Sample:      sha256={state.sample.sha256}")
    L.append(f"             md5={state.sample.md5}")
    L.append(f"             type={state.sample.file_type}  size={state.sample.size} bytes")
    L.append(f"             source={state.sample.provenance.source}"
             + (f" (ticket {state.sample.provenance.ticket_id})"
                if state.sample.provenance.ticket_id else ""))
    L.append("")

    L.append(thin)
    L.append("SECTION 1: EXECUTIVE SUMMARY")
    L.append(thin)
    L.append(exec_summary)
    L.append("")

    L.append(thin)
    L.append("SECTION 2: VERDICT")
    L.append(thin)
    L.append(f"Verdict:            {v.verdict.upper()}")
    L.append(f"Confidence:         {v.confidence}")
    L.append(f"Evidence complete:  {v.evidence_complete}")
    L.append(f"ATT&CK techniques:  {', '.join(v.attack_techniques) if v.attack_techniques else '(none)'}")
    L.append(f"Family:             {v.family or '(undetermined)'}")
    L.append("")

    L.append(thin)
    L.append("SECTION 3: DETAILED FINDINGS NARRATIVE")
    L.append(thin)
    narrative_finding = next(
        (f for f in state.findings if f.source_stage == "behavioral_analyst" and f.grounded), None)
    if narrative_finding:
        L.append(narrative_finding.claim)
    else:
        L.append("No independently-verified behavioral narrative is available for this run "
                 "(see Appendix A for the raw findings this assessment is based on).")
    L.append("")

    L.append(thin)
    L.append("SECTION 4: RECOMMENDATIONS")
    L.append(thin)
    L.append(recommendations)
    L.append("")

    grounded = [f for f in state.findings if f.grounded]
    L.append(thin)
    L.append(f"APPENDIX A: ALL GROUNDED FINDINGS ({len(grounded)})")
    L.append(thin)
    if grounded:
        for f in grounded:
            L.append(f"[{f.severity}] ({f.category}, {f.source_stage or 'triage'}, "
                     f"conf={f.confidence}) {f.claim}")
            L.append(f"  evidence: {', '.join(f.evidence) if f.evidence else '(none)'}")
    else:
        L.append("(none)")
    L.append("")

    ungrounded = [f for f in state.findings if not f.grounded]
    L.append(thin)
    L.append(f"APPENDIX B: UNGROUNDED / MODEL-DERIVED FINDINGS ({len(ungrounded)})")
    L.append(thin)
    if ungrounded:
        for f in ungrounded:
            L.append(f"[{f.severity}] ({f.category}, {f.source_stage or 'triage'}, "
                     f"conf={f.confidence}) {f.claim}")
    else:
        L.append("(none)")
    L.append("")

    L.append(thin)
    L.append(f"APPENDIX C: ALL EVIDENCE RECORDS ({len(state.evidence)})")
    L.append(thin)
    for ev in state.evidence:
        L.append(f"{ev.evidence_id}  locator={ev.locator}  trust={ev.trust}")
        if ev.excerpt:
            L.append(f"  excerpt: {ev.excerpt}")
    L.append("")

    L.append(thin)
    L.append(f"APPENDIX D: IOCs ({len(v.iocs)})")
    L.append(thin)
    if v.iocs:
        for i in v.iocs:
            L.append(f"{i.type}: {i.value}")
    else:
        L.append("(none)")
    L.append("")

    L.append(thin)
    L.append("APPENDIX E: STAGE TRACE")
    L.append(thin)
    for sr in state.stage_results:
        L.append(f"[{sr.stage}] status={sr.status}" + (f"  notes={sr.notes}" if sr.notes else ""))
        for u in sr.unresolved:
            L.append(f"  unresolved: {u}")
    L.append("")

    L.append(thin)
    L.append(f"APPENDIX F: MODEL CALL LOG ({len(state.model_calls)})")
    L.append(thin)
    if state.model_calls:
        for m in state.model_calls:
            L.append(f"{m.at.isoformat()}  provider={m.provider}  model={m.model}  "
                     f"location={m.location}  egress_allowed={m.egress_allowed}  "
                     f"prompt_hash={m.prompt_hash}")
    else:
        L.append("(no model calls made)")
    L.append("")

    L.append(thin)
    L.append(f"APPENDIX G: AUDIT LOG (chain intact: {audit.verify()}, {len(audit.records)} records)")
    L.append(thin)
    for rec in audit.records:
        L.append(f"[{rec.seq}] {rec.at.isoformat()}  action={rec.action}  detail={rec.detail}")
    L.append("")

    L.append(thin)
    L.append(f"APPENDIX H: GENERATED YARA RULES ({len(v.yara_rules)})")
    L.append(thin)
    if v.yara_rules:
        for rule in v.yara_rules:
            L.append(rule)
            L.append("")
    else:
        L.append("(none)")

    L.append(bar)
    L.append("END OF REPORT")
    L.append(bar)
    return "\n".join(L)


def render_markdown(state: AnalysisState, v: Verdict) -> str:
    L = []
    L.append(f"# MAL-AGENT report — `{v.sample_sha256[:16]}…`")
    L.append("")
    L.append(f"**Verdict:** {v.verdict.upper()}  |  **Confidence:** {v.confidence}  "
             f"|  **Evidence complete:** {v.evidence_complete}")
    prov = state.sample.provenance
    L.append(f"**Sample:** {state.sample.file_type}, {state.sample.size} bytes  "
             f"|  **Source:** {prov.source}"
             + (f" (ticket {prov.ticket_id})" if prov.ticket_id else ""))
    if v.attack_techniques:
        L.append(f"**ATT&CK:** {', '.join(v.attack_techniques)}")
    L.append("")
    L.append("## Grounded findings")
    grounded = [f for f in state.findings if f.grounded]
    if grounded:
        for f in grounded:
            L.append(f"- [{f.severity}] {f.claim}  _(conf {f.confidence}, {len(f.evidence)} evidence)_")
    else:
        L.append("- _None grounded._")
    ung = [f for f in state.findings if not f.grounded]
    if ung:
        L.append("")
        L.append("## Model-derived (ungrounded — lower trust)")
        for f in ung:
            L.append(f"- {f.claim[:400]}")
    if v.iocs:
        L.append("")
        L.append("## IOCs")
        for i in v.iocs[:40]:
            L.append(f"- {i.type}: `{i.value}`")
    if v.yara_rules:
        L.append("")
        L.append("## Generated YARA rules")
        L.append("_Deterministic, from grounded literal evidence only (M4 baseline; no RAG yet)._")
        for rule in v.yara_rules:
            L.append("```yara")
            L.append(rule)
            L.append("```")
    L.append("")
    L.append("## What this analysis could NOT determine")
    if v.unresolved:
        for u in v.unresolved:
            L.append(f"- {u}")
    else:
        L.append("- _Nothing flagged as unresolved._")
    L.append("")
    L.append("## Stage trace")
    for sr in state.stage_results:
        L.append(f"- **{sr.stage}** — {sr.status}" + (f" — {sr.notes}" if sr.notes else ""))
    L.append("")
    L.append(f"_Model calls: {len(state.model_calls)} "
             f"(cloud: {sum(1 for m in state.model_calls if m.location=='cloud')}). "
             f"Scoring is heuristic pending calibration._")
    return "\n".join(L)
