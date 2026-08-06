"""Reporter: deterministic, transparent verdict scoring + Markdown render.
Scoring is heuristic and evidence-gated; real calibration arrives at M6."""
from __future__ import annotations
import html as _html
from typing import Literal, Optional
from .contracts import AnalysisState, Finding, Verdict
from .knowngood import is_known_good_match
from .models import ModelRouter
from .tools import _HIGH_SIGNAL_NAMESPACES
from .yara_gen import generate_yara_rules

_SEV_W = {"info": 0.0, "low": 1.0, "medium": 2.5, "high": 4.0, "critical": 6.0}

# Phase 3.5 of the ML classifier plan (docs/ML_CLASSIFIER_PLAN.md S10):
# Confidence-Gated Evidence Fusion. The real score distribution across all
# 71 real labeled samples in dataset/ showed a wide, completely empty gap
# between all-benign (max 0.0325) and all-malicious (min 0.3707) scores.
# These two thresholds carve out the zones where real data shows EMBER's
# score alone is reliable; the gap between them -- where zero real data
# points fall, exactly where a genuinely ambiguous sample would land -- is
# where the deterministic corroboration gate gets a real vote instead of
# just narrative value. Not a formal Platt/isotonic/conformal calibration
# (see the plan doc for why that's the honest next refinement, not done
# here) -- chosen with margin from the real observed gap, not guessed.
_EMBER_CONFIDENT_BENIGN_MAX = 0.05
_EMBER_CONFIDENT_MALICIOUS_MIN = 0.30

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

# Phase 3.6 (docs/ML_CLASSIFIER_PLAN.md S11): "simple" fusion mode, now the
# DEFAULT. A genuinely held-out 57-sample evaluation (zero hash/threshold
# overlap with the 71 samples used above) showed this single naive threshold
# achieves perfect precision/recall/F1 on its own (45 TP, 0 FP, 12 TN, 0 FN,
# 0 undetermined) -- and CGEF's gray-zone gate never demonstrated a case
# where it corrected a wrong EMBER call. Rather than keep the other 11
# triage tools voting on the verdict via category-counting, EMBER alone
# decides malicious/benign outright when configured; those tools' findings
# become evidence/explanation only (see render_tool_narrative below). CGEF
# is not deleted -- it's preserved as an opt-in mode (fusion_mode="cgef")
# for the unresolved "does fusion ever beat the raw model" research question.
_EMBER_SIMPLE_THRESHOLD = 0.15


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


def _locator_category(locator: str) -> Optional[str]:
    """Which single high-signal corroboration category a locator maps to,
    if any -- factored out of _high_signal_categories so the same
    per-finding classification can be reused by the verbose per-tool
    narrative (render_tool_narrative) without duplicating the mapping."""
    if locator.startswith("capa:"):
        _, ns, _ = locator.split(":", 2)
        return ns if ns in _HIGH_SIGNAL_NAMESPACES else None
    if _is_packing_locator(locator):
        return "packing"
    if locator.startswith("ioc_reputation:"):
        return "ioc_reputation"
    if locator.startswith("yara_match:"):
        return "yara_match"
    if locator.startswith("unpacker:"):
        return "unpacked_payload"
    return None


def _high_signal_categories(state: AnalysisState, grounded: list[Finding]) -> set[str]:
    """Distinct high-signal categories backing this sample's medium+
    findings -- capa namespace categories, plus a single synthetic
    'packing' category for entropy/overlay evidence, plus single
    synthetic 'ioc_reputation'/'yara_match'/'unpacked_payload' categories
    for IocReputationTool's local blocklist matches, YaraMatchTool's
    third-party rule matches, and UnpackerTool's recovered-payload/
    nested-container findings respectively. Trusts each tool's own
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
            cat = _locator_category(ev.locator)
            if cat:
                categories.add(cat)
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


def _ember_score(state: AnalysisState) -> Optional[float]:
    """EmberClassifierTool's raw P(malicious), if present -- travels as a
    plain EvidenceRecord (locator='ember:score') rather than a new frozen-
    contract field, since the value can be read directly from what already
    exists. Returns None (not 0.0) on anything malformed, so a corrupted
    record degrades to the deterministic gate rather than silently voting
    'benign'."""
    for ev in state.evidence:
        if ev.locator == "ember:score":
            try:
                return float(ev.excerpt)
            except (TypeError, ValueError):
                return None
    return None


def _named_threat_intel_override(state: AnalysisState, grounded: list[Finding]) -> bool:
    """A specific, named match -- a third-party YARA rule, or a
    high-confidence VirusTotal reputation hit (severity='high', >=5
    engines per VirusTotalTool's own existing threshold) -- is stronger,
    more specific evidence than a generic classifier probability. Gives
    the deterministic tools a genuine veto over even a confidently
    'benign' EMBER score (docs/ML_CLASSIFIER_PLAN.md S10). Deliberately
    asymmetric: no equivalent override exists in the benign direction
    beyond the known-good hash match, since no local tool here currently
    produces evidence that strong in favor of benignity."""
    ev_by_id = {e.evidence_id: e for e in state.evidence}
    for f in grounded:
        for eid in f.evidence:
            ev = ev_by_id.get(eid)
            if not ev:
                continue
            if ev.locator.startswith("yara_match:"):
                return True
            if ev.locator == "virustotal:detections" and f.severity == "high":
                return True
    return False


def _ember_decide_cgef(ember_p: float, corroborated: bool, categories: set[str]) -> tuple[str, float]:
    """Confidence-Gated Evidence Fusion (docs/ML_CLASSIFIER_PLAN.md S10),
    opt-in via fusion_mode="cgef". Trusts EMBER directly only in the two
    zones a real 71-sample measurement showed it separates classes
    perfectly; in the gray zone between them, the deterministic
    corroboration gate gets a genuine vote: strong corroboration convicts
    outright, weak corroboration produces the one deliberately-non-binary
    'suspicious' outcome CGEF allows."""
    if ember_p <= _EMBER_CONFIDENT_BENIGN_MAX:
        return "benign", round(min(0.5 + (1 - ember_p) / 2, 0.99), 2)
    if ember_p >= _EMBER_CONFIDENT_MALICIOUS_MIN:
        return "malicious", round(min(0.5 + ember_p / 2, 0.99), 2)
    if corroborated:
        return "malicious", round(min(0.5 + ember_p / 2, 0.9), 2)
    if categories:
        return "suspicious", 0.5
    return "benign", round(min(0.5 + (1 - ember_p) / 2, 0.9), 2)


def _ember_decide_simple(ember_p: float) -> tuple[str, float]:
    """"simple" fusion mode (docs/ML_CLASSIFIER_PLAN.md S11), the DEFAULT.
    EMBER alone decides, binary, no gray zone, no "suspicious" middle
    ground -- the other 11 triage tools' findings are evidence/explanation
    only in this mode, not a vote. Confidence is continuous and scaled by
    distance from the single calibrated threshold: ~0.5 right at the
    boundary (maximal uncertainty), rising toward 0.99 as the score moves
    away from it on whichever side it lands, each side scaled against its
    own available range so both directions reach the same ceiling."""
    verdict = "malicious" if ember_p >= _EMBER_SIMPLE_THRESHOLD else "benign"
    span = (1.0 - _EMBER_SIMPLE_THRESHOLD) if verdict == "malicious" else _EMBER_SIMPLE_THRESHOLD
    distance = abs(ember_p - _EMBER_SIMPLE_THRESHOLD)
    conf = round(min(0.5 + 0.49 * (distance / span), 0.99), 2) if span else 0.99
    return verdict, conf


def _fusion_mode_label(state: AnalysisState) -> str:
    """Human-readable statement of which mechanism actually decided this
    run's verdict -- the single most important transparency line in the
    report, since the answer differs by run (and by whether EMBER was
    even configured at all)."""
    if _ember_score(state) is None:
        return "n/a (no EMBER score available -- deterministic gate decided; see docs/ARCHITECTURE.md)"
    if state.fusion_mode == "cgef":
        return "cgef (opt-in) -- Confidence-Gated Evidence Fusion, docs/ML_CLASSIFIER_PLAN.md S10"
    return "simple (default) -- EMBER classifier decides alone, docs/ML_CLASSIFIER_PLAN.md S11"


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

    # Verdict decision when a real trained classifier's score is available
    # (docs/ML_CLASSIFIER_PLAN.md S11 "simple", the default; S10 "cgef",
    # opt-in). A named threat-intel override wins regardless of mode -- a
    # specific signature match is stronger evidence than any generic
    # probability. Otherwise, dispatch on state.fusion_mode.
    ember_p = _ember_score(state)
    if ember_p is not None:
        ember_finding = next((f for f in grounded
                             if any(state_ev.locator == "ember:score" for state_ev in state.evidence
                                    if state_ev.evidence_id in f.evidence)), None)
        key_findings = ([ember_finding.finding_id] if ember_finding else []) + \
            [f.finding_id for f in grounded if f is not ember_finding][:24]

        if _named_threat_intel_override(state, grounded):
            verdict, conf = "malicious", 0.9
        elif state.fusion_mode == "cgef":
            verdict, conf = _ember_decide_cgef(ember_p, corroborated, categories)
        else:
            verdict, conf = _ember_decide_simple(ember_p)

        return Verdict(
            sample_sha256=state.sample.sha256, verdict=verdict, confidence=conf,
            attack_techniques=techniques, iocs=state.iocs,
            yara_rules=generate_yara_rules(state),
            key_findings=key_findings,
            unresolved=unresolved, evidence_complete=True)

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


# ---- verbose per-tool narrative (requested directly: every tool's real
# output, in detail, with a plain-language what/why per tool and an
# honest, generic "what this indicates" per finding -- never a verdict
# word, since the analyst reading this makes that call, not this text) ----

TOOL_DESCRIPTIONS: dict[str, str] = {
    "known_good": "Checks the sample's SHA256 against a trusted-hash allowlist "
                  "(e.g. an NSRL import). A match means this exact file is already "
                  "known-trusted, and short-circuits the rest of the pipeline.",
    "static_features": "Computes whole-file Shannon entropy, extracts ASCII + "
                       "wide/UTF-16LE strings, and regex-extracts IOCs (IPs, URLs, "
                       "domains, emails, mutexes) directly from the raw bytes.",
    "ioc_reputation": "Cross-references IPs/domains/URLs already extracted by "
                      "StaticFeaturesTool against local threat-intel blocklists. "
                      "Zero network egress.",
    "unpacker": "Recursively unpacks ZIP/ISO 9660 containers, flags risky imports "
               "in any extracted PE payload, and flags suspicious multi-layer "
               "nesting (e.g. a ZIP wrapping an ISO wrapping an executable).",
    "pe_header": "Parses PE structure via pefile: imports, imphash, per-section "
                "entropy, overlay (data appended past the last section), Rich "
                "header, and .rsrc resource walking.",
    "elf_header": "Linux/ELF equivalent of pe_header: dynamic-symbol imports "
                  "(ptrace, execve, mprotect, memfd_create, ...) and non-standard-"
                  "section entropy.",
    "macho_header": "Identifies Mach-O header fields (CPU type, file type) only -- "
                    "deliberately no deeper heuristics (no real macOS sample "
                    "existed to verify a stronger check against).",
    "capa": "Matches the binary against capa's capability-detection rule corpus, "
           "mapping each match to an ATT&CK technique and/or MBC behavior. The "
           "richest single deterministic signal in the pipeline.",
    "authenticode": "Checks Windows code-signing: is the file signed, and by whom. "
                    "Corroborating context only -- never a trust short-circuit, "
                    "since stolen/abused signing certs are a real attack vector.",
    "yara_match": "Matches the sample against an operator-supplied YARA rule set -- "
                 "distinct from this project's own YARA rule *generation*, which "
                 "always runs.",
    "die": "Runs Detect It Easy (diec) to identify a specific, named packer/"
          "compiler/protector, if any.",
    "virustotal": "Looks up the file's hash against VirusTotal's aggregated "
                 "multi-engine reputation database.",
    "ember_classifier": "Runs a pretrained EMBER2024 LightGBM classifier (trained "
                        "on 3.2M real files) on the raw bytes, producing a real "
                        "P(malicious) probability. See docs/ML_CLASSIFIER_PLAN.md.",
    "ghidra": "Headless-decompiles the top-N capa-ranked functions into real "
             "pseudocode, and traces caller/callee call-graph edges between them.",
    "floss": "Recovers strings constructed or decoded at runtime (stack strings, "
            "XOR/base64-decoded-in-a-loop strings) that plain byte-pattern "
            "scanning can't see.",
    "static_llm_summary": "An LLM reads each decompiled function (or, if none were "
                          "decompiled, the whole-sample capability list) and writes "
                          "a plain-language summary. Narrative only -- severity is "
                          "always 'info', so this can never move the verdict score.",
    "dynamic_agent": "Intentional v1 stub: no sandbox detonation. Reports itself "
                     "skipped, never silently 'benign'.",
    "ttp_agent": "Groups every capability finding by ATT&CK technique ID and "
                "resolves each to its real name via a local 692-entry MITRE "
                "reference table.",
    "behavioral_analyst": "Synthesizes every grounded finding into one kill-chain-"
                          "sequenced narrative (e.g. Discovery -> Persistence -> "
                          "Defense Evasion -> C2 -> Impact), grounded in real "
                          "retrieved MITRE tactic descriptions, explicitly separating "
                          "malicious-supporting from benign/ambiguous evidence. "
                          "Narrative only -- severity is always 'info' and it is "
                          "instructed never to state a verdict word itself.",
    "verifier_agent": "The grounding gate: findings need >=1 real evidence citation "
                      "to survive; also scans evidence text for prompt-injection "
                      "patterns.",
    "verifier_critic": "An independent LLM re-reads the behavioral narrative and "
                       "its cited evidence, and can downgrade it if it finds "
                       "overclaiming.",
}


def _finding_indication(f: Finding, state: AnalysisState) -> str:
    """Honest, generic annotation of what a finding actually does inside
    the verdict-decision machinery -- never a verdict word
    ('malicious'/'benign'), and never a fabricated explanation invented
    per-claim. Mode-aware: in "simple" mode (the default), a finding's
    category-corroboration membership is real context but does NOT change
    the verdict -- EMBER alone does that -- so the text must say so
    honestly rather than reuse cgef-mode's "counts toward the gate"
    phrasing, which would be misleading once simple is the default."""
    if f.severity == "info":
        return ("Informational context only -- severity='info' carries zero weight "
                "in the deterministic scoring formula and can never affect the "
                "verdict decision.")
    ev_by_id = {e.evidence_id: e for e in state.evidence}
    for eid in f.evidence:
        ev = ev_by_id.get(eid)
        if ev and ev.locator == "ember:score":
            return ("This is the EMBER classifier score itself -- in 'simple' fusion "
                    "mode (the default) it alone decides the verdict; see Section 2.")
        if ev and (ev.locator.startswith("yara_match:")
                  or (ev.locator == "virustotal:detections" and f.severity == "high")):
            return ("Named threat-intel match -- overrides the verdict outright in "
                    "either fusion mode, regardless of the EMBER score.")
    cats = {cat for eid in f.evidence
           if (ev := ev_by_id.get(eid)) and (cat := _locator_category(ev.locator))}
    ember_present = _ember_score(state) is not None
    if cats:
        if ember_present and state.fusion_mode == "simple":
            return (f"Corroborating/contextual evidence only (category: "
                    f"{', '.join(sorted(cats))}) -- in 'simple' fusion mode (the "
                    f"default), the verdict is decided solely by the EMBER score "
                    f"above; this finding does not change it. It would count toward "
                    f"the corroboration-gate vote under --fusion-mode=cgef.")
        return (f"Counts toward the deterministic corroboration gate's category "
                f"requirement (category: {', '.join(sorted(cats))}).")
    return ("Capability evidence, but its locator doesn't map to a recognized "
           "high-signal category -- does not by itself count toward the "
           "corroboration requirement.")


def _finding_direction(f: Finding, state: AnalysisState) -> Literal[
        "supports_malicious", "supports_benign", "neutral"]:
    """Honest, structural "which way does this finding point" tag --
    derived only from facts _finding_indication() already inspects
    (severity, category, locator), never fabricated per-claim. Shown
    alongside _finding_indication() so a reader can see both what a
    finding means for scoring AND which conclusion it leans toward,
    even when (in 'simple' mode) it doesn't itself decide anything."""
    if f.category == "verdict_factor":
        return "supports_benign"
    ev_by_id = {e.evidence_id: e for e in state.evidence}
    for eid in f.evidence:
        ev = ev_by_id.get(eid)
        if not ev:
            continue
        if ev.locator == "ember:score":
            try:
                score = float(ev.excerpt)
            except (TypeError, ValueError):
                return "neutral"
            return "supports_malicious" if score >= _EMBER_SIMPLE_THRESHOLD else "supports_benign"
        if ev.locator.startswith("yara_match:"):
            return "supports_malicious"
        if ev.locator == "virustotal:detections" and f.severity == "high":
            return "supports_malicious"
    if f.severity in ("medium", "high", "critical"):
        return "supports_malicious"
    return "neutral"


def render_tool_narrative(state: AnalysisState) -> str:
    """Verbose, per-tool narrative: every canonical tool (TOOL_DESCRIPTIONS'
    key order) is accounted for unconditionally, not just the ones that
    happened to produce a StageResult. A known-good hash match short-
    circuits triage_agent after KnownGoodTool runs (agents.py), so the
    other 11 triage tools never even run -- without this, they'd simply
    vanish from the report instead of showing an honest 'skipped, here's
    why,' which would look like an omission rather than an accounted-for
    skip. Every tool gets: a static what/why description, its real status
    (or an honest reason it never ran), its real findings with what each
    one indicates AND which way it leans (never a verdict word itself --
    that call is left to the person reading this), and its real
    notes/unresolved items."""
    thin = "-" * 80
    L: list[str] = []
    by_tool: dict[str, list] = {}
    for sr in state.stage_results:
        by_tool.setdefault(sr.tool or f"(unlabeled, stage={sr.stage})", []).append(sr)

    known_good_hit = is_known_good_match(state)

    def _render_stage_result(tool_name: str, sr) -> None:
        L.append(thin)
        L.append(f"TOOL: {tool_name}  (stage: {sr.stage})")
        L.append(thin)
        desc = TOOL_DESCRIPTIONS.get(tool_name, "(no static description available for this tool)")
        L.append(f"Purpose: {desc}")
        L.append(f"Status:  {sr.status}")
        if sr.findings:
            L.append(f"Findings ({len(sr.findings)}):")
            for f in sr.findings:
                L.append(f"  [{f.severity}, confidence={f.confidence}] {f.claim}")
                L.append(f"    Indicates: {_finding_indication(f, state)}")
                L.append(f"    Direction: {_finding_direction(f, state).replace('_', ' ')}")
        else:
            L.append("Findings: (none -- no relevant findings from this tool for this sample)")
        if sr.notes:
            L.append(f"Notes: {sr.notes}")
        if sr.unresolved:
            for u in sr.unresolved:
                L.append(f"Unresolved: {u}")
        L.append("")

    for tool_name in TOOL_DESCRIPTIONS:
        srs = by_tool.pop(tool_name, None)
        if srs:
            for sr in srs:
                _render_stage_result(tool_name, sr)
            continue
        L.append(thin)
        L.append(f"TOOL: {tool_name}")
        L.append(thin)
        desc = TOOL_DESCRIPTIONS.get(tool_name, "(no static description available for this tool)")
        L.append(f"Purpose: {desc}")
        L.append("Status:  skipped")
        if known_good_hit:
            L.append("Reason:  sample matched the known-good hash allowlist, so the "
                     "rest of triage (and static/dynamic analysis) never ran -- see "
                     "Section 2.")
        else:
            L.append("Reason:  not attempted -- no StageResult was recorded for this "
                     "tool during this run.")
        L.append("")

    for tool_name, srs in by_tool.items():
        for sr in srs:
            _render_stage_result(tool_name, sr)

    return "\n".join(L)


def build_tool_report(state: AnalysisState) -> list[dict]:
    """JSON-serializable equivalent of render_tool_narrative()'s canonical
    per-tool accounting, for the web UI (docs/TODO.md Phase 8) to render
    its own ToolCard components against. Deliberately reuses the exact
    same helpers (_finding_indication, _finding_direction, TOOL_DESCRIPTIONS,
    is_known_good_match) as the text/HTML reports, so the web UI can never
    drift from what report.txt says -- this stays the single source of
    truth for "what does this finding indicate and which way does it
    lean," never duplicated in TypeScript."""
    by_tool: dict[str, list] = {}
    for sr in state.stage_results:
        by_tool.setdefault(sr.tool or f"(unlabeled, stage={sr.stage})", []).append(sr)

    known_good_hit = is_known_good_match(state)

    def _entry_for(tool_name: str, sr) -> dict:
        return {
            "tool": tool_name,
            "stage": sr.stage,
            "purpose": TOOL_DESCRIPTIONS.get(tool_name, "(no static description available for this tool)"),
            "status": sr.status,
            "reason": None,
            "notes": sr.notes,
            "unresolved": list(sr.unresolved),
            "findings": [
                {
                    "claim": f.claim,
                    "severity": f.severity,
                    "confidence": f.confidence,
                    "indicates": _finding_indication(f, state),
                    "direction": _finding_direction(f, state),
                }
                for f in sr.findings
            ],
        }

    report: list[dict] = []
    for tool_name in TOOL_DESCRIPTIONS:
        srs = by_tool.pop(tool_name, None)
        if srs:
            for sr in srs:
                report.append(_entry_for(tool_name, sr))
            continue
        reason = ("sample matched the known-good hash allowlist, so the rest of "
                 "triage (and static/dynamic analysis) never ran"
                 if known_good_hit else
                 "not attempted: no StageResult was recorded for this tool during this run")
        report.append({
            "tool": tool_name,
            "stage": None,
            "purpose": TOOL_DESCRIPTIONS.get(tool_name, "(no static description available for this tool)"),
            "status": "skipped",
            "reason": reason,
            "notes": None,
            "unresolved": [],
            "findings": [],
        })

    for tool_name, srs in by_tool.items():
        for sr in srs:
            report.append(_entry_for(tool_name, sr))

    return report


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
    L.append(f"Fusion mode:        {_fusion_mode_label(state)}")
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

    L.append(thin)
    L.append("SECTION 5: PER-TOOL DETAILED ANALYSIS")
    L.append(thin)
    L.append("Every tool, in canonical order, with what it does, its real output (or an "
             "honest reason if it didn't run), and an indication of what each finding "
             "means and which way it leans. This section is explanation, not a second "
             "vote -- the verdict above was decided by the mechanism named in Section 2, "
             "not by tallying findings here.")
    L.append("")
    L.append(render_tool_narrative(state))

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


_VERDICT_COLORS = {
    "malicious": "#c0392b", "suspicious": "#d68910", "benign": "#1e8449", "undetermined": "#5d6d7e",
}
_STATUS_COLORS = {
    "ok": "#1e8449", "partial": "#d68910", "skipped": "#7f8c8d", "error": "#c0392b",
}
_SEVERITY_COLORS = {
    "info": "#5d6d7e", "low": "#2874a6", "medium": "#d68910", "high": "#ca6f1e", "critical": "#c0392b",
}


def _e(text) -> str:
    """Escape any sample-derived text before it goes into the HTML report.
    Every Finding.claim / EvidenceRecord.excerpt / StageResult.notes and
    unresolved string traces back to -- or is derived from -- an
    untrusted malware sample, the same threat model security.py's
    scan_for_injection/wrap_untrusted defend against for LLM prompts.
    Here the risk is a report opened in a browser executing embedded
    script/HTML from a sample's own strings -- every dynamic value must
    go through this, not just the obviously long ones."""
    return _html.escape(str(text) if text is not None else "", quote=True)


def render_html(state: AnalysisState, v: Verdict, audit,
                narrative: tuple[str, str]) -> str:
    """Self-contained, offline-viewable HTML report -- no external CSS/JS/
    fonts/CDN, since an analyst may open this air-gapped. Generated
    alongside report.md/report.txt, not a replacement for either: this is
    the version meant to be read in a browser, with color-coded status/
    severity and collapsible per-tool sections; report.txt remains the
    unabridged, grep-friendly archival record."""
    exec_summary, recommendations = narrative
    verdict_color = _VERDICT_COLORS.get(v.verdict, "#5d6d7e")

    parts: list[str] = []
    parts.append(f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>MAL-AGENT report — {_e(v.sample_sha256[:16])}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, Arial, sans-serif; max-width: 960px;
         margin: 2rem auto; padding: 0 1rem; color: #1c2833; background: #fff; line-height: 1.5; }}
  h1, h2, h3 {{ color: #17202a; }}
  .verdict-banner {{ background: {verdict_color}; color: #fff; padding: 1.25rem 1.5rem;
                     border-radius: 8px; margin-bottom: 1.5rem; }}
  .verdict-banner .verdict {{ font-size: 1.8rem; font-weight: 700; letter-spacing: 0.05em; }}
  .verdict-banner .confidence {{ font-size: 1rem; opacity: 0.9; }}
  .meta {{ font-size: 0.85rem; color: #566573; margin-bottom: 1.5rem; }}
  .meta code {{ background: #f4f6f7; padding: 0.1rem 0.3rem; border-radius: 3px; }}
  .chip {{ display: inline-block; background: #eaf2f8; color: #1a5276; padding: 0.15rem 0.6rem;
          border-radius: 12px; font-size: 0.8rem; margin: 0.15rem; font-family: monospace; }}
  section {{ margin-bottom: 2rem; }}
  details {{ border: 1px solid #e5e8e8; border-radius: 6px; margin-bottom: 0.6rem; }}
  details > summary {{ padding: 0.6rem 1rem; cursor: pointer; font-weight: 600;
                       display: flex; align-items: center; gap: 0.6rem; }}
  details .body {{ padding: 0 1rem 1rem 1rem; }}
  .status-badge {{ display: inline-block; padding: 0.1rem 0.5rem; border-radius: 4px;
                   color: #fff; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }}
  .finding {{ border-left: 3px solid #ccc; padding: 0.4rem 0.8rem; margin: 0.5rem 0;
             background: #fbfcfc; }}
  .sev-badge {{ display: inline-block; padding: 0.05rem 0.4rem; border-radius: 3px; color: #fff;
               font-size: 0.7rem; font-weight: 600; margin-right: 0.4rem; text-transform: uppercase; }}
  .indicates {{ font-size: 0.85rem; color: #566573; font-style: italic; margin-top: 0.2rem; }}
  .dir-badge {{ display: inline-block; padding: 0.05rem 0.4rem; border-radius: 3px; color: #fff;
               font-size: 0.7rem; font-weight: 600; margin-top: 0.2rem; }}
  .dir-malicious {{ background: #c0392b; }}
  .dir-benign {{ background: #1e8449; }}
  .dir-neutral {{ background: #7f8c8d; }}
  table {{ border-collapse: collapse; width: 100%; }}
  th, td {{ text-align: left; padding: 0.4rem 0.6rem; border-bottom: 1px solid #eee; font-size: 0.9rem; }}
  .unresolved {{ color: #935116; font-size: 0.85rem; }}
  @media (prefers-color-scheme: dark) {{
    body {{ background: #17202a; color: #eaecee; }}
    h1, h2, h3 {{ color: #fdfefe; }}
    .meta {{ color: #aab7b8; }}
    .meta code {{ background: #212f3c; }}
    details {{ border-color: #2c3e50; }}
    .finding {{ background: #1c2833; border-left-color: #566573; }}
    th, td {{ border-bottom-color: #2c3e50; }}
    .chip {{ background: #21618c; color: #eaf2f8; }}
  }}
</style>
</head>
<body>
""")

    parts.append('<div class="verdict-banner">')
    parts.append(f'<div class="verdict">{_e(v.verdict.upper())}</div>')
    parts.append(f'<div class="confidence">Confidence: {_e(v.confidence)} &nbsp;|&nbsp; '
                 f'Evidence complete: {_e(v.evidence_complete)} &nbsp;|&nbsp; '
                 f'Fusion mode: {_e(_fusion_mode_label(state))}</div>')
    parts.append('</div>')

    parts.append('<div class="meta">')
    parts.append(f'Run ID: <code>{_e(state.run_id)}</code><br>')
    parts.append(f'Generated: {_e(v.generated_at.isoformat())}<br>')
    parts.append(f'Sample SHA256: <code>{_e(state.sample.sha256)}</code><br>')
    parts.append(f'Type: {_e(state.sample.file_type)} &nbsp;|&nbsp; Size: {_e(state.sample.size)} bytes')
    parts.append('</div>')

    if v.attack_techniques:
        parts.append('<section><h2>ATT&amp;CK techniques</h2>')
        for t in v.attack_techniques:
            parts.append(f'<span class="chip">{_e(t)}</span>')
        parts.append('</section>')

    parts.append('<section><h2>Executive summary</h2>')
    parts.append(f'<p>{_e(exec_summary)}</p></section>')

    parts.append('<section><h2>Recommendations</h2>')
    parts.append(f'<p>{_e(recommendations)}</p></section>')

    if v.iocs:
        parts.append('<section><h2>IOCs</h2><table><tr><th>Type</th><th>Value</th></tr>')
        for i in v.iocs[:100]:
            parts.append(f'<tr><td>{_e(i.type)}</td><td><code>{_e(i.value)}</code></td></tr>')
        parts.append('</table></section>')

    parts.append('<section><h2>Per-tool detailed analysis</h2>')
    parts.append('<p style="font-size:0.9rem;color:#566573">Every tool, in canonical order, with '
                 'what it does, its real output (or an honest reason if it didn\'t run), and what '
                 'each finding indicates and which way it leans &mdash; explanation, not a second '
                 'vote; the verdict above was decided by the mechanism named in the banner.</p>')

    by_tool: dict[str, list] = {}
    for sr in state.stage_results:
        by_tool.setdefault(sr.tool or f"(unlabeled, stage={sr.stage})", []).append(sr)
    known_good_hit = is_known_good_match(state)
    _DIR_CSS = {"supports_malicious": "dir-malicious", "supports_benign": "dir-benign",
               "neutral": "dir-neutral"}

    def _render_tool_details(tool_name: str, sr) -> None:
        status_color = _STATUS_COLORS.get(sr.status, "#7f8c8d")
        desc = TOOL_DESCRIPTIONS.get(tool_name, "(no static description available for this tool)")
        parts.append('<details>')
        parts.append(f'<summary>{_e(tool_name)} '
                     f'<span class="status-badge" style="background:{status_color}">{_e(sr.status)}</span>'
                     f'<span style="font-weight:400;color:#909497;font-size:0.85rem">'
                     f'stage: {_e(sr.stage)}</span></summary>')
        parts.append('<div class="body">')
        parts.append(f'<p>{_e(desc)}</p>')
        if sr.findings:
            for f in sr.findings:
                sev_color = _SEVERITY_COLORS.get(f.severity, "#5d6d7e")
                direction = _finding_direction(f, state)
                parts.append('<div class="finding">')
                parts.append(f'<span class="sev-badge" style="background:{sev_color}">{_e(f.severity)}</span>'
                             f'{_e(f.claim)}')
                parts.append(f'<div class="indicates">Indicates: {_e(_finding_indication(f, state))}</div>')
                parts.append(f'<span class="dir-badge {_DIR_CSS.get(direction, "dir-neutral")}">'
                             f'{_e(direction.replace("_", " "))}</span>')
                parts.append('</div>')
        else:
            parts.append('<p style="color:#909497">No relevant findings from this tool for this sample.</p>')
        if sr.notes:
            parts.append(f'<p><strong>Notes:</strong> {_e(sr.notes)}</p>')
        for u in sr.unresolved:
            parts.append(f'<p class="unresolved">Unresolved: {_e(u)}</p>')
        parts.append('</div></details>')

    for tool_name in TOOL_DESCRIPTIONS:
        srs = by_tool.pop(tool_name, None)
        if srs:
            for sr in srs:
                _render_tool_details(tool_name, sr)
            continue
        desc = TOOL_DESCRIPTIONS.get(tool_name, "(no static description available for this tool)")
        reason = ("sample matched the known-good hash allowlist, so the rest of triage "
                 "(and static/dynamic analysis) never ran"
                 if known_good_hit else
                 "not attempted -- no StageResult was recorded for this tool during this run")
        parts.append('<details>')
        parts.append(f'<summary>{_e(tool_name)} '
                     f'<span class="status-badge" style="background:{_STATUS_COLORS["skipped"]}">skipped</span>'
                     '</summary>')
        parts.append(f'<div class="body"><p>{_e(desc)}</p>'
                     f'<p style="color:#909497">Reason: {_e(reason)}</p></div>')
        parts.append('</details>')

    for tool_name, srs in by_tool.items():
        for sr in srs:
            _render_tool_details(tool_name, sr)

    parts.append('</section>')

    parts.append('<details><summary>Raw evidence records '
                 f'({len(state.evidence)})</summary><div class="body">')
    for ev in state.evidence:
        parts.append(f'<p><code>{_e(ev.evidence_id)}</code> locator=<code>{_e(ev.locator)}</code>'
                     f' trust={_e(ev.trust)}')
        if ev.excerpt:
            parts.append(f'<br><span style="color:#566573">{_e(ev.excerpt[:2000])}</span>')
        parts.append('</p>')
    parts.append('</div></details>')

    if audit is not None:
        parts.append('<details><summary>Audit log '
                     f'(chain intact: {_e(audit.verify())}, {len(audit.records)} records)</summary>'
                     '<div class="body">')
        for rec in audit.records:
            parts.append(f'<p style="font-size:0.8rem;color:#566573">[{rec.seq}] '
                         f'{_e(rec.at.isoformat())} action={_e(rec.action)} '
                         f'detail={_e(rec.detail)}</p>')
        parts.append('</div></details>')

    if v.yara_rules:
        parts.append(f'<details><summary>Generated YARA rules ({len(v.yara_rules)})</summary>'
                     '<div class="body">')
        for rule in v.yara_rules:
            parts.append(f'<pre style="white-space:pre-wrap">{_e(rule)}</pre>')
        parts.append('</div></details>')

    parts.append("</body></html>")
    return "\n".join(parts)


def render_markdown(state: AnalysisState, v: Verdict) -> str:
    L = []
    L.append(f"# MAL-AGENT report — `{v.sample_sha256[:16]}…`")
    L.append("")
    L.append(f"**Verdict:** {v.verdict.upper()}  |  **Confidence:** {v.confidence}  "
             f"|  **Evidence complete:** {v.evidence_complete}")
    L.append(f"**Fusion mode:** {_fusion_mode_label(state)}")
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
