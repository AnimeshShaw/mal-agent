"""Evidence bundles: the frozen, JSON-serializable record of everything the
deterministic pipeline found for one sample.

Each bundle carries
  - identity + ground-truth label/metadata (label is never shown to a judge),
  - every evidence item with a provenance tag: 'tool' (a fact a tool
    computed -- a capa rule matched, an entropy value) or 'sample_text'
    (text copied out of the sample itself -- a URL, a script body, a macro,
    an archive member name: attacker-controlled),
  - every finding (claim, severity, evidence ids, ATT&CK ids),
  - every tool's run/skip/error status,
  - EMBER's raw and decision-eligible score,
  - the verdicts of the three non-LLM arms (simple = EMBER alone, cgef,
    gate = deterministic corroboration gate with EMBER removed), computed
    from the same state by the production reporter code.
"""
from __future__ import annotations
import json
import re
from pathlib import Path
from typing import Optional

from ..contracts import AnalysisState, EvidenceRecord, Provenance, StageResult
from ..reporter import (_decisive_ember_score, _ember_score, _high_signal_categories,
                        _is_validly_signed, build_verdict)

BUNDLE_SCHEMA = 1
_EXCERPT_MAX = 1500

# Locators whose excerpt is text copied verbatim out of the sample.
_SAMPLE_TEXT_PREFIXES = ("ioc:", "floss:", "unpacker:contains:", "function@", "strings:",
                         "script:excerpt", "office:source", "lnk:target", "lnk:arguments",
                         "pdf:uri")


def provenance_of(ev: EvidenceRecord) -> str:
    if ev.trust == "sample" or ev.locator.startswith(_SAMPLE_TEXT_PREFIXES):
        return "sample_text"
    if ev.trust == "model":
        return "model"
    return "tool"


def _format_of(state: AnalysisState) -> str:
    for ev in state.evidence:
        if ev.locator == "format:type" and ev.excerpt:
            return ev.excerpt
    return {"PE": "pe", "ELF": "elf", "Mach-O": "macho"}.get(state.sample.file_type, "unknown")


def _verdict_dict(v) -> dict:
    return {"verdict": v.verdict, "confidence": v.confidence}


def _baselines(state: AnalysisState) -> dict:
    out = {}
    for mode in ("simple", "cgef"):
        s = state.model_copy(deep=True)
        s.fusion_mode = mode
        out[mode] = _verdict_dict(build_verdict(s))
    g = state.model_copy(deep=True)
    g.evidence = [e for e in g.evidence if not e.locator.startswith("ember:")]
    out["gate"] = _verdict_dict(build_verdict(g))
    return out


def build_bundle(state: AnalysisState, label: Optional[str] = None,
                 meta: Optional[dict] = None) -> dict:
    grounded = [f for f in state.findings if f.grounded]
    categories = sorted(_high_signal_categories(state, grounded))
    signed = _is_validly_signed(grounded, state)
    evidence = [{
        "id": e.evidence_id,
        "locator": e.locator,
        "tool": e.locator.split(":", 1)[0] if ":" in e.locator else e.locator,
        "excerpt": (e.excerpt or "")[:_EXCERPT_MAX],
        "provenance": provenance_of(e),
    } for e in state.evidence]
    findings = [{
        "id": f.finding_id, "claim": f.claim[:600], "severity": f.severity,
        "category": f.category, "evidence": list(f.evidence),
        "attack": list(f.attack_techniques), "stage": f.source_stage,
        "grounded": f.grounded,
    } for f in state.findings]
    tools = [{"tool": sr.tool or sr.stage, "stage": sr.stage, "status": sr.status,
              "notes": (sr.notes or "")[:300], "unresolved": [u[:300] for u in sr.unresolved]}
             for sr in state.stage_results]
    return {
        "schema": BUNDLE_SCHEMA,
        "sha256": state.sample.sha256,
        "size": state.sample.size,
        "format": _format_of(state),
        "label": label,
        "meta": meta or {},
        "ember": {"score": _ember_score(state), "decisive": _decisive_ember_score(state)},
        "gate": {"categories": categories, "signed": signed,
                 "required": 3 + (1 if signed else 0)},
        "baselines": _baselines(state),
        "evidence": evidence,
        "findings": findings,
        "tools": tools,
        "iocs": [{"type": i.type, "value": i.value[:300]} for i in state.iocs][:50],
        "durations_ms": dict(state.stage_durations_ms),
    }


def save_bundle(bundle: dict, out_dir) -> Path:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    p = out / f"{bundle['sha256']}.json"
    p.write_text(json.dumps(bundle, indent=1), encoding="utf-8")
    return p


def load_bundles(bundle_dir) -> list[dict]:
    return [json.loads(p.read_text(encoding="utf-8"))
            for p in sorted(Path(bundle_dir).glob("*.json")) if not p.name.startswith("_")]


# ---------------------------------------------------------------- collection
_STR_RX = re.compile(rb"[\x20-\x7e]{8,200}")
_WSTR_RX = re.compile(rb"(?:[\x20-\x7e]\x00){8,200}")


def strings_evidence(data: bytes, sha256: str, limit: int = 60) -> Optional[EvidenceRecord]:
    """A sample of the file's printable strings, as an analyst's `strings`
    view -- sample_text, and exactly the surface a prompt-injection or
    representation-confusion attack writes into."""
    seen, out = set(), []
    found = _STR_RX.findall(data) + [w.replace(b"\x00", b"") for w in _WSTR_RX.findall(data)]
    for s in found:
        t = s.decode("latin1").strip()
        # skip runs of one repeated character / pure hex-ish noise
        if len(set(t)) < 4 or t in seen:
            continue
        seen.add(t)
        out.append(t)
        if len(out) >= limit:
            break
    if not out:
        return None
    return EvidenceRecord(evidence_id=f"ev_strings_{sha256[:16]}", artifact_id="strings",
                          locator="strings:sample", excerpt="\n".join(out), trust="sample")


def analyze_for_bundle(path: str, *, label: Optional[str] = None, meta: Optional[dict] = None,
                       fusion_mode: str = "simple") -> dict:
    """Deterministic triage (every triage tool, incl. capa/EMBER/format
    tools) + ATT&CK aggregation + grounding -- no Ghidra/FLOSS, no LLM.
    The same evidence tier for every sample, so arms are comparable."""
    import time
    from ..agents import triage_agent, ttp_agent, verifier_agent
    from ..ingest import ingest, new_run_id

    sample = ingest(path, provenance=Provenance(source="dataset"))
    state = AnalysisState(run_id=new_run_id(), sample=sample, fusion_mode=fusion_mode)
    for name, agent in (("triage", triage_agent), ("ttp", ttp_agent), ("verify", verifier_agent)):
        t0 = time.monotonic()
        state = agent(state)
        state.stage_durations_ms[name] = (time.monotonic() - t0) * 1000.0
    with open(sample.path, "rb") as fh:
        sev = strings_evidence(fh.read(), sample.sha256)
    if sev is not None:
        state.evidence.append(sev)
        state.stage_results.append(StageResult(stage="triage", status="ok", tool="strings",
                                               evidence=[], notes="printable-string sample"))
    return build_bundle(state, label=label, meta=meta)
