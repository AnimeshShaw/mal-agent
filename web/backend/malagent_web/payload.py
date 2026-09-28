"""The run-detail payload the frontend renders. Built from the same evidence
bundle the research experiments use (malagent.judge.bundle), so the UI
shows exactly what a judge would see: every evidence item with its
provenance (tool-derived vs. attacker-controlled sample text), findings
with their direction, tool coverage, EMBER applicability, gate categories,
the hard-case route, and (in judge mode) the adjudication."""
from __future__ import annotations

from malagent.attck_reference import technique_name
from malagent.judge.bundle import build_bundle
from malagent.judge.routing import route
from malagent.reporter import (_finding_direction, _finding_indication, build_tool_report,
                               fusion_mode_label)


def build_detail(state, verdict) -> dict:
    b = build_bundle(state)
    rt = route(b)
    f_by_id = {f.finding_id: f for f in state.findings}
    findings = []
    for f in b["findings"]:
        real = f_by_id.get(f["id"])
        findings.append({**f,
                         "direction": _finding_direction(real, state) if real else "neutral",
                         "indication": _finding_indication(real, state) if real else ""})
    narrative = next((f for f in state.findings if f.source_stage == "behavioral_analyst"), None)
    critic = next((sr for sr in state.stage_results if sr.stage == "verifier_critic"), None)
    attack = []
    for t in sorted({t for f in state.findings for t in f.attack_techniques}):
        tactics = sorted({tac for f in state.findings if t in f.attack_techniques
                          for tac in f.attack_tactics})
        attack.append({"id": t, "name": technique_name(t) or "", "tactics": tactics})
    em = b["ember"]
    return {
        "verdict": verdict.model_dump(mode="json"),
        "fusion_mode": state.fusion_mode,
        "fusion_mode_label": fusion_mode_label(state),
        "sample": {"sha256": state.sample.sha256, "md5": state.sample.md5,
                   "size": state.sample.size, "file_type": state.sample.file_type,
                   "format": b["format"]},
        "ember": {**em, "in_distribution": em["decisive"] is not None,
                  "payloads": [e for e in b["evidence"] if e["locator"].startswith("ember:payload:")]},
        "gate": b["gate"],
        "route": {"routed": rt.routed, "reasons": rt.reasons},
        "adjudication": state.adjudication,
        "tools": build_tool_report(state),
        "findings": findings,
        "evidence": b["evidence"],
        "iocs": b["iocs"],
        "attack": attack,
        "narrative": narrative.claim if narrative else None,
        "narrative_grounded": bool(narrative and narrative.grounded),
        "narrative_check": (critic.notes if critic else None),
        "durations_ms": dict(state.stage_durations_ms),
        "unresolved": verdict.unresolved,
        "yara_rules": verdict.yara_rules,
    }
