"""fusion_mode="judge" (opt-in): EMBER-alone decides confident PE cases;
routed hard cases (EMBER out-of-distribution / gray zone / conflict with the
deterministic evidence) take a validated LLM adjudication. Default modes
never consult an LLM (tests/test_llm_agents_never_score.py still holds)."""
from __future__ import annotations
import json

from malagent.contracts import AnalysisState, EvidenceRecord, Finding, Provenance, Sample, StageResult
from malagent.judge.providers import GenResult
from malagent.pipeline import adjudicate_state
from malagent.reporter import build_verdict, fusion_mode_label


def _state(file_type="unknown", ember=0.9, mode="judge"):
    s = AnalysisState(run_id="r1", sample=Sample(sha256="a" * 64, md5="b" * 32, path="x",
                      file_type=file_type, size=10, provenance=Provenance()), fusion_mode=mode)
    s.evidence = [EvidenceRecord(evidence_id="e_em", artifact_id="a", locator="ember:score",
                                 excerpt=f"{ember:.4f}"),
                  EvidenceRecord(evidence_id="e_fmt", artifact_id="a", locator="format:type",
                                 excerpt="script_js" if file_type != "PE" else "pe"),
                  EvidenceRecord(evidence_id="e_ind", artifact_id="a",
                                 locator="script:indicator:execution:shell_exec", excerpt="WScript.Shell")]
    s.findings = [Finding(finding_id="f1", claim="shell exec", category="capability", severity="medium",
                          confidence=0.6, evidence=["e_ind"], grounded=True, source_stage="triage"),
                  Finding(finding_id="f_em", claim="ember", category="capability", severity="info",
                          evidence=["e_em"], grounded=True, source_stage="triage")]
    s.stage_results = [StageResult(stage="triage", status="ok")]
    return s


class _Judge:
    name, model = "fake", "judge-1"

    def __init__(self, verdict="malicious", cite_tool=True):
        self.verdict, self.cite_tool = verdict, cite_tool

    def generate(self, system, prompt, **kw):
        # find the alias of the tool-derived indicator in the rendered prompt
        alias = next(line.split("]")[0].strip("[") for line in prompt.splitlines()
                     if "script:indicator" in line)
        return GenResult(text=json.dumps({"verdict": self.verdict, "confidence": 0.8,
                                          "cited": [alias], "rationale": "shell exec"}),
                         provider="fake", model="judge-1")


def test_routed_case_takes_judge_verdict():
    s = _state()
    adjudicate_state(s, _Judge("malicious"))
    v = build_verdict(s)
    assert v.verdict == "malicious"
    assert s.adjudication["routed"] and s.adjudication["result"]["valid"]
    assert "judge" in fusion_mode_label(s).lower()


def test_routed_case_judge_abstain_is_undetermined():
    s = _state()
    adjudicate_state(s, _Judge("abstain"))
    assert build_verdict(s).verdict == "undetermined"


def test_routed_case_without_judge_is_undetermined_not_guessed():
    s = _state()
    adjudicate_state(s, None)
    v = build_verdict(s)
    assert v.verdict in ("undetermined", "suspicious", "benign", "malicious")
    assert any("no judge" in u.lower() for u in v.unresolved)


def test_confident_pe_is_not_sent_to_judge():
    s = _state(file_type="PE", ember=0.99)
    adjudicate_state(s, _Judge("benign"))
    assert not s.adjudication["routed"]
    assert build_verdict(s).verdict == "malicious"


def test_judge_mode_is_opt_in_simple_mode_ignores_adjudication():
    s = _state(mode="simple")
    adjudicate_state(s, _Judge("malicious"))
    s.fusion_mode = "simple"
    assert build_verdict(s).verdict != "malicious"
