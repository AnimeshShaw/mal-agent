"""M6 sub-task (V2-DESIGN.md S6): measures whether verifier_critic actually
catches overclaiming in the behavioral_analyst narrative, using synthetic
(evidence, narrative, ground-truth) fixtures. This is the "with/without
verifier" ablation axis the research doc's own evaluation methodology
calls for -- deliberately independent of the benign/malicious evaluation
harness in evaluation.py, since it needs no real malware corpus at all:
every fixture here is hand-written with known ground truth about whether
the narrative overclaims beyond its cited evidence. A small bundled
default set (DEFAULT_CASES) lets `mal-agent ablate-critic` run with no
external data."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional
from .agents import make_verifier_critic
from .contracts import AnalysisState, EvidenceRecord, Finding, Provenance, Sample


@dataclass(frozen=True)
class AblationCase:
    case_id: str
    evidence_excerpts: list
    narrative: str
    overclaims: bool  # ground truth: does the narrative claim more than the evidence supports?


@dataclass
class CaseResult:
    case: AblationCase
    critic_flagged_overclaiming: bool


@dataclass
class AblationReport:
    results: list = field(default_factory=list)
    tp: int = 0  # correctly caught real overclaiming
    fp: int = 0  # wrongly flagged an accurate narrative
    tn: int = 0  # correctly passed an accurate narrative
    fn: int = 0  # missed real overclaiming

    @property
    def precision(self) -> Optional[float]:
        denom = self.tp + self.fp
        return self.tp / denom if denom else None

    @property
    def recall(self) -> Optional[float]:
        denom = self.tp + self.fn
        return self.tp / denom if denom else None

    @property
    def f1(self) -> Optional[float]:
        p, r = self.precision, self.recall
        if p is None or r is None or (p + r) == 0:
            return None
        return 2 * p * r / (p + r)

    @property
    def accuracy(self) -> Optional[float]:
        total = self.tp + self.fp + self.tn + self.fn
        return (self.tp + self.tn) / total if total else None


def _synthetic_sample() -> Sample:
    return Sample(sha256="0" * 64, md5="0" * 32, path="/synthetic/ablation.bin",
                  file_type="PE", size=1, provenance=Provenance(source="dataset"))


def _build_state(case: AblationCase) -> AnalysisState:
    """A minimal AnalysisState carrying exactly one behavioral_analyst
    Finding (the narrative under test) and the EvidenceRecords it cites --
    everything verifier_critic actually reads."""
    state = AnalysisState(run_id=f"ablation-{case.case_id}", sample=_synthetic_sample())
    evidence_ids = []
    for i, excerpt in enumerate(case.evidence_excerpts):
        eid = f"ev_{case.case_id}_{i}"
        state.evidence.append(EvidenceRecord(
            evidence_id=eid, artifact_id="synthetic",
            locator=f"synthetic:{case.case_id}:{i}", excerpt=excerpt, trust="tool"))
        evidence_ids.append(eid)
    state.findings.append(Finding(
        finding_id=f"behavioral_{case.case_id}", claim=case.narrative,
        category="behavior", severity="info", confidence=0.5,
        evidence=evidence_ids, source_stage="behavioral_analyst", grounded=True))
    return state


def run_ablation(cases: list, router) -> AblationReport:
    critic = make_verifier_critic(router=router)
    results = []
    tp = fp = tn = fn = 0
    for case in cases:
        state = critic(_build_state(case))
        narrative = next(f for f in state.findings if f.source_stage == "behavioral_analyst")
        flagged = not narrative.grounded
        results.append(CaseResult(case=case, critic_flagged_overclaiming=flagged))
        if case.overclaims and flagged:
            tp += 1
        elif not case.overclaims and flagged:
            fp += 1
        elif not case.overclaims and not flagged:
            tn += 1
        else:
            fn += 1
    return AblationReport(results=results, tp=tp, fp=fp, tn=tn, fn=fn)


def format_report(report: AblationReport) -> str:
    def fmt(x):
        return "n/a" if x is None else f"{x:.4f}"

    lines = [
        "VERIFIER_CRITIC ABLATION REPORT",
        "=" * 40,
        f"Cases evaluated: {len(report.results)}",
        f"TP={report.tp} (caught real overclaiming)   FP={report.fp} (false alarm on accurate narrative)",
        f"TN={report.tn} (correctly passed accurate)   FN={report.fn} (missed real overclaiming)",
        "-" * 40,
        f"precision: {fmt(report.precision)}",
        f"recall:    {fmt(report.recall)}",
        f"f1:        {fmt(report.f1)}",
        f"accuracy:  {fmt(report.accuracy)}",
    ]
    return "\n".join(lines)


# Bundled default fixtures: half accurate, half overclaiming, hand-written
# so `mal-agent ablate-critic` has something to run against with zero
# external data. Not a substitute for a larger, ideally human-rated set --
# a good first expansion target once this harness is in real use.
DEFAULT_CASES = [
    AblationCase(
        case_id="accurate_file_io",
        evidence_excerpts=["Capability detected: create or open file",
                           "Capability detected: read file on Windows"],
        narrative="This sample opens and reads files on the local filesystem.",
        overclaims=False),
    AblationCase(
        case_id="accurate_registry",
        evidence_excerpts=["Capability detected: create or open registry key",
                           "Capability detected: set registry value"],
        narrative="This sample creates registry keys and sets registry values, consistent "
                  "with configuration storage or persistence via the registry.",
        overclaims=False),
    AblationCase(
        case_id="accurate_discovery",
        evidence_excerpts=["ATT&CK T1082: System Information Discovery"],
        narrative="This sample queries system information, a common reconnaissance technique.",
        overclaims=False),
    AblationCase(
        case_id="accurate_hedged_persistence",
        evidence_excerpts=["Capability detected: create or open registry key (Run key path)"],
        narrative="This sample writes to a registry Run key, which may indicate an attempt "
                  "at establishing persistence, though registry writes alone are not "
                  "conclusive of malicious intent.",
        overclaims=False),
    AblationCase(
        case_id="overclaim_ransomware",
        evidence_excerpts=["Capability detected: create or open file"],
        narrative="This sample is ransomware that encrypts victim files and demands payment.",
        overclaims=True),
    AblationCase(
        case_id="overclaim_family_attribution",
        evidence_excerpts=["Capability detected: create process on Windows",
                           "Capability detected: read file on Windows"],
        narrative="This sample is definitely part of the Emotet malware family.",
        overclaims=True),
    AblationCase(
        case_id="overclaim_exfiltration",
        evidence_excerpts=["Capability detected: get geographical location"],
        narrative="This sample exfiltrates the victim's precise GPS coordinates to a remote "
                  "command-and-control server.",
        overclaims=True),
    AblationCase(
        case_id="overclaim_fabricated_confidence",
        evidence_excerpts=["Capability detected: delay execution"],
        narrative="This sample uses sleep-based evasion specifically to bypass EDR sandboxes, "
                  "with 99% confidence this is a targeted APT campaign.",
        overclaims=True),
]
