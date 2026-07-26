"""YARA rule MATCHING against a real corpus (docs/TODO.md Phase 2) --
distinct from the existing rule GENERATION in yara_gen.py (which builds a
rule per-sample from grounded literal evidence). Same env-var-configured-
external-data pattern as CAPA_RULES_PATH/KNOWN_GOOD_HASHES_PATH/
IP_BLOCKLIST_PATH: the operator supplies their own rules -- never
bundled, since third-party YARA rule sets carry their own licenses."""
from __future__ import annotations
import os
from pathlib import Path

from .contracts import AnalysisState, EvidenceRecord, Finding, StageResult
from .tools import _artifact, _id

try:
    import yara
except Exception:
    yara = None


def _compile_rules(rules_path: str):
    path = Path(rules_path)
    if path.is_dir():
        filepaths = {f.stem: str(f) for f in sorted(path.glob("**/*.yar*"))}
        if not filepaths:
            return None
        return yara.compile(filepaths=filepaths)
    return yara.compile(filepath=str(path))


class YaraMatchTool:
    """Triage-stage tool: compiles an operator-supplied YARA rule set
    (YARA_RULES_PATH, a file or a directory of .yar/.yara files) and
    matches it against the sample. A real match against a third-party
    rule set is a meaningfully strong, independent signal -- similar in
    spirit to IocReputationTool's blocklist match -- so it counts toward
    the corroboration gate as its own category (see
    reporter._high_signal_categories)."""
    name = "yara_match"

    def run(self, state: AnalysisState) -> StageResult:
        if yara is None:
            return StageResult(stage="triage", status="skipped",
                               unresolved=["YARA rule matching not performed: 'yara-python' "
                                           "not installed."],
                               notes="install with: pip install yara-python")
        rules_path = os.getenv("YARA_RULES_PATH")
        if not rules_path:
            return StageResult(
                stage="triage", status="skipped",
                unresolved=["YARA rule matching not configured: set YARA_RULES_PATH to a "
                            ".yar/.yara file or a directory of them."],
                notes="no rules configured")
        if not Path(rules_path).exists():
            return StageResult(stage="triage", status="skipped",
                               notes="configured YARA_RULES_PATH not found")

        try:
            rules = _compile_rules(rules_path)
        except Exception as e:
            return StageResult(stage="triage", status="error",
                               unresolved=[f"YARA rule compilation failed: {e}"])
        if rules is None:
            return StageResult(stage="triage", status="skipped",
                               notes="no .yar/.yara files found under YARA_RULES_PATH")

        input_ref = state.sample.sha256
        try:
            matches = rules.match(state.sample.path)
        except Exception as e:
            return StageResult(stage="triage", status="error",
                               unresolved=[f"YARA matching failed: {e}"])

        art = _artifact(self.name, input_ref, input_ref.encode())
        findings: list[Finding] = []
        evidence: list[EvidenceRecord] = []
        for m in matches:
            claim = f"Matched YARA rule {m.rule!r} from the configured rule set."
            if m.tags:
                claim += f" Tags: {', '.join(m.tags)}."
            ev = EvidenceRecord(evidence_id=_id("ev", input_ref, "yara", m.rule),
                                artifact_id=art.artifact_id, locator=f"yara_match:{m.rule}",
                                excerpt=m.rule, trust="tool")
            evidence.append(ev)
            findings.append(Finding(
                finding_id=_id("f", input_ref, "yara", m.rule),
                claim=claim, category="capability", severity="medium", confidence=0.65,
                evidence=[ev.evidence_id], source_stage="triage"))

        return StageResult(stage="triage", status="ok", findings=findings,
                           artifacts=[art], evidence=evidence,
                           notes=f"{len(findings)} rule(s) matched")
