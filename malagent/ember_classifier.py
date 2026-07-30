"""ML classifier plan, Phase 3 (docs/ML_CLASSIFIER_PLAN.md): wraps a
pretrained EMBER2024 LightGBM model
(github.com/FutureComputing4AI/EMBER2024, Apache-2.0) to produce a real
P(malicious) score on every sample -- decided over 3.2M real files, not
hand-tuned constants like the deterministic corroboration gate. Gated
behind EMBER_MODEL_PATH, degrades gracefully when unconfigured, matching
every other optional tool in this codebase (capa/Ghidra/YARA/die/VT).

The score itself doesn't decide anything here -- it's just evidence
(locator='ember:score'), read and turned into the actual verdict by
reporter.build_verdict() (see docs/ML_CLASSIFIER_PLAN.md Phase 3 for the
full reasoning and the calibrated threshold)."""
from __future__ import annotations
import os
from .contracts import AnalysisState, EvidenceRecord, Finding, StageResult
from .tools import _artifact, _id


def _import_thrember():
    """Isolated so tests can monkeypatch it the same way
    tests/test_pe_header_tool.py monkeypatches pefile.PE -- avoids needing
    a real ~3.5MB model file or the thrember/lightgbm dependency chain
    installed in every test environment."""
    try:
        import lightgbm as lgb
        import thrember
        return lgb, thrember
    except Exception:
        return None, None


class EmberClassifierTool:
    name = "ember_classifier"

    def run(self, state: AnalysisState) -> StageResult:
        model_path = os.getenv("EMBER_MODEL_PATH")
        if not model_path:
            return StageResult(
                stage="triage", status="skipped",
                unresolved=["EMBER classifier not run: EMBER_MODEL_PATH not set."],
                notes="see docs/ML_CLASSIFIER_PLAN.md for setup")
        if not os.path.exists(model_path):
            return StageResult(
                stage="triage", status="skipped",
                unresolved=[f"EMBER_MODEL_PATH={model_path} set but file not found."])

        lgb, thrember = _import_thrember()
        if lgb is None:
            return StageResult(
                stage="triage", status="skipped",
                unresolved=["EMBER_MODEL_PATH set but 'thrember'/'lightgbm' not installed."],
                notes="pip install thrember (see docs/ML_CLASSIFIER_PLAN.md)")

        try:
            with open(state.sample.path, "rb") as fh:
                data = fh.read()
            model = lgb.Booster(model_file=model_path)
            score = float(thrember.predict_sample(model, data))
        except Exception as e:
            return StageResult(stage="triage", status="error",
                               unresolved=[f"EMBER classifier failed: {e}"])

        input_ref = state.sample.sha256
        art = _artifact(self.name, input_ref, f"{score:.6f}".encode())
        ev = EvidenceRecord(evidence_id=_id("ev", input_ref, "ember"),
                            artifact_id=art.artifact_id, locator="ember:score",
                            excerpt=f"{score:.4f}", trust="tool")
        finding = Finding(
            finding_id=_id("f", input_ref, "ember"),
            claim=f"EMBER2024 classifier: P(malicious)={score:.4f} "
                  f"(model: {os.path.basename(model_path)}).",
            category="capability", severity="info", confidence=0.5,
            evidence=[ev.evidence_id], source_stage="triage")
        return StageResult(stage="triage", status="ok", findings=[finding],
                           artifacts=[art], evidence=[ev],
                           notes=f"ember score={score:.4f}")
