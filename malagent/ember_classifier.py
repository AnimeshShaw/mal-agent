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
from .unpacker import extract_files


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

        # A non-PE container is out-of-distribution for EMBER as a whole, but
        # the PE payloads inside it are not -- score each one separately so
        # the verdict can rest on in-distribution evidence (reporter decides).
        payload_scores: list[tuple[str, float]] = []
        unresolved: list[str] = []
        if data[:2] != b"MZ":
            for name, inner in extract_files(data):
                if inner[:2] != b"MZ":
                    continue
                try:
                    payload_scores.append((name, float(thrember.predict_sample(model, inner))))
                except Exception as e:
                    unresolved.append(f"EMBER failed on extracted payload {name}: {e}")

        input_ref = state.sample.sha256
        art = _artifact(self.name, input_ref, f"{score:.6f}".encode())
        ev = EvidenceRecord(evidence_id=_id("ev", input_ref, "ember"),
                            artifact_id=art.artifact_id, locator="ember:score",
                            excerpt=f"{score:.4f}", trust="tool")
        evidence = [ev]
        for name, ps in payload_scores:
            evidence.append(EvidenceRecord(
                evidence_id=_id("ev", input_ref, "ember_payload", name),
                artifact_id=art.artifact_id, locator=f"ember:payload:{name}",
                excerpt=f"{ps:.4f}", trust="tool"))
        claim = (f"EMBER2024 classifier: P(malicious)={score:.4f} "
                 f"(model: {os.path.basename(model_path)}).")
        if payload_scores:
            claim += " Extracted PE payloads: " + ", ".join(
                f"{n}={ps:.4f}" for n, ps in payload_scores) + "."
        finding = Finding(
            finding_id=_id("f", input_ref, "ember"), claim=claim,
            category="capability", severity="info", confidence=0.5,
            evidence=[e.evidence_id for e in evidence], source_stage="triage")
        notes = f"ember score={score:.4f}"
        if payload_scores:
            notes += f"; {len(payload_scores)} PE payload(s) scored"
        return StageResult(stage="triage", status="ok", findings=[finding],
                           artifacts=[art], evidence=evidence, unresolved=unresolved,
                           notes=notes)
