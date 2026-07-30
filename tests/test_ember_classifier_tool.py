"""EmberClassifierTool (ML classifier plan, Phase 3): wraps a pretrained
EMBER2024 LightGBM model (github.com/FutureComputing4AI/EMBER2024,
Apache-2.0) to produce a real P(malicious) score on every sample, gated
behind EMBER_MODEL_PATH -- degrades gracefully when unconfigured, matching
every other optional tool in this codebase (capa/Ghidra/YARA/die/VT).
The score travels as a plain EvidenceRecord (locator='ember:score'),
read directly by reporter.build_verdict() (see
tests/test_reporter_ember_decision.py) rather than a new frozen-contract
field."""
from __future__ import annotations
from malagent.contracts import AnalysisState, Provenance, Sample
from malagent.ember_classifier import EmberClassifierTool


def _sample(tmp_path, data=b"MZ" + b"\x00" * 100):
    p = tmp_path / "sample.bin"
    p.write_bytes(data)
    return Sample(sha256="a" * 64, md5="b" * 32, path=str(p),
                  file_type="PE", size=len(data), provenance=Provenance())


def _state(tmp_path, data=b"MZ" + b"\x00" * 100):
    return AnalysisState(run_id="r1", sample=_sample(tmp_path, data))


def test_no_model_path_configured_skips_gracefully(monkeypatch, tmp_path):
    monkeypatch.delenv("EMBER_MODEL_PATH", raising=False)
    sr = EmberClassifierTool().run(_state(tmp_path))
    assert sr.status == "skipped"
    assert any("EMBER_MODEL_PATH" in u for u in sr.unresolved)


def test_model_path_set_but_missing_file_skips_gracefully(monkeypatch, tmp_path):
    monkeypatch.setenv("EMBER_MODEL_PATH", str(tmp_path / "nope.model"))
    sr = EmberClassifierTool().run(_state(tmp_path))
    assert sr.status == "skipped"
    assert any("not found" in u.lower() for u in sr.unresolved)


def test_missing_thrember_dependency_skips_gracefully(monkeypatch, tmp_path):
    import malagent.ember_classifier as mod
    monkeypatch.setenv("EMBER_MODEL_PATH", str(tmp_path / "fake.model"))
    (tmp_path / "fake.model").write_bytes(b"not a real model")
    monkeypatch.setattr(mod, "_import_thrember", lambda: (None, None))
    sr = EmberClassifierTool().run(_state(tmp_path))
    assert sr.status == "skipped"
    assert any("thrember" in u.lower() or "lightgbm" in u.lower() for u in sr.unresolved)


def test_real_score_produces_grounded_finding_and_evidence(monkeypatch, tmp_path):
    """Mocks thrember.predict_sample the same way tests/test_pe_header_tool.py
    mocks pefile.PE, so this doesn't depend on a real model file existing
    in the test environment -- live verification against the real model
    happens separately (see docs/ML_CLASSIFIER_PLAN.md Phase 3)."""
    import malagent.ember_classifier as mod

    class _FakeLgb:
        @staticmethod
        def Booster(model_file):
            return object()

    class _FakeThrember:
        @staticmethod
        def predict_sample(model, data):
            return 0.9876

    monkeypatch.setenv("EMBER_MODEL_PATH", str(tmp_path / "fake.model"))
    (tmp_path / "fake.model").write_bytes(b"fake")
    monkeypatch.setattr(mod, "_import_thrember", lambda: (_FakeLgb, _FakeThrember))

    sr = EmberClassifierTool().run(_state(tmp_path))
    assert sr.status == "ok"
    assert len(sr.evidence) == 1
    assert sr.evidence[0].locator == "ember:score"
    assert float(sr.evidence[0].excerpt) == 0.9876
    assert len(sr.findings) == 1
    assert sr.findings[0].severity == "info"  # must never move the old severity-weighted sum
    assert sr.findings[0].evidence == [sr.evidence[0].evidence_id]


def test_prediction_failure_reports_error_not_silently_skipped(monkeypatch, tmp_path):
    import malagent.ember_classifier as mod

    class _FakeLgb:
        @staticmethod
        def Booster(model_file):
            return object()

    class _FakeThrember:
        @staticmethod
        def predict_sample(model, data):
            raise ValueError("corrupted feature vector")

    monkeypatch.setenv("EMBER_MODEL_PATH", str(tmp_path / "fake.model"))
    (tmp_path / "fake.model").write_bytes(b"fake")
    monkeypatch.setattr(mod, "_import_thrember", lambda: (_FakeLgb, _FakeThrember))

    sr = EmberClassifierTool().run(_state(tmp_path))
    assert sr.status == "error"
    assert any("corrupted feature vector" in u for u in sr.unresolved)
