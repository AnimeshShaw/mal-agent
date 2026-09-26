"""Containers (ZIP/ISO) are out-of-distribution for EMBER2024 as a whole,
but the PE payloads inside them are not. EmberClassifierTool scores each
extracted PE payload (locator 'ember:payload:<path>'), and the verdict for
a non-PE container is decided by the highest in-distribution payload
score -- a container is as dangerous as the worst executable it carries."""
from __future__ import annotations
import io
import zipfile

from malagent.contracts import AnalysisState, EvidenceRecord, Finding, Provenance, Sample, StageResult
from malagent.ember_classifier import EmberClassifierTool
from malagent.reporter import build_verdict, fusion_mode_label


def _zip_bytes(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buf.getvalue()


def _fake_thrember(monkeypatch, score_for):
    import malagent.ember_classifier as mod

    class _Lgb:
        @staticmethod
        def Booster(model_file):
            return object()

    class _Thr:
        @staticmethod
        def predict_sample(model, data):
            return score_for(data)

    monkeypatch.setattr(mod, "_import_thrember", lambda: (_Lgb, _Thr))


def _state_for(tmp_path, data: bytes, file_type: str) -> AnalysisState:
    p = tmp_path / "s.bin"
    p.write_bytes(data)
    return AnalysisState(run_id="r1", sample=Sample(
        sha256="a" * 64, md5="b" * 32, path=str(p), file_type=file_type,
        size=len(data), provenance=Provenance()))


def test_zip_with_pe_payload_gets_payload_score(monkeypatch, tmp_path):
    (tmp_path / "m.model").write_bytes(b"x")
    monkeypatch.setenv("EMBER_MODEL_PATH", str(tmp_path / "m.model"))
    pe = b"MZ" + b"\x01" * 200
    data = _zip_bytes({"invoice.exe": pe, "readme.txt": b"hello"})
    _fake_thrember(monkeypatch, lambda d: 0.97 if d.startswith(b"MZ") else 0.9)
    sr = EmberClassifierTool().run(_state_for(tmp_path, data, "unknown"))
    locs = {e.locator: e.excerpt for e in sr.evidence}
    assert locs.get("ember:payload:invoice.exe") == "0.9700"
    assert "ember:payload:readme.txt" not in locs   # non-PE payloads aren't scored


def test_pe_sample_does_not_try_to_unpack(monkeypatch, tmp_path):
    (tmp_path / "m.model").write_bytes(b"x")
    monkeypatch.setenv("EMBER_MODEL_PATH", str(tmp_path / "m.model"))
    _fake_thrember(monkeypatch, lambda d: 0.5)
    sr = EmberClassifierTool().run(_state_for(tmp_path, b"MZ" + b"\x00" * 50, "PE"))
    assert not any(e.locator.startswith("ember:payload:") for e in sr.evidence)


def _container_state(payload_scores: dict[str, float], outer: float = 0.95) -> AnalysisState:
    s = AnalysisState(run_id="r1", sample=Sample(
        sha256="a" * 64, md5="b" * 32, path="/tmp/x", file_type="unknown", size=1,
        provenance=Provenance()))
    ev = [EvidenceRecord(evidence_id="ev_outer", artifact_id="a", locator="ember:score",
                         excerpt=f"{outer:.4f}", trust="tool")]
    for i, (name, sc) in enumerate(payload_scores.items()):
        ev.append(EvidenceRecord(evidence_id=f"ev_p{i}", artifact_id="a",
                                 locator=f"ember:payload:{name}", excerpt=f"{sc:.4f}", trust="tool"))
    s.evidence = ev
    s.findings = [Finding(finding_id="f_e", claim="EMBER", category="capability",
                          severity="info", confidence=0.5,
                          evidence=[e.evidence_id for e in ev], grounded=True)]
    s.stage_results = [StageResult(stage="triage", status="ok")]
    return s


def test_container_decided_by_worst_payload():
    v = build_verdict(_container_state({"a.exe": 0.01, "b.exe": 0.98}))
    assert v.verdict == "malicious"


def test_container_with_only_benign_payloads_is_benign():
    v = build_verdict(_container_state({"setup.exe": 0.002}))
    assert v.verdict == "benign"


def test_container_label_names_the_payload():
    label = fusion_mode_label(_container_state({"b.exe": 0.98}))
    assert "b.exe" in label
