"""Web-UI redesign guarantees: persisted history, upload hygiene, input
validation, and exposure controls."""
from __future__ import annotations
import pytest

pytest.importorskip("fastapi")

import threading
import time
from pathlib import Path

from fastapi.testclient import TestClient

from malagent_web import runs as runs_module
from malagent_web.app import create_app, run as run_server


class _Audit:
    records = []

    def verify(self):
        return True


def _fake_analyze(captured=None):
    def _fn(path, **kw):
        from malagent.contracts import AnalysisState, Provenance, Sample, Verdict
        if captured is not None:
            captured["path"] = path
            captured["kw"] = kw
        s = AnalysisState(run_id="x", sample=Sample(sha256="a" * 64, md5="b" * 32, path=path,
                          file_type="PE", size=3, provenance=Provenance()))
        return s, Verdict(sample_sha256="a" * 64, verdict="benign", confidence=0.9), \
            "md", "txt", "<html>r</html>", _Audit()
    return _fn


def _wait(client, rid, status="complete"):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        body = client.get(f"/api/analyses/{rid}").json()
        if body["status"] in ("complete", "error"):
            return body
        time.sleep(0.02)
    raise AssertionError("run did not finish")


@pytest.fixture()
def fresh(monkeypatch):
    monkeypatch.setattr(runs_module, "_runs", {})
    yield
    runs_module.set_store(None)


def test_completed_runs_survive_a_restart(fresh, monkeypatch, tmp_path):
    monkeypatch.setattr("malagent.pipeline.analyze", _fake_analyze())
    db = str(tmp_path / "web.db")
    c = TestClient(create_app(store=runs_module.RunStore(db)))
    rid = c.post("/api/analyses", files={"file": ("a.exe", b"MZ\x00", "application/octet-stream")}
                 ).json()["run_id"]
    _wait(c, rid)
    # "restart": empty in-memory registry, new app, same database file
    monkeypatch.setattr(runs_module, "_runs", {})
    c2 = TestClient(create_app(store=runs_module.RunStore(db)))
    body = c2.get(f"/api/analyses/{rid}").json()
    assert body["status"] == "complete" and body["verdict"]["verdict"] == "benign"
    assert body["filename"] == "a.exe"
    assert c2.get(f"/api/analyses/{rid}/report.txt").text == "txt"
    assert [r["run_id"] for r in c2.get("/api/analyses").json()["runs"]] == [rid]


def test_upload_temp_dir_is_removed_after_the_run(fresh, monkeypatch):
    captured = {}
    monkeypatch.setattr("malagent.pipeline.analyze", _fake_analyze(captured))
    c = TestClient(create_app())
    rid = c.post("/api/analyses", files={"file": ("a.exe", b"MZ\x00", "x")}).json()["run_id"]
    _wait(c, rid)
    assert not Path(captured["path"]).exists()
    assert not Path(captured["path"]).parent.exists()


def test_oversized_upload_rejected(fresh, monkeypatch):
    monkeypatch.setattr("malagent.pipeline.analyze", _fake_analyze())
    c = TestClient(create_app(max_upload_mb=1))
    r = c.post("/api/analyses", files={"file": ("big.bin", b"A" * (1024 * 1024 + 10), "x")})
    assert r.status_code == 413


def test_invalid_fusion_mode_rejected(fresh, tmp_path):
    p = tmp_path / "s.bin"
    p.write_bytes(b"MZ")
    r = TestClient(create_app()).post("/api/analyses", data={"path": str(p), "fusion_mode": "yolo"})
    assert r.status_code == 400


def test_invalid_judge_model_rejected(fresh, tmp_path):
    p = tmp_path / "s.bin"
    p.write_bytes(b"MZ")
    r = TestClient(create_app()).post("/api/analyses", data={"path": str(p), "fusion_mode": "judge",
                                                             "judge_model": "nocolon"})
    assert r.status_code == 400


def test_judge_mode_and_model_reach_the_pipeline(fresh, monkeypatch, tmp_path):
    captured = {}
    monkeypatch.setattr("malagent.pipeline.analyze", _fake_analyze(captured))
    p = tmp_path / "s.bin"
    p.write_bytes(b"MZ")
    c = TestClient(create_app())
    rid = c.post("/api/analyses", data={"path": str(p), "fusion_mode": "judge",
                                        "judge_model": "ollama:qwen3:8b"}).json()["run_id"]
    _wait(c, rid)
    assert captured["kw"]["fusion_mode"] == "judge"
    assert captured["kw"]["judge_model"] == "ollama:qwen3:8b"


def test_server_paths_can_be_disabled(fresh, tmp_path):
    p = tmp_path / "s.bin"
    p.write_bytes(b"MZ")
    r = TestClient(create_app(allow_server_paths=False)).post("/api/analyses", data={"path": str(p)})
    assert r.status_code == 403


def test_token_required_when_configured(fresh):
    c = TestClient(create_app(token="s3cret"))
    assert c.get("/api/health").status_code == 200
    assert c.get("/api/analyses").status_code == 401
    assert c.get("/api/analyses", headers={"X-Mal-Agent-Token": "s3cret"}).status_code == 200


def test_non_loopback_bind_without_token_refuses(monkeypatch):
    monkeypatch.delenv("MAL_AGENT_WEB_TOKEN", raising=False)
    with pytest.raises(SystemExit):
        run_server(host="0.0.0.0", port=0)


def test_html_report_is_served_with_a_script_blocking_csp(fresh, monkeypatch):
    monkeypatch.setattr("malagent.pipeline.analyze", _fake_analyze())
    c = TestClient(create_app())
    rid = c.post("/api/analyses", files={"file": ("a", b"MZ", "x")}).json()["run_id"]
    _wait(c, rid)
    r = c.get(f"/api/analyses/{rid}/report.html")
    assert "default-src 'none'" in r.headers["content-security-policy"]


def test_detail_payload_has_evidence_provenance_and_route(fresh, monkeypatch):
    monkeypatch.setattr("malagent.pipeline.analyze", _fake_analyze())
    c = TestClient(create_app())
    rid = c.post("/api/analyses", files={"file": ("a", b"MZ", "x")}).json()["run_id"]
    body = _wait(c, rid)
    for key in ("sample", "ember", "gate", "route", "tools", "findings", "evidence", "attack"):
        assert key in body, key
