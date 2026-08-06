"""FastAPI backend for mal-agent's local web UI (docs/TODO.md Phase 8).
Thin: the app imports and calls malagent.pipeline.analyze directly, no
logic duplicated. Ghidra-backed runs can take minutes (docs/EFFICIENCY.md's
real measured numbers), so POST /api/analyses must return immediately --
these tests assert on that non-blocking behavior explicitly, not just on
the eventual result."""
from __future__ import annotations
import pytest

pytest.importorskip("fastapi")

import os
import threading
import time
from pathlib import Path

from fastapi.testclient import TestClient

from malagent_web.app import create_app, ensure_default_database_url
from malagent_web import runs as runs_module


def _fake_analyze_factory(gate: threading.Event, verdict_word="malicious"):
    """A fake pipeline.analyze() that blocks on `gate` until the test
    releases it -- lets a test assert the HTTP response returns before
    the analysis is actually done."""
    def _fake_analyze(path, **kw):
        gate.wait(timeout=5)
        from malagent.contracts import Verdict

        class _FakeAudit:
            def verify(self):
                return True
            records = []

        class _FakeSample:
            sha256 = "a" * 64

        class _FakeState:
            sample = _FakeSample()

        v = Verdict(sample_sha256="a" * 64, verdict=verdict_word, confidence=0.9)
        return _FakeState(), v, "md report", "txt report", "<html>html report</html>", _FakeAudit()
    return _fake_analyze


@pytest.fixture()
def client(monkeypatch):
    # Fresh run registry per test -- the module-level dict in runs.py
    # would otherwise leak state between tests. create_app() itself is
    # pure (no env/filesystem side effects) -- see ensure_default_database_url()
    # for why that matters and why it's a separate, explicitly-opt-in function.
    monkeypatch.setattr(runs_module, "_runs", {})
    app = create_app()
    return TestClient(app)


def _sample_path(tmp_path):
    p = tmp_path / "sample.bin"
    p.write_bytes(b"MZ" + b"\x00" * 64)
    return str(p)


def test_health_endpoint():
    app = create_app()
    client = TestClient(app)
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_create_app_does_not_mutate_the_process_environment(monkeypatch):
    """Regression guard: create_app() must be pure. It's imported (and the
    module-level `app = create_app()` executed) the moment pytest collects
    this test module -- if create_app() itself set DATABASE_URL as a side
    effect, that would fire during collection, before any test/fixture
    runs, leaking a real DATABASE_URL (and creating a stray sqlite file in
    the repo root) for the rest of the session regardless of any
    test-level cleanup. This exact bug happened once during development."""
    monkeypatch.delenv("DATABASE_URL", raising=False)
    create_app()
    assert "DATABASE_URL" not in os.environ


def test_ensure_default_database_url_defaults_to_local_sqlite_not_postgres(monkeypatch):
    """Runs must survive across requests within the same server process --
    unlike the CLI's one-shot default (in-memory), the web UI defaults to
    a local SQLite file, not Postgres (no server process required). This
    is called by run() (the real server-startup path), never by
    create_app() -- see the regression guard above."""
    monkeypatch.delenv("DATABASE_URL", raising=False)
    ensure_default_database_url()
    assert os.environ["DATABASE_URL"].startswith("sqlite:///")


def test_ensure_default_database_url_does_not_override_an_explicit_setting(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://example/db")
    ensure_default_database_url()
    assert os.environ["DATABASE_URL"] == "postgresql://example/db"


def test_post_analyses_returns_immediately_without_blocking(client, monkeypatch, tmp_path):
    gate = threading.Event()
    monkeypatch.setattr("malagent.pipeline.analyze", _fake_analyze_factory(gate))

    start = time.monotonic()
    resp = client.post("/api/analyses", data={"path": _sample_path(tmp_path)})
    elapsed = time.monotonic() - start

    assert resp.status_code == 200
    body = resp.json()
    assert "run_id" in body
    assert body["status"] in ("queued", "running")
    assert elapsed < 2.0, "POST must not block on the analysis itself"

    gate.set()  # let the background thread finish so it doesn't leak into other tests


def test_get_analysis_transitions_to_complete(client, monkeypatch, tmp_path):
    gate = threading.Event()
    monkeypatch.setattr("malagent.pipeline.analyze", _fake_analyze_factory(gate, verdict_word="benign"))

    resp = client.post("/api/analyses", data={"path": _sample_path(tmp_path)})
    run_id = resp.json()["run_id"]

    gate.set()
    deadline = time.monotonic() + 5
    status = None
    while time.monotonic() < deadline:
        got = client.get(f"/api/analyses/{run_id}")
        status = got.json()["status"]
        if status == "complete":
            break
        time.sleep(0.05)

    assert status == "complete"
    assert got.json()["verdict"]["verdict"] == "benign"


def test_get_unknown_run_id_returns_404(client):
    resp = client.get("/api/analyses/does-not-exist")
    assert resp.status_code == 404


def test_post_analyses_rejects_missing_path(client):
    resp = client.post("/api/analyses", data={})
    assert resp.status_code == 400


def test_post_analyses_rejects_nonexistent_path(client):
    resp = client.post("/api/analyses", data={"path": "/definitely/not/a/real/path.bin"})
    assert resp.status_code == 400


def test_uploaded_filename_path_traversal_is_neutralized(client, monkeypatch, tmp_path):
    """file.filename is client-supplied and untrusted -- a crafted name
    with traversal sequences or an absolute path must not let the upload
    escape the server-controlled temp directory or overwrite an arbitrary
    file elsewhere on disk. Regression test for a real path-traversal bug
    found by automated review during development."""
    captured = {}

    def _fake_analyze(path, **kw):
        captured["path"] = path
        from malagent.contracts import Verdict

        class _FakeAudit:
            def verify(self):
                return True
            records = []

        class _FakeSample:
            sha256 = "a" * 64

        class _FakeState:
            sample = _FakeSample()

        return (_FakeState(), Verdict(sample_sha256="a" * 64, verdict="benign"),
               "md", "txt", "<html></html>", _FakeAudit())

    monkeypatch.setattr("malagent.pipeline.analyze", _fake_analyze)

    marker_dir = tmp_path / "should_not_be_touched"
    marker_dir.mkdir()
    canary = marker_dir / "canary.txt"
    canary.write_text("original contents")

    malicious_name = "../" * 6 + str(canary).lstrip("/").replace("\\", "/")
    resp = client.post(
        "/api/analyses",
        files={"file": (malicious_name, b"attacker-controlled bytes", "application/octet-stream")})
    assert resp.status_code == 200

    deadline = time.monotonic() + 5
    while "path" not in captured and time.monotonic() < deadline:
        time.sleep(0.02)

    assert canary.read_text() == "original contents", "path traversal wrote outside the temp dir"
    written_path = Path(captured["path"])
    assert ".." not in written_path.parts
    assert written_path.name in ("canary.txt", "passwd")  # just the basename survives, no traversal


def test_report_endpoints_serve_rendered_reports_once_complete(client, monkeypatch, tmp_path):
    gate = threading.Event()
    gate.set()  # complete immediately -- this test only cares about the report bytes
    monkeypatch.setattr("malagent.pipeline.analyze", _fake_analyze_factory(gate))

    resp = client.post("/api/analyses", data={"path": _sample_path(tmp_path)})
    run_id = resp.json()["run_id"]

    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if client.get(f"/api/analyses/{run_id}").json()["status"] == "complete":
            break
        time.sleep(0.05)

    txt = client.get(f"/api/analyses/{run_id}/report.txt")
    assert txt.status_code == 200
    assert txt.text == "txt report"

    html = client.get(f"/api/analyses/{run_id}/report.html")
    assert html.status_code == 200
    assert "html report" in html.text

    md = client.get(f"/api/analyses/{run_id}/report.md")
    assert md.status_code == 200
    assert md.text == "md report"


def test_report_endpoint_404s_before_run_completes(client, monkeypatch, tmp_path):
    gate = threading.Event()
    monkeypatch.setattr("malagent.pipeline.analyze", _fake_analyze_factory(gate))

    resp = client.post("/api/analyses", data={"path": _sample_path(tmp_path)})
    run_id = resp.json()["run_id"]

    txt = client.get(f"/api/analyses/{run_id}/report.txt")
    assert txt.status_code == 404

    gate.set()


def _fake_analyze_with_progress(progress_lines, gate: threading.Event):
    """A fake pipeline.analyze() that invokes progress_cb (like the real
    orchestrator does) before completing -- exercises the SSE endpoint's
    actual job: relaying progress_cb output to the browser."""
    def _fake_analyze(path, progress_cb=None, **kw):
        for line in progress_lines:
            if progress_cb is not None:
                progress_cb(line)
        gate.wait(timeout=5)
        from malagent.contracts import Verdict

        class _FakeAudit:
            def verify(self):
                return True
            records = []

        class _FakeSample:
            sha256 = "a" * 64

        class _FakeState:
            sample = _FakeSample()

        v = Verdict(sample_sha256="a" * 64, verdict="malicious", confidence=0.9)
        return _FakeState(), v, "md", "txt", "<html></html>", _FakeAudit()
    return _fake_analyze


def test_events_endpoint_streams_progress_lines_pushed_via_progress_cb(client, monkeypatch, tmp_path):
    gate = threading.Event()
    gate.set()  # let it complete immediately once progress lines are pushed
    lines = ["[pipeline] stage 'triage': running...", "[pipeline] stage 'triage': done in 5ms (status=ok)"]
    monkeypatch.setattr("malagent.pipeline.analyze", _fake_analyze_with_progress(lines, gate))

    resp = client.post("/api/analyses", data={"path": _sample_path(tmp_path)})
    run_id = resp.json()["run_id"]

    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if client.get(f"/api/analyses/{run_id}").json()["status"] == "complete":
            break
        time.sleep(0.02)

    events_resp = client.get(f"/api/analyses/{run_id}/events")
    assert events_resp.status_code == 200
    for line in lines:
        assert line in events_resp.text


def test_events_endpoint_404s_for_unknown_run(client):
    resp = client.get("/api/analyses/does-not-exist/events")
    assert resp.status_code == 404
