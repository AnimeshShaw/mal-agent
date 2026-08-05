"""FastAPI app for mal-agent's local web UI (docs/TODO.md Phase 8). Thin:
imports and calls malagent.pipeline.analyze()/reporter render functions
directly -- no analysis logic duplicated here. Runs each analysis in a
background thread (see runs.py) so POST /api/analyses returns immediately
instead of blocking on a Ghidra-backed run that can take minutes."""
from __future__ import annotations
import os
from pathlib import Path
from tempfile import mkdtemp
from typing import Optional

from fastapi import FastAPI, Form, HTTPException, UploadFile
from fastapi.responses import HTMLResponse, PlainTextResponse

from . import runs

# malagent.pipeline.analyze() persists every run via malagent.store.get_repository(),
# which reads DATABASE_URL: unset -> in-memory (doesn't survive past a single
# call), sqlite:/// -> local file, otherwise -> Postgres. The web UI runs many
# analyses across the lifetime of one server process and a user reasonably
# expects past runs to still be there after a page reload, so it defaults to a
# local SQLite file (not Postgres -- no server process required) unless the
# operator has already set DATABASE_URL themselves.
_DEFAULT_DB_PATH = "malagent_web.db"


def ensure_default_database_url() -> None:
    """Deliberately NOT called by create_app() itself: mutating the real
    process environment as a side effect of merely constructing (or
    testing) the app object caused a real bug during development -- the
    module-level `app = create_app()` below runs at import time, so an
    env mutation inside create_app() fired the moment pytest collected
    this module, before any test or fixture ran, leaking DATABASE_URL
    (and creating a stray malagent_web.db in the repo root) for the rest
    of the test session regardless of any test-level cleanup. This is a
    server-startup concern only -- see run() below."""
    os.environ.setdefault("DATABASE_URL", f"sqlite:///{_DEFAULT_DB_PATH}")


def create_app() -> FastAPI:
    app = FastAPI(title="mal-agent web")

    @app.get("/api/health")
    def health():
        return {"status": "ok"}

    @app.post("/api/analyses")
    async def create_analysis(
        path: Optional[str] = Form(default=None),
        file: Optional[UploadFile] = None,
        fusion_mode: str = Form(default="simple"),
        enable_models: bool = Form(default=False),
        no_cloud: bool = Form(default=False),
    ):
        if file is not None and file.filename:
            dest_dir = Path(mkdtemp(prefix="malagent_web_"))
            target = dest_dir / file.filename
            target.write_bytes(await file.read())
            target_path = str(target)
        elif path:
            if not Path(path).exists():
                raise HTTPException(status_code=400, detail=f"{path} not found")
            target_path = path
        else:
            raise HTTPException(status_code=400, detail="either 'path' or 'file' is required")

        from malagent.contracts import EgressPolicy
        policy = EgressPolicy(allow_cloud=not no_cloud)
        run = runs.start_run(target_path, fusion_mode=fusion_mode,
                             enable_models=enable_models, policy=policy)
        return {"run_id": run.run_id, "status": run.status}

    @app.get("/api/analyses/{run_id}")
    def get_analysis(run_id: str):
        run = runs.get_run(run_id)
        if run is None:
            raise HTTPException(status_code=404, detail="run not found")
        result = {"run_id": run.run_id, "status": run.status}
        if run.status == "error":
            result["error"] = run.error
        if run.status == "complete" and run.verdict is not None:
            result["verdict"] = run.verdict.model_dump(mode="json")
        return result

    @app.get("/api/analyses/{run_id}/report.txt", response_class=PlainTextResponse)
    def get_report_txt(run_id: str):
        run = _completed_run_or_404(run_id)
        return run.report_txt

    @app.get("/api/analyses/{run_id}/report.html", response_class=HTMLResponse)
    def get_report_html(run_id: str):
        run = _completed_run_or_404(run_id)
        return run.report_html

    @app.get("/api/analyses/{run_id}/report.md", response_class=PlainTextResponse)
    def get_report_md(run_id: str):
        run = _completed_run_or_404(run_id)
        return run.report_md

    def _completed_run_or_404(run_id: str) -> runs.Run:
        run = runs.get_run(run_id)
        if run is None or run.status != "complete":
            raise HTTPException(status_code=404, detail="report not ready")
        return run

    return app


app = create_app()


def run(host: str = "127.0.0.1", port: int = 8765) -> None:
    ensure_default_database_url()
    import uvicorn
    uvicorn.run(app, host=host, port=port)
