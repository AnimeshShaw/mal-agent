"""FastAPI app for mal-agent's local web UI. Thin: calls
malagent.pipeline.analyze() and the reporter/bundle code directly, no
analysis logic duplicated here.

Security posture (a malware-analysis service is a juicy target):
  - uploads are streamed to disk under a size cap, stored as a neutral
    'upload.bin' (never the client's name/extension), and deleted once
    ingest has copied the sample into quarantine;
  - analysing an arbitrary *server-side path* is allowed only when the app
    is bound to loopback (or explicitly enabled);
  - binding to a non-loopback host requires an API token (MAL_AGENT_WEB_TOKEN),
    checked on every /api request;
  - fusion_mode and judge_model are validated; cloud judges honour the
    egress policy exactly as the CLI does.
"""
from __future__ import annotations
import asyncio
import hmac
import os
from pathlib import Path
from tempfile import mkdtemp
from typing import Optional

from fastapi import FastAPI, Form, HTTPException, Request, UploadFile
from fastapi.responses import (FileResponse, HTMLResponse, JSONResponse, PlainTextResponse,
                               StreamingResponse)
from fastapi.staticfiles import StaticFiles

from . import runs
from .payload import build_detail

_DEFAULT_FRONTEND_DIST = Path(__file__).resolve().parent.parent.parent / "frontend" / "dist"
_SSE_POLL_INTERVAL_S = 0.2
_DEFAULT_DB_PATH = "malagent_web.db"
_FUSION_MODES = ("simple", "cgef", "judge")
_LOOPBACK = {"127.0.0.1", "localhost", "::1"}
_UPLOAD_CHUNK = 1 << 20


def ensure_default_database_url() -> None:
    """Server-startup concern only, deliberately NOT called by create_app():
    mutating the process environment at import/construct time leaked
    DATABASE_URL into the whole test session once."""
    os.environ.setdefault("DATABASE_URL", f"sqlite:///{_DEFAULT_DB_PATH}")


def _judge_models() -> list[str]:
    env = os.getenv("MAL_AGENT_JUDGE_MODELS")
    if env:
        return [m.strip() for m in env.split(",") if m.strip()]
    return ["ollama:qwen3:8b", "ollama:gemma4:12b"]


def create_app(frontend_dist: Optional[Path] = None, *, store: Optional[runs.RunStore] = None,
               allow_server_paths: bool = True, token: Optional[str] = None,
               max_upload_mb: int = 200) -> FastAPI:
    app = FastAPI(title="mal-agent web")
    frontend_dist = frontend_dist or _DEFAULT_FRONTEND_DIST
    runs.set_store(store)
    max_bytes = max_upload_mb * 1024 * 1024

    if token:
        @app.middleware("http")
        async def _require_token(request: Request, call_next):
            if request.url.path.startswith("/api/") and request.url.path != "/api/health":
                given = (request.headers.get("x-mal-agent-token")
                         or request.query_params.get("token") or "")
                if not hmac.compare_digest(given, token):
                    return JSONResponse({"detail": "missing or invalid token"}, status_code=401)
            return await call_next(request)

    @app.get("/api/health")
    def health():
        return {"status": "ok"}

    @app.get("/api/config")
    def config():
        return {"fusion_modes": list(_FUSION_MODES), "judge_models": _judge_models(),
                "allow_server_paths": allow_server_paths, "max_upload_mb": max_upload_mb,
                "workers": runs._MAX_WORKERS}

    @app.get("/api/analyses")
    def list_analyses(limit: int = 100):
        return {"runs": runs.list_runs(limit=max(1, min(limit, 500)))}

    @app.post("/api/analyses")
    async def create_analysis(
        path: Optional[str] = Form(default=None),
        file: Optional[UploadFile] = None,
        fusion_mode: str = Form(default="simple"),
        judge_model: Optional[str] = Form(default=None),
        enable_models: bool = Form(default=False),
        no_cloud: bool = Form(default=True),
    ):
        if fusion_mode not in _FUSION_MODES:
            raise HTTPException(status_code=400, detail=f"fusion_mode must be one of {_FUSION_MODES}")
        if judge_model:
            from malagent.judge.providers import parse_spec
            try:
                parse_spec(judge_model)
            except ValueError as e:
                raise HTTPException(status_code=400, detail=str(e))
        cleanup_dir, filename = None, None
        if file is not None and file.filename:
            # The client's filename is untrusted: keep only its basename, as
            # display metadata. The bytes land under a neutral name so a
            # sample is never written to disk with an executable extension.
            filename = Path(file.filename).name or "upload.bin"
            cleanup_dir = mkdtemp(prefix="malagent_web_")
            target = Path(cleanup_dir) / "upload.bin"
            size = 0
            with open(target, "wb") as fh:
                while chunk := await file.read(_UPLOAD_CHUNK):
                    size += len(chunk)
                    if size > max_bytes:
                        fh.close()
                        import shutil
                        shutil.rmtree(cleanup_dir, ignore_errors=True)
                        raise HTTPException(status_code=413,
                                            detail=f"upload exceeds {max_upload_mb} MB")
                    fh.write(chunk)
            target_path = str(target)
        elif path:
            if not allow_server_paths:
                raise HTTPException(status_code=403,
                                    detail="server-side paths are disabled on this deployment")
            if not Path(path).is_file():
                raise HTTPException(status_code=400, detail=f"{path} not found")
            target_path, filename = path, Path(path).name
        else:
            raise HTTPException(status_code=400, detail="either 'path' or 'file' is required")

        from malagent.contracts import EgressPolicy
        run = runs.start_run(target_path, filename=filename, detail_fn=build_detail,
                             cleanup_dir=cleanup_dir, fusion_mode=fusion_mode,
                             judge_model=judge_model or None, enable_models=enable_models,
                             policy=EgressPolicy(allow_cloud=not no_cloud))
        return {"run_id": run.run_id, "status": run.status}

    @app.get("/api/analyses/{run_id}")
    def get_analysis(run_id: str):
        run = runs.get_run(run_id)
        if run is None:
            raise HTTPException(status_code=404, detail="run not found")
        result = run.summary()
        if run.status == "error":
            result["error"] = run.error
        if run.status == "complete":
            detail = run.detail
            if detail is None and run.state is not None:  # detail_fn not supplied
                detail = build_detail(run.state, run.verdict)
            result.update(detail or {})
            result["progress"] = run.progress[-400:]
        return result

    @app.get("/api/analyses/{run_id}/events")
    async def get_events(run_id: str):
        run = runs.get_run(run_id)
        if run is None:
            raise HTTPException(status_code=404, detail="run not found")

        async def _stream():
            sent = 0
            while True:
                lines = run.progress[sent:]
                for line in lines:
                    yield f"data: {line}\n\n"
                sent += len(lines)
                if run.status in ("complete", "error"):
                    yield f"event: done\ndata: {run.status}\n\n"
                    return
                await asyncio.sleep(_SSE_POLL_INTERVAL_S)

        return StreamingResponse(_stream(), media_type="text/event-stream")

    def _completed_run_or_404(run_id: str) -> runs.Run:
        run = runs.get_run(run_id)
        if run is None or run.status != "complete":
            raise HTTPException(status_code=404, detail="report not ready")
        return run

    @app.get("/api/analyses/{run_id}/report.txt", response_class=PlainTextResponse)
    def get_report_txt(run_id: str):
        return _completed_run_or_404(run_id).report_txt

    @app.get("/api/analyses/{run_id}/report.html", response_class=HTMLResponse)
    def get_report_html(run_id: str):
        # The HTML report escapes every sample-derived string (see
        # reporter._e); serve it with a CSP that forbids scripts anyway.
        html = _completed_run_or_404(run_id).report_html
        return HTMLResponse(html, headers={"Content-Security-Policy":
                                           "default-src 'none'; style-src 'unsafe-inline'"})

    @app.get("/api/analyses/{run_id}/report.md", response_class=PlainTextResponse)
    def get_report_md(run_id: str):
        return _completed_run_or_404(run_id).report_md

    assets_dir = frontend_dist / "assets"
    if frontend_dist.is_dir() and assets_dir.is_dir():
        app.mount("/assets", StaticFiles(directory=assets_dir), name="frontend-assets")

        @app.get("/{full_path:path}")
        async def spa_fallback(full_path: str):
            if full_path.startswith("api/"):
                raise HTTPException(status_code=404, detail="not found")
            index = frontend_dist / "index.html"
            if not index.is_file():
                raise HTTPException(status_code=404, detail="not found")
            return FileResponse(index)

    return app


app = create_app()


def run(host: str = "127.0.0.1", port: int = 8765) -> None:
    ensure_default_database_url()
    token = os.getenv("MAL_AGENT_WEB_TOKEN") or None
    loopback = host in _LOOPBACK
    if not loopback and not token:
        raise SystemExit("refusing to bind mal-agent web to a non-loopback address without an "
                         "API token: set MAL_AGENT_WEB_TOKEN (clients send it as the "
                         "X-Mal-Agent-Token header).")
    allow_paths = loopback or os.getenv("MAL_AGENT_WEB_ALLOW_SERVER_PATHS") == "1"
    store = runs.RunStore(os.getenv("MAL_AGENT_WEB_DB", _DEFAULT_DB_PATH))
    import uvicorn
    uvicorn.run(create_app(store=store, allow_server_paths=allow_paths, token=token,
                           max_upload_mb=int(os.getenv("MAL_AGENT_MAX_UPLOAD_MB", "200"))),
                host=host, port=port)
