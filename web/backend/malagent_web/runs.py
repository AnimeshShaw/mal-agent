"""Run registry for the web UI.

Analyses execute in a background worker pool (pipeline.analyze() is fully
synchronous and a Ghidra-backed run takes minutes). Live runs are tracked
in memory; every finished run -- its detail payload and the three rendered
reports -- is persisted to a local SQLite table, so history and report links
survive a server restart (before this, runs lived only in the in-memory
dict and vanished on restart).

Defaults to ONE worker: pyghidra hosts the JVM inside this process, so
concurrent Ghidra runs in threads are not safe. MAL_AGENT_WEB_WORKERS
raises it for deployments without Ghidra.
"""
from __future__ import annotations
import json
import os
import shutil
import sqlite3
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from malagent import pipeline as pipeline_module

_MAX_WORKERS = int(os.getenv("MAL_AGENT_WEB_WORKERS", "1"))
_executor = ThreadPoolExecutor(max_workers=_MAX_WORKERS)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class Run:
    run_id: str
    status: str = "queued"  # queued -> running -> complete | error
    error: Optional[str] = None
    created_at: str = field(default_factory=_now)
    finished_at: Optional[str] = None
    filename: Optional[str] = None
    fusion_mode: str = "simple"
    state: Optional[Any] = None
    verdict: Optional[Any] = None
    detail: Optional[dict] = None          # the API payload, once complete
    report_md: Optional[str] = None
    report_txt: Optional[str] = None
    report_html: Optional[str] = None
    # Appended to, never replaced: the SSE endpoint replays everything so far
    # to a client that connects (or reconnects) mid-run.
    progress: list[str] = field(default_factory=list)

    def summary(self) -> dict:
        v = (self.detail or {}).get("verdict") or {}
        s = (self.detail or {}).get("sample") or {}
        return {"run_id": self.run_id, "status": self.status, "created_at": self.created_at,
                "finished_at": self.finished_at, "filename": self.filename,
                "fusion_mode": self.fusion_mode, "verdict": v.get("verdict"),
                "confidence": v.get("confidence"), "sha256": s.get("sha256"),
                "format": s.get("format"), "error": self.error}


class RunStore:
    """SQLite persistence for finished runs (stdlib sqlite3; one table)."""

    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.execute("""CREATE TABLE IF NOT EXISTS web_runs (
            run_id TEXT PRIMARY KEY, status TEXT, error TEXT, created_at TEXT, finished_at TEXT,
            filename TEXT, fusion_mode TEXT, detail TEXT, report_md TEXT, report_txt TEXT,
            report_html TEXT)""")
        self._db.commit()

    def save(self, run: Run) -> None:
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO web_runs VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (run.run_id, run.status, run.error, run.created_at, run.finished_at, run.filename,
                 run.fusion_mode, json.dumps(run.detail) if run.detail is not None else None,
                 run.report_md, run.report_txt, run.report_html))
            self._db.commit()

    def load(self, run_id: str) -> Optional[Run]:
        with self._lock:
            row = self._db.execute("SELECT * FROM web_runs WHERE run_id=?", (run_id,)).fetchone()
        return self._row_to_run(row) if row else None

    def list(self, limit: int = 100) -> list[Run]:
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM web_runs ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        return [self._row_to_run(r) for r in rows]

    @staticmethod
    def _row_to_run(row) -> Run:
        (run_id, status, error, created_at, finished_at, filename, fusion_mode, detail,
         md, txt, html) = row
        return Run(run_id=run_id, status=status, error=error, created_at=created_at,
                   finished_at=finished_at, filename=filename, fusion_mode=fusion_mode or "simple",
                   detail=json.loads(detail) if detail else None, report_md=md, report_txt=txt,
                   report_html=html)


_runs: dict[str, Run] = {}
_lock = threading.Lock()
_store: Optional[RunStore] = None


def set_store(store: Optional[RunStore]) -> None:
    global _store
    _store = store


def _execute(run: Run, path: str, kwargs: dict, detail_fn: Optional[Callable],
             cleanup_dir: Optional[str]) -> None:
    run.status = "running"
    try:
        kwargs = dict(kwargs)
        kwargs["progress_cb"] = run.progress.append
        state, verdict, report_md, report_txt, report_html, audit = pipeline_module.analyze(
            path, **kwargs)
        run.state, run.verdict = state, verdict
        run.report_md, run.report_txt, run.report_html = report_md, report_txt, report_html
        run.detail = detail_fn(state, verdict) if detail_fn else None
        run.status = "complete"
    except OSError as e:
        run.error = (f"{type(e).__name__}: {e}. The sample could not be read back from disk -- "
                     f"on Windows this is usually antivirus quarantining it on arrival. Add an "
                     f"exclusion for the mal-agent quarantine folder (or set MAL_AGENT_UPLOAD_DIR "
                     f"to an excluded folder) and try again.")
        run.status = "error"
    except Exception as e:
        run.error = f"{type(e).__name__}: {e}"
        run.status = "error"
    finally:
        run.finished_at = _now()
        # The sample now lives in quarantine/<sha256>.malz (read-only, defanged
        # extension); the uploaded copy must not linger in a temp directory.
        if cleanup_dir:
            shutil.rmtree(cleanup_dir, ignore_errors=True)
        if _store is not None:
            try:
                _store.save(run)
            except Exception as e:  # persistence failure must not lose the live result
                run.progress.append(f"[web] warning: could not persist run: {e}")


def start_run(path: str, *, filename: Optional[str] = None, detail_fn: Optional[Callable] = None,
              cleanup_dir: Optional[str] = None, **kwargs) -> Run:
    run = Run(run_id=str(uuid.uuid4()), filename=filename,
              fusion_mode=kwargs.get("fusion_mode", "simple"))
    with _lock:
        _runs[run.run_id] = run
    _executor.submit(_execute, run, path, kwargs, detail_fn, cleanup_dir)
    return run


def get_run(run_id: str) -> Optional[Run]:
    with _lock:
        run = _runs.get(run_id)
    if run is None and _store is not None:
        run = _store.load(run_id)
    return run


def list_runs(limit: int = 100) -> list[dict]:
    with _lock:
        live = {r.run_id: r for r in _runs.values()}
    stored = {r.run_id: r for r in (_store.list(limit) if _store is not None else [])}
    stored.update(live)
    runs = sorted(stored.values(), key=lambda r: r.created_at, reverse=True)[:limit]
    return [r.summary() for r in runs]
