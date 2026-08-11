"""In-process background-run registry. malagent.pipeline.analyze() and
everything under it (pyghidra, subprocess calls to capa/diec, requests to
Ollama/VirusTotal) is fully synchronous, blocking code -- Ghidra-backed
runs can take minutes (docs/EFFICIENCY.md's real measured numbers), so
wrapping each run in a background thread (rather than making the whole
pipeline async, out of scope for this rewrite) is what lets
POST /api/analyses return immediately instead of blocking the request."""
from __future__ import annotations
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Optional

from malagent import pipeline as pipeline_module

# Small pool: pyghidra work already spawns its own JVM-equivalent process
# per run, not something to fan out unbounded on a single machine.
_MAX_WORKERS = 4
_executor = ThreadPoolExecutor(max_workers=_MAX_WORKERS)


@dataclass
class Run:
    run_id: str
    status: str = "queued"  # queued -> running -> complete | error
    error: Optional[str] = None
    state: Optional[Any] = None
    verdict: Optional[Any] = None
    report_md: Optional[str] = None
    report_txt: Optional[str] = None
    report_html: Optional[str] = None
    # Progress lines pushed by pipeline.analyze()'s progress_cb -- appended
    # to, never replaced, so the SSE endpoint can replay everything-so-far
    # to a client that connects (or reconnects) after the run has started.
    progress: list[str] = field(default_factory=list)


_runs: dict[str, Run] = {}
_lock = threading.Lock()


def _execute(run: Run, path: str, kwargs: dict) -> None:
    run.status = "running"
    try:
        kwargs = dict(kwargs)
        kwargs["progress_cb"] = run.progress.append
        state, verdict, report_md, report_txt, report_html, audit = pipeline_module.analyze(
            path, **kwargs)
        run.state = state
        run.verdict = verdict
        run.report_md = report_md
        run.report_txt = report_txt
        run.report_html = report_html
        run.status = "complete"
    except Exception as e:
        run.error = str(e)
        run.status = "error"


def start_run(path: str, **kwargs) -> Run:
    run = Run(run_id=str(uuid.uuid4()))
    with _lock:
        _runs[run.run_id] = run
    _executor.submit(_execute, run, path, kwargs)
    return run


def get_run(run_id: str) -> Optional[Run]:
    with _lock:
        return _runs.get(run_id)
