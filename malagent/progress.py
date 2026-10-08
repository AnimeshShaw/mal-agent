"""Per-run progress lines. Agents call emit(); it prints (the CLI's
behavior, unchanged) and also forwards the line to the callback bound for
the current run via progress_to() -- a context variable, so concurrent runs
in different threads (the web UI) never see each other's lines."""
from __future__ import annotations
import contextvars
from contextlib import contextmanager
from typing import Callable, Optional

_cb: contextvars.ContextVar[Optional[Callable[[str], None]]] = contextvars.ContextVar(
    "mal_agent_progress_cb", default=None)


def emit(*parts, flush: bool = True, **_ignored) -> None:
    line = " ".join(str(p) for p in parts)
    print(line, flush=flush)
    cb = _cb.get()
    if cb is not None:
        try:
            cb(line)
        except Exception:
            pass  # a UI listener must never break an analysis


@contextmanager
def progress_to(cb: Optional[Callable[[str], None]]):
    token = _cb.set(cb)
    try:
        yield
    finally:
        _cb.reset(token)
