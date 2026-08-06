"""Entry point for `mal-agent web` (docs/TODO.md Phase 8). The web
backend (web/backend/malagent_web/) is a separate, sibling package to
this one -- not part of the malagent distribution, since it depends on
fastapi/uvicorn (the optional "web" extra) -- so it needs its own
directory added to sys.path before it can be imported. Only reached when
`mal-agent web` is actually invoked (cli.py's lazy import), so a normal
install without the web extra never needs this module to succeed.

Assumes a source checkout where web/ is a sibling of malagent/ (this
project's real deployment model -- git-cloned, not published to PyPI;
see README.md's install instructions), not an arbitrary installed
wheel with no sibling web/ directory."""
from __future__ import annotations
import sys
from pathlib import Path


def _web_backend_dir() -> Path:
    return Path(__file__).resolve().parent.parent / "web" / "backend"


def run(host: str = "127.0.0.1", port: int = 8765) -> None:
    backend_dir = _web_backend_dir()
    if str(backend_dir) not in sys.path:
        sys.path.insert(0, str(backend_dir))
    from malagent_web.app import run as _run
    _run(host=host, port=port)
