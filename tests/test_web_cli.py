"""malagent.web_cli: the lazy-imported entry point cli.py's `mal-agent web`
subcommand reaches. web/backend/malagent_web/ is a sibling package to
malagent/, not part of its distribution (depends on fastapi/uvicorn, the
optional "web" extra) -- this module's whole job is finding and importing
it correctly regardless of the caller's current working directory."""
from __future__ import annotations
import sys
from malagent import web_cli


def test_web_backend_dir_points_at_the_real_sibling_directory():
    backend_dir = web_cli._web_backend_dir()
    assert backend_dir.name == "backend"
    assert backend_dir.parent.name == "web"
    assert (backend_dir / "malagent_web" / "app.py").is_file()


def test_run_adds_the_backend_dir_to_sys_path_and_calls_through(monkeypatch):
    captured = {}

    # Import for real first (this dev checkout has the real web/backend/
    # available), then monkeypatch the inner run() so this test doesn't
    # actually start a uvicorn server.
    backend_dir = str(web_cli._web_backend_dir())
    if backend_dir not in sys.path:
        sys.path.insert(0, backend_dir)
    import malagent_web.app as web_app

    def _fake_run(host, port):
        captured["host"] = host
        captured["port"] = port

    monkeypatch.setattr(web_app, "run", _fake_run)

    web_cli.run(host="0.0.0.0", port=9000)
    assert captured == {"host": "0.0.0.0", "port": 9000}
