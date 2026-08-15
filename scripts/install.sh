#!/usr/bin/env bash
# MAL-AGENT Python-only installer (Linux/macOS). Creates a venv, installs
# the package with its optional extras (including the web UI's fastapi/
# uvicorn), builds the web UI's frontend if Node.js is available, and
# scaffolds .env. Leaves Ghidra, capa-rules/sigs, Ollama, and Postgres as
# documented manual steps -- see docs/SETUP.md, or run
# scripts/install-full.sh to automate those too.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "Creating virtual environment (.venv)..."
python3 -m venv .venv

echo "Installing mal-agent with full/providers/ghidra/web extras..."
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e ".[full,providers,ghidra,web]"

if [ ! -f .env ]; then
    echo "Creating .env from .env.example..."
    cp .env.example .env
else
    echo ".env already exists, leaving it untouched."
fi

WEB_UI_BUILT=0
if command -v npm >/dev/null 2>&1; then
    echo ""
    echo "Node.js found -- building the web UI frontend..."
    (cd web/frontend && npm install && npm run build)
    WEB_UI_BUILT=1
else
    echo ""
    echo "npm not found on PATH -- skipping the web UI frontend build."
    echo "Install Node.js (https://nodejs.org, LTS) and re-run:"
    echo "  cd web/frontend && npm install && npm run build"
    echo "'mal-agent web' still works without this (serves the JSON API alone;"
    echo "the browser UI needs the built frontend)."
fi

echo ""
echo "Done. Next steps:"
echo "  1. source .venv/bin/activate"
echo "  2. Edit .env with your configuration (API keys, GHIDRA_HOME, etc.)"
echo "  3. mal-agent doctor"
if [ "$WEB_UI_BUILT" -eq 1 ]; then
    echo "  4. mal-agent web   (then open http://127.0.0.1:8765)"
else
    echo "  4. mal-agent analyze <sample>   (or build the web UI frontend first -- see above)"
fi
echo "  5. See docs/SETUP.md for installing Ghidra, capa-rules/sigs, Ollama, Postgres."
