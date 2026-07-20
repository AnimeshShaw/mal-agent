#!/usr/bin/env bash
# MAL-AGENT Python-only installer (Linux/macOS). Creates a venv, installs
# the package with its optional extras, and scaffolds .env. Leaves Ghidra,
# capa-rules/sigs, Ollama, and Postgres as documented manual steps -- see
# docs/SETUP.md, or run scripts/install-full.sh to automate those too.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "Creating virtual environment (.venv)..."
python3 -m venv .venv

echo "Installing mal-agent with full/providers/ghidra extras..."
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e ".[full,providers,ghidra]"

if [ ! -f .env ]; then
    echo "Creating .env from .env.example..."
    cp .env.example .env
else
    echo ".env already exists, leaving it untouched."
fi

echo ""
echo "Done. Next steps:"
echo "  1. source .venv/bin/activate"
echo "  2. Edit .env with your configuration (API keys, GHIDRA_HOME, etc.)"
echo "  3. mal-agent doctor"
echo "  4. See docs/SETUP.md for installing Ghidra, capa-rules/sigs, Ollama, Postgres."
