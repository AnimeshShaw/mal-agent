# MAL-AGENT Python-only installer (Windows). Creates a venv, installs the
# package with its optional extras, and scaffolds .env. Leaves Ghidra,
# capa-rules/sigs, Ollama, and Postgres as documented manual steps -- see
# docs/SETUP.md, or run scripts/install-full.ps1 to automate those too.
$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

Write-Host "Creating virtual environment (.venv)..."
python -m venv .venv

Write-Host "Installing mal-agent with full/providers/ghidra extras..."
& .\.venv\Scripts\python.exe -m pip install --upgrade pip
& .\.venv\Scripts\python.exe -m pip install -e ".[full,providers,ghidra]"

if (-not (Test-Path ".env")) {
    Write-Host "Creating .env from .env.example..."
    Copy-Item ".env.example" ".env"
} else {
    Write-Host ".env already exists, leaving it untouched."
}

Write-Host ""
Write-Host "Done. Next steps:"
Write-Host "  1. .\.venv\Scripts\Activate.ps1"
Write-Host "  2. Edit .env with your configuration (API keys, GHIDRA_HOME, etc.)"
Write-Host "  3. mal-agent doctor"
Write-Host "  4. See docs\SETUP.md for installing Ghidra, capa-rules/sigs, Ollama, Postgres."
