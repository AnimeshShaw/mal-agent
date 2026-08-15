# MAL-AGENT Python-only installer (Windows). Creates a venv, installs the
# package with its optional extras (including the web UI's fastapi/uvicorn),
# builds the web UI's frontend if Node.js is available, and scaffolds .env.
# Leaves Ghidra, capa-rules/sigs, Ollama, and Postgres as documented manual
# steps -- see docs/SETUP.md, or run scripts/install-full.ps1 to automate
# those too.
$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

Write-Host "Creating virtual environment (.venv)..."
python -m venv .venv

Write-Host "Installing mal-agent with full/providers/ghidra/web extras..."
& .\.venv\Scripts\python.exe -m pip install --upgrade pip
& .\.venv\Scripts\python.exe -m pip install -e ".[full,providers,ghidra,web]"

if (-not (Test-Path ".env")) {
    Write-Host "Creating .env from .env.example..."
    Copy-Item ".env.example" ".env"
} else {
    Write-Host ".env already exists, leaving it untouched."
}

$webUiBuilt = $false
if (Get-Command npm -ErrorAction SilentlyContinue) {
    Write-Host ""
    Write-Host "Node.js found -- building the web UI frontend..."
    Push-Location "web\frontend"
    npm install
    npm run build
    Pop-Location
    $webUiBuilt = $true
} else {
    Write-Host ""
    Write-Host "npm not found on PATH -- skipping the web UI frontend build."
    Write-Host "Install Node.js (https://nodejs.org, LTS) and re-run:"
    Write-Host "  cd web\frontend; npm install; npm run build"
    Write-Host "'mal-agent web' still works without this (serves the JSON API alone;"
    Write-Host "the browser UI needs the built frontend)."
}

Write-Host ""
Write-Host "Done. Next steps:"
Write-Host "  1. .\.venv\Scripts\Activate.ps1"
Write-Host "  2. Edit .env with your configuration (API keys, GHIDRA_HOME, etc.)"
Write-Host "  3. mal-agent doctor"
if ($webUiBuilt) {
    Write-Host "  4. mal-agent web   (then open http://127.0.0.1:8765)"
} else {
    Write-Host "  4. mal-agent analyze <sample>   (or build the web UI frontend first -- see above)"
}
Write-Host "  5. See docs\SETUP.md for installing Ghidra, capa-rules/sigs, Ollama, Postgres."
