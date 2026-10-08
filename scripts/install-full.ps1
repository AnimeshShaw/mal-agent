# MAL-AGENT full-automation installer (Windows). Runs install.ps1, then
# installs JDK 21, Ghidra, capa-rules+sigs (version-matched to the
# installed capa), Ollama + model pull, and brings up Postgres via docker
# compose. Mirrors the exact commands verified live in this project's own
# setup session (docs/TODO.md M2 setup notes). Large downloads (~5-6GB
# total) -- confirms before each one unless -Yes is passed.
param(
    [switch]$Yes,
    [string]$InstallDir = "C:\mal-agent-tools"
)
$ErrorActionPreference = "Stop"

function Confirm-Step($message) {
    if ($Yes) { return $true }
    $response = Read-Host "$message [y/N]"
    return ($response -eq "y" -or $response -eq "Y")
}

$RepoRoot = Split-Path -Parent $PSScriptRoot
& "$PSScriptRoot\install.ps1"

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

# JDK 21
if (-not (Get-Command java -ErrorAction SilentlyContinue)) {
    if (Confirm-Step "Install Eclipse Temurin JDK 21 via winget?") {
        winget install --id EclipseAdoptium.Temurin.21.JDK --source winget `
            --accept-package-agreements --accept-source-agreements -e
    }
} else {
    Write-Host "java already on PATH, skipping JDK install."
}

# Ghidra
$existingGhidra = Get-ChildItem -Path "C:\" -Directory -Filter "ghidra_*" -ErrorAction SilentlyContinue |
    Select-Object -First 1
if (-not $existingGhidra) {
    if (Confirm-Step "Download and install Ghidra (~570MB) to $InstallDir?") {
        Write-Host "Fetching latest Ghidra release metadata..."
        $release = Invoke-RestMethod -Uri "https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest"
        $asset = $release.assets | Where-Object { $_.name -like "*.zip" } | Select-Object -First 1
        $zipPath = Join-Path $InstallDir "ghidra.zip"
        Write-Host "Downloading $($asset.browser_download_url)..."
        Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $zipPath
        Write-Host "Extracting..."
        Expand-Archive -Path $zipPath -DestinationPath $InstallDir -Force
        Remove-Item $zipPath
        $existingGhidra = Get-ChildItem -Path $InstallDir -Directory -Filter "ghidra_*" | Select-Object -First 1
    }
} else {
    Write-Host "Ghidra already found at $($existingGhidra.FullName), skipping download."
}
if ($existingGhidra) {
    [System.Environment]::SetEnvironmentVariable("GHIDRA_HOME", $existingGhidra.FullName, "User")
    Write-Host "Set GHIDRA_HOME (User) = $($existingGhidra.FullName)"
}

# capa-rules + FLIRT sigs, version-matched to the installed capa
$capaVersionLine = & "$RepoRoot\.venv\Scripts\python.exe" -m pip show flare-capa 2>$null |
    Select-String "^Version:"
if ($capaVersionLine) {
    $capaVersion = ($capaVersionLine.ToString() -split "\s+")[1]
    if (Confirm-Step "Download capa-rules v$capaVersion and FLIRT sigs?") {
        $rulesDir = Join-Path $InstallDir "capa-rules-$capaVersion"
        if (-not (Test-Path $rulesDir)) {
            $rulesZip = Join-Path $InstallDir "capa-rules.zip"
            Invoke-WebRequest -Uri "https://github.com/mandiant/capa-rules/archive/refs/tags/v$capaVersion.zip" `
                -OutFile $rulesZip
            Expand-Archive -Path $rulesZip -DestinationPath $InstallDir -Force
            Remove-Item $rulesZip
        }
        $sigsDir = Join-Path $InstallDir "capa-sigs"
        New-Item -ItemType Directory -Force -Path $sigsDir | Out-Null
        foreach ($sig in @("1_flare_msvc_rtf_32_64.sig", "2_flare_msvc_atlmfc_32_64.sig",
                           "3_flare_common_libs.sig")) {
            Invoke-WebRequest -Uri "https://raw.githubusercontent.com/mandiant/capa/v$capaVersion/sigs/$sig" `
                -OutFile (Join-Path $sigsDir $sig)
        }
        [System.Environment]::SetEnvironmentVariable("CAPA_RULES_PATH", $rulesDir, "User")
        [System.Environment]::SetEnvironmentVariable("CAPA_SIGS_PATH", $sigsDir, "User")
        Write-Host "Set CAPA_RULES_PATH and CAPA_SIGS_PATH (User)"
    }
} else {
    Write-Host "flare-capa not installed (install.ps1 should have installed it) -- skipping rules/sigs."
}

# Node.js (for the web UI's frontend build -- install.ps1 already builds
# it if npm happens to be present; this installs npm itself when missing)
if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
    if (Confirm-Step "Install Node.js LTS via winget (needed for the web UI)?") {
        winget install --id OpenJS.NodeJS.LTS --source winget `
            --accept-package-agreements --accept-source-agreements -e
        Write-Host "Node.js installed -- restart your shell, then run:"
        Write-Host "  cd web\frontend; npm install; npm run build"
    }
} else {
    Write-Host "npm already on PATH, skipping Node.js install."
    if (-not (Test-Path "$RepoRoot\web\frontend\dist")) {
        Push-Location "$RepoRoot\web\frontend"
        npm install
        npm run build
        Pop-Location
    }
}

# Ollama + model pull
if (-not (Get-Command ollama -ErrorAction SilentlyContinue)) {
    if (Confirm-Step "Install Ollama via winget?") {
        winget install --id Ollama.Ollama --source winget `
            --accept-package-agreements --accept-source-agreements -e
    }
}
if (Get-Command ollama -ErrorAction SilentlyContinue) {
    # Both local models actually evaluated in this project's own research
    # (docs/RESEARCH.md): qwen3:8b (best coverage, 84.9%) and gemma4:12b
    # (best local FPR, 8.3%). Pull both so --judge-model can use either.
    if (Confirm-Step "Pull qwen3:8b (~5GB)?") {
        ollama pull qwen3:8b
    }
    if (Confirm-Step "Pull gemma4:12b (~8GB)?") {
        ollama pull gemma4:12b
    }
}

# EMBER2024 PE classifier model -- the ~3.8MB .model file this project's
# EMBER_MODEL_PATH expects, fetched directly from the public HF repo (no
# auth, no need to clone the full 512MB model family or the 3.2M-file
# dataset -- see docs/RESEARCH.md §1 for why PE-only).
$emberModelPath = "$InstallDir\EMBER2024_PE.model"
if (-not (Test-Path $emberModelPath)) {
    if (Confirm-Step "Download the EMBER2024 PE classifier model (~3.8MB)?") {
        Invoke-WebRequest -Uri "https://huggingface.co/joyce8/EMBER2024-benchmark-models/resolve/main/EMBER2024_PE.model" `
            -OutFile $emberModelPath
        [Environment]::SetEnvironmentVariable("EMBER_MODEL_PATH", $emberModelPath, "User")
        Write-Host "Downloaded to $emberModelPath and set EMBER_MODEL_PATH (User scope -- restart your shell)."
    }
} else {
    Write-Host "EMBER model already found at $emberModelPath, skipping download."
}

# Postgres
if (Confirm-Step "Bring up Postgres via docker compose (requires Docker)?") {
    docker compose -f "$RepoRoot\docker-compose.yml" up -d db
}

Write-Host ""
Write-Host "Full installation complete. Restart your shell to pick up new"
Write-Host "environment variables (GHIDRA_HOME, CAPA_RULES_PATH, CAPA_SIGS_PATH),"
Write-Host "then run: mal-agent doctor"
