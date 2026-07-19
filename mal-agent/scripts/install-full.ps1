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

# Ollama + model pull
if (-not (Get-Command ollama -ErrorAction SilentlyContinue)) {
    if (Confirm-Step "Install Ollama via winget?") {
        winget install --id Ollama.Ollama --source winget `
            --accept-package-agreements --accept-source-agreements -e
    }
}
if ((Get-Command ollama -ErrorAction SilentlyContinue) -and
    (Confirm-Step "Pull qwen2.5-coder:7b (~4.7GB)?")) {
    ollama pull qwen2.5-coder:7b
}

# Postgres
if (Confirm-Step "Bring up Postgres via docker compose (requires Docker)?") {
    docker compose -f "$RepoRoot\docker-compose.yml" up -d db
}

Write-Host ""
Write-Host "Full installation complete. Restart your shell to pick up new"
Write-Host "environment variables (GHIDRA_HOME, CAPA_RULES_PATH, CAPA_SIGS_PATH),"
Write-Host "then run: mal-agent doctor"
