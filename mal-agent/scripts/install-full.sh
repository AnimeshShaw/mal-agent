#!/usr/bin/env bash
# MAL-AGENT full-automation installer (Linux/macOS). Runs install.sh, then
# installs a JDK, Ghidra, capa-rules+sigs (version-matched to the
# installed capa), Ollama + model pull, and brings up Postgres via docker
# compose.
#
# UNVERIFIED: this project's live-testing history is Windows-only (see
# docs/TODO.md, docs/AUDIT.md). This script is written to the same intent
# as install-full.ps1 but has not been run on Linux or macOS. Verify each
# step manually the first time it's used and report/fix any drift before
# trusting it for unattended use.
set -euo pipefail

YES=0
INSTALL_DIR="${INSTALL_DIR:-$HOME/mal-agent-tools}"
for arg in "$@"; do
    case "$arg" in
        --yes) YES=1 ;;
    esac
done

confirm() {
    if [ "$YES" -eq 1 ]; then return 0; fi
    read -r -p "$1 [y/N] " response
    [ "$response" = "y" ] || [ "$response" = "Y" ]
}

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
"$REPO_ROOT/scripts/install.sh"

mkdir -p "$INSTALL_DIR"

# JDK 21
if ! command -v java >/dev/null 2>&1; then
    if confirm "Install a JDK 21 (apt: openjdk-21-jdk / brew: openjdk@21)?"; then
        if command -v apt-get >/dev/null 2>&1; then
            sudo apt-get update && sudo apt-get install -y openjdk-21-jdk
        elif command -v brew >/dev/null 2>&1; then
            brew install openjdk@21
        else
            echo "No known package manager found -- install a JDK 21 manually, then re-run."
        fi
    fi
else
    echo "java already on PATH, skipping JDK install."
fi

# Ghidra
existing_ghidra="$(find / -maxdepth 3 -type d -name 'ghidra_*' 2>/dev/null | head -1 || true)"
if [ -z "$existing_ghidra" ]; then
    if confirm "Download and install Ghidra (~570MB) to $INSTALL_DIR?"; then
        echo "Fetching latest Ghidra release metadata..."
        asset_url="$(curl -sL https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest \
            | grep -o '"browser_download_url": *"[^"]*\.zip"' | head -1 | cut -d'"' -f4)"
        curl -L "$asset_url" -o "$INSTALL_DIR/ghidra.zip"
        unzip -q "$INSTALL_DIR/ghidra.zip" -d "$INSTALL_DIR"
        rm "$INSTALL_DIR/ghidra.zip"
        existing_ghidra="$(find "$INSTALL_DIR" -maxdepth 1 -type d -name 'ghidra_*' | head -1)"
    fi
else
    echo "Ghidra already found at $existing_ghidra, skipping download."
fi
if [ -n "$existing_ghidra" ]; then
    echo "export GHIDRA_HOME=\"$existing_ghidra\"" >> "$HOME/.profile"
    echo "Added GHIDRA_HOME to ~/.profile = $existing_ghidra (source it or restart your shell)"
fi

# capa-rules + FLIRT sigs, version-matched to the installed capa
capa_version="$("$REPO_ROOT/.venv/bin/python" -m pip show flare-capa 2>/dev/null | grep '^Version:' | awk '{print $2}')"
if [ -n "$capa_version" ]; then
    if confirm "Download capa-rules v$capa_version and FLIRT sigs?"; then
        rules_dir="$INSTALL_DIR/capa-rules-$capa_version"
        if [ ! -d "$rules_dir" ]; then
            curl -L "https://github.com/mandiant/capa-rules/archive/refs/tags/v$capa_version.zip" \
                -o "$INSTALL_DIR/capa-rules.zip"
            unzip -q "$INSTALL_DIR/capa-rules.zip" -d "$INSTALL_DIR"
            rm "$INSTALL_DIR/capa-rules.zip"
        fi
        sigs_dir="$INSTALL_DIR/capa-sigs"
        mkdir -p "$sigs_dir"
        for sig in 1_flare_msvc_rtf_32_64.sig 2_flare_msvc_atlmfc_32_64.sig 3_flare_common_libs.sig; do
            curl -L "https://raw.githubusercontent.com/mandiant/capa/v$capa_version/sigs/$sig" \
                -o "$sigs_dir/$sig"
        done
        {
            echo "export CAPA_RULES_PATH=\"$rules_dir\""
            echo "export CAPA_SIGS_PATH=\"$sigs_dir\""
        } >> "$HOME/.profile"
        echo "Added CAPA_RULES_PATH and CAPA_SIGS_PATH to ~/.profile"
    fi
else
    echo "flare-capa not installed (install.sh should have installed it) -- skipping rules/sigs."
fi

# Ollama + model pull
if ! command -v ollama >/dev/null 2>&1; then
    if confirm "Install Ollama (curl https://ollama.com/install.sh | sh)?"; then
        curl -fsSL https://ollama.com/install.sh | sh
    fi
fi
if command -v ollama >/dev/null 2>&1 && confirm "Pull qwen2.5-coder:7b (~4.7GB)?"; then
    ollama pull qwen2.5-coder:7b
fi

# Postgres
if confirm "Bring up Postgres via docker compose (requires Docker)?"; then
    docker compose -f "$REPO_ROOT/docker-compose.yml" up -d db
fi

echo ""
echo "Full installation complete. Source ~/.profile (or restart your shell)"
echo "to pick up new environment variables, then run: mal-agent doctor"
