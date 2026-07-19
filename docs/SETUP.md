# MAL-AGENT Setup Guide

Two install paths. Both start the same way; the full-automation path adds
the heavy external tools (Ghidra, capa's rules/sigs, Ollama, Postgres) on
top.

## Quick path: `mal-agent doctor` first

Whichever path you choose, `mal-agent doctor` tells you what's configured
and what isn't (PASS/WARN/FAIL) — run it after installing to confirm
things actually work, not just that files exist.

## Path A: Python-only (fast, manual tool setup after)

```powershell
# Windows
.\scripts\install.ps1
```
```bash
# Linux/macOS
./scripts/install.sh
```

Installs the package + all optional Python extras, scaffolds `.env`.
Leaves Ghidra/capa-rules/Ollama/Postgres for you to install manually — see
"Manual tool setup" below.

## Path B: Full automation (one command, ~5-6GB of downloads)

```powershell
# Windows -- verified live this project's own setup session
.\scripts\install-full.ps1
```
```bash
# Linux/macOS -- written to the same intent, NOT yet verified live
./scripts/install-full.sh
```

Runs Path A, then downloads/installs a JDK, Ghidra, capa-rules + FLIRT
sigs (version-matched to the capa version just installed), Ollama +
`qwen2.5-coder:7b`, and brings up Postgres via `docker compose`. Prompts
before each large download; pass `-Yes` (PowerShell) / `--yes` (bash) for
unattended/CI use.

**The Linux/macOS variant has not been run on a real Linux or macOS
machine** — this project's entire live-verification history is Windows.
Treat it as a documented best-effort translation of the verified Windows
steps, not a tested equal. Report back what breaks.

## Manual tool setup (what Path A leaves undone)

Each of these was verified working live during this project's own setup —
exact commands, not guesses.

### capa (capability/ATT&CK mapping)

```bash
pip install flare-capa
```

`pip install flare-capa` does **not** bundle capa's rules or FLIRT
signatures. Without them, capa fails with `"default embedded rules not
found"`. Download both, version-matched to your installed capa:

- Rules: `https://github.com/mandiant/capa-rules/releases` — pick the tag
  matching `capa --version`
- FLIRT sigs: the three `.sig` files under `sigs/` in
  `https://github.com/mandiant/capa` at the matching tag

Set `CAPA_RULES_PATH` and `CAPA_SIGS_PATH` (see `.env.example`) to where
you extracted them.

### Ghidra (per-function decompilation)

Requires a real Ghidra install **and** JDK 21+ **and** `pip install
pyghidra` (Ghidra ≥11 no longer bundles Jython for scripting by default —
`pyghidra` drives Ghidra's Java API directly instead of the older
subprocess+script approach).

1. Install a JDK 21+ (e.g. Eclipse Temurin).
2. Download Ghidra from `https://github.com/NationalSecurityAgency/ghidra/releases`,
   extract it anywhere.
3. Set `GHIDRA_HOME` to the extracted Ghidra directory (the one containing
   `support/analyzeHeadless`).
4. `pip install pyghidra`.

### Ollama (local model)

```bash
# Windows: winget install Ollama.Ollama
# Linux/macOS: curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen2.5-coder:7b
```

### Postgres (optional — in-memory repository is the supported default)

```bash
docker compose up -d db
```

Host port **5433**, not 5432 — see the comment in `docker-compose.yml`.
Set `DATABASE_URL` per `.env.example` (already points at 5433).

## Troubleshooting (real bugs hit during this project's own setup)

- **`GHIDRA_HOME` vs `GHIDRA_INSTALL_DIR`.** Only `GHIDRA_HOME` needs to be
  set — `ghidra_tool.py` passes it through to `pyghidra.start(install_dir=...)`
  explicitly. If you see `pyghidra` complaining about a missing install
  dir despite `GHIDRA_HOME` being set correctly, run `mal-agent doctor` to
  confirm `pyghidra` itself is actually importable (`pip install pyghidra`
  is a separate step from installing Ghidra itself).
- **`"Ghidra was not started with PyGhidra. Python is not available"`** —
  this means something is trying to invoke a `.py` Ghidra script the old
  (subprocess + Jython postScript) way. This project's `GhidraTool` was
  rewritten to avoid this entirely (drives Ghidra's Java API directly via
  `pyghidra`, in-process) — if you see this error, you're not running the
  current code.
- **`capa: default embedded rules not found!`** — `CAPA_RULES_PATH` isn't
  set or points somewhere without capa rules in it. Run `mal-agent doctor`
  to confirm.
- **Postgres port 5432 already in use / `docker compose up -d db` starts
  but `mal-agent doctor` still reports `database: FAIL`.** Another
  Postgres instance (a different project, a system service) is already on
  port 5432. Docker will start the container without error but silently
  fail to bind the port — `docker port mal-agent-db-1` will show no
  binding. This project's `docker-compose.yml` already uses port 5433
  specifically to avoid this; if you changed it back to 5432, change it
  back to a free port, or find and stop whatever else owns 5432.
