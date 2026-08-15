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

### die / Detect It Easy (optional — packer/compiler identification)

Install `diec` (the CLI build of [die](https://github.com/horsicq/DIE-engine))
and put it on `PATH`. No env var needed. **Not live-verified in this
project's own development** — no `die` installation was available to test
against; the tool degrades to an honest `skipped` result if `diec` isn't
found.

### Postgres (optional — in-memory repository is the supported default)

```bash
docker compose up -d db
```

Host port **5433**, not 5432 — see the comment in `docker-compose.yml`.
Set `DATABASE_URL` per `.env.example` (already points at 5433).

## Web UI (`mal-agent web`)

Not part of "Manual tool setup" above — this is a first-class part of the
product, not an optional external tool, but it needs one thing Path A/B
don't install by default: **Node.js** (LTS, from
[nodejs.org](https://nodejs.org) or your package manager), to build the
frontend once.

```bash
pip install -e ".[web]"          # fastapi, uvicorn, python-multipart
cd web/frontend
npm install
npm run build                     # produces web/frontend/dist/ (gitignored, built locally)
cd ../..
mal-agent web                     # serves the API + the built UI on one port
```

`scripts/install.ps1`/`.sh` already do all of this automatically when
`npm` is on `PATH` at install time (and print clear instructions if it
isn't). `mal-agent doctor` reports the web UI's real status as its own
`web_ui` check — `PASS` means both fastapi/uvicorn are importable *and*
the frontend is actually built; `WARN` tells you exactly which half is
missing.

Then open **http://127.0.0.1:8765** in a browser. `--host`/`--port`
change either. Runs persist to a local SQLite file (`malagent_web.db`,
created next to wherever you run the command) by default — set
`DATABASE_URL` yourself to opt into Postgres instead.

### Running it for a demo or any session longer than a few commands

**`mal-agent web` is a foreground, long-running process.** Run it in its
own dedicated terminal window and leave that window open for as long as
you want the UI reachable — closing the terminal, or the process being
killed for any reason, takes the whole UI down immediately and silently
(the browser just shows a connection error, with no indication of what
happened). If you're about to demo this, start the server yourself in
your own terminal a few minutes ahead of time and confirm it's up
(`curl http://127.0.0.1:8765/api/health` should return `{"status":"ok"}`)
rather than relying on a process someone else started for you — a
background process managed by a separate tool/session is not guaranteed
to still be alive by the time you actually need it.

If you'd rather not depend on a browser at all for a demo, `mal-agent
analyze <sample>` prints the same live per-stage progress straight to
the terminal and needs nothing but the CLI — the more failure-resistant
option when reliability matters more than the visual report.

## Troubleshooting (real bugs hit during this project's own setup)

- **Web UI loads a blank page, or every action ("upload," "run") fails
  immediately.** Check the backend is actually running first —
  `curl http://127.0.0.1:8765/api/health`. A dead/never-started backend
  is indistinguishable, from the browser's side, from "the whole thing is
  broken": no error detail, just a failed connection. This is the single
  most common failure mode and it's a process-lifecycle issue, not a code
  bug — see "Running it for a demo" above.
- **`mal-agent doctor`'s `web_ui` check says `WARN` about the frontend not
  being built** even though you ran `npm run build` — confirm you ran it
  inside `web/frontend/` (not the repo root) and that it completed without
  error; check for `web/frontend/dist/index.html` directly.
- **Browser shows the page but nothing happens on submit.** Open the
  browser's own developer console (F12) and check for a red error there
  first — that tells you whether the request left the browser at all
  (network tab) versus failed once it arrived at the backend (check the
  terminal running `mal-agent web` for a traceback).

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
