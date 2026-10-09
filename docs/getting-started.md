# Getting started

Three ways in, pick one:

- **Just try it, no setup** → [30-second path](#30-second-path)
- **Full local install** (all tools, local LLMs) → [one-command setup](#one-command-setup)
- **Just the web UI** → [web UI](#web-ui)

## 30-second path

No API keys, no Ollama, no Ghidra. Works right away.

```bash
pip install -e .
mal-agent path/to/sample --out ./out
```

What you get: PE parsing, `capa` (if installed), Authenticode checks,
IOC extraction, a deterministic verdict — `malicious` / `suspicious` /
`benign` / `undetermined`. Every claim traces to real tool evidence.
Nothing guessed.

```bash
mal-agent doctor
```

Run this anytime. Tells you what's on, what's off, and what's actually
broken (vs. just not configured) — `PASS` / `WARN` / `FAIL` per tool.

## One-command setup

```powershell
# Windows
.\scripts\install.ps1          # quick: venv + package + .env scaffold
.\scripts\install-full.ps1      # + Ghidra, JDK, capa-rules, Ollama + models, EMBER
```

```bash
# Linux/macOS
./scripts/install.sh
./scripts/install-full.sh
```

| Script | Gets you |
|---|---|
| `install.ps1` / `.sh` | venv, package, `.env` scaffold — the 30-second path's dependencies |
| `install-full.ps1` / `.sh` | + JDK 21, Ghidra, capa-rules+sigs, Node (web UI build), **Ollama + `qwen3:8b` + `gemma4:12b`**, the EMBER2024 PE classifier model, Postgres |

Prompts before each large download. Pass `--yes` (`-Yes` on
PowerShell) to skip prompts.

Full troubleshooting and manual per-tool setup (if you only want one or
two optional tools, not everything): **[Setup Guide](SETUP.md)**.

## Local LLM models — which one?

Only matters if you turn on `--enable-models` / `--fusion-mode judge`.
Both are pulled automatically by `install-full`.

| Model | Best for | Measured result |
|---|---|---|
| **`qwen3:8b`** (recommended default) | Highest coverage | 84.9% of hard cases committed, F1 0.822 |
| **`gemma4:12b`** | Lowest false-positive rate among local models | FPR 8.3%, F1 0.825 |

These are the only two local models this project has actually
benchmarked (see [Research & Benchmarks](RESEARCH.md)) — that's why
they're the ones recommended, not a guess. Any other Ollama-compatible
model works too (`--judge-model ollama:<any-tag-you've-pulled>`); it
just hasn't been measured here. Browse more at
[ollama.com/library](https://ollama.com/library).

## Web UI

```bash
pip install -e ".[web]"
cd web/frontend && npm install && npm run build && cd ../..
mal-agent web
```

Opens at `http://127.0.0.1:8765`. Same verdict, same evidence, browser
instead of a text file. `--host` / `--port` to change either.

## What's next

- **[CLI Reference](CLI.md)** — every command and flag
- **[Architecture](ARCHITECTURE.md)** — how it's put together and why
- **[Research & Benchmarks](RESEARCH.md)** — the numbers, how to reproduce them
