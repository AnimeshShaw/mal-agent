# scripts/

## Setup (everyday use)

| Script | Purpose |
|---|---|
| `install.ps1` / `install.sh` | Quick path: venv, package install, `.env` scaffold. |
| `install-full.ps1` / `install-full.sh` | Full automation: also installs JDK, Ghidra, capa-rules+sigs, Node.js (frontend build), Ollama + both evaluated local models (`qwen3:8b`, `gemma4:12b`), the EMBER2024 PE classifier model, and brings up Postgres. See [docs/SETUP.md](../docs/SETUP.md). |

## Dataset construction (for reproducing the research dataset)

| Script | Purpose |
|---|---|
| `make_manifest_v2.py` | Builds `dataset/manifest_v2.csv` from a sample directory. |
| `fetch_malwarebazaar.py` | Pulls malicious samples from MalwareBazaar (needs an API key). |
| `select_mb_daily.py` | Selects a daily slice from a MalwareBazaar bulk export. |
| `fetch_family_ground_truth.py` | Builds family ground-truth labels for `family-attribution`. |
| `collect_benign.py` | Assembles the benign half of the corpus. |
| `check_ember_overlap.py` | Checks for sample overlap with EMBER2024's own training set. |
| `eval_cgef_heldout.py` | One-off held-out evaluation of the CGEF fusion mode. |

## Reproduction

| Script | Purpose |
|---|---|
| `reproduce.py` | The single documented entry point for reproducing this project's research numbers end to end. See its own `--help` and [docs/RESEARCH.md](../docs/RESEARCH.md). |
| `run_research_jobs.ps1` | What `reproduce.py`'s long path actually runs unattended on Windows — referenced directly from `docs/RESEARCH.md` and `reproduce.py`'s own help text. |
| `prepare_dataset_deposit.py` | Builds the defanged, PII-redacted dataset package deposited on Mendeley Data / Hugging Face from `research_out/` + `bundles/v2/`. Read-only over its inputs. |
| `ui_screenshots.py` | Regenerates the web UI screenshots used in documentation. |

## `research/` — one-off model-run orchestration

Hardcoded to the exact local setup and specific runs used to produce this
project's paper numbers (which model, which experiment axis, which log
path) — not reusable, general-purpose tooling, and not referenced from
any doc. Kept rather than deleted because they're real provenance: anyone
checking how a specific number was actually produced can see the literal
script that produced it, not a paraphrase.

| Script | Purpose |
|---|---|
| `run_gemini_main.ps1` | Ran Gemini 3.1 Pro's main-experiment arm (resumable; skips already-recorded sha256+variant pairs). |
| `run_gemma_adversarial.ps1` | Ran gemma4:12b's adversarial-robustness axis. |
| `run_gemma_reliability.ps1` | Ran gemma4:12b's calibration/reliability axis. |
| `resume_gemini_at_reset.ps1` | Waited out a Gemini API daily-quota reset, then launched `run_gemini_main.ps1`. |
