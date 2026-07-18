# MAL-AGENT (v0 skeleton)

Evidence-grounded, agentic **static** malware analysis. Hybrid model strategy
(local-first via Ollama, policy-gated escalation to OpenAI / Anthropic / Gemini /
xAI). Every analytical claim is tied to tool evidence; anything the system cannot
determine is reported explicitly rather than guessed.

## Why this shape
- **Frozen contracts** (`malagent/contracts.py`) are the only hard-to-change part.
  Tools, agents, models, and storage behind them are swappable without a rewrite.
- **Agents are pure functions** `(AnalysisState) -> AnalysisState`, so LangGraph
  vs a linear runner is an implementation detail.
- **Egress fails closed** (`models.EgressGuard`): raw bytes never leave; when a
  hard case can't be escalated, the verdict is `undetermined`, not `benign`.
- **Tamper-evident audit** (`malagent/audit.py`): hash-chained chain-of-custody
  for SOC/CDC samples.

## Quick start (no external services needed)
```bash
pip install -e .
python -m malagent.cli path/to/sample --source soc --ticket SOC-1234 --out ./out
```
Runs the deterministic spine (features + IOCs + PE imports/imphash + known-good
allowlist check + Authenticode signature check + capa-if-present), the
grounding verifier, and renders a report. Dynamic + model stages report
themselves as skipped/undetermined honestly. See `docs/AUDIT.md` for the full
tool inventory and a static-analysis technique coverage matrix (what's
implemented, what isn't, and why).

## Turn on more
- **Known-good hash allowlist (skips expensive stages on a match):** set
  `KNOWN_GOOD_HASHES_PATH` to a hash-per-line file or `hash,name` CSV (an
  NSRL RDS export works directly). Verified live: ~1s instead of several
  minutes on a matched sample, verdict `benign` at high confidence.
- **Authenticode signature check:** on by default on Windows, no setup
  needed -- reports signer identity as informational context (deliberately
  not a trust short-circuit; see `docs/AUDIT.md` §2 for why).
- **Capabilities + ATT&CK:** `pip install flare-capa` (puts `capa` on PATH).
  A plain pip install does **not** bundle capa's rules or FLIRT signatures --
  download them and set `CAPA_RULES_PATH` / `CAPA_SIGS_PATH` (see
  `.env.example`), or capa fails with "default embedded rules not found".
- **PE imports + imphash:** `pip install pefile`.
- **Per-function decompilation:** `pip install -e ".[ghidra]"` (pyghidra),
  install Ghidra itself, and set `GHIDRA_HOME` to the install root. Ghidra
  >=11 no longer bundles Jython for scripting by default -- `pyghidra` drives
  Ghidra's Java API directly from this process instead.
- **Models:** `pip install -e ".[providers]"`, set keys in `.env`, add
  `--enable-models` (and `--no-cloud` to stay local). Local: install
  [Ollama](https://ollama.com), `ollama pull qwen2.5-coder:7b`.
- **Postgres (production default):** `docker compose up -d db`, set `DATABASE_URL`
  (host port **5433**, not 5432 -- see the comment in `docker-compose.yml` for
  why). Verified live: `PostgresRepository` connects and a real run's verdict
  round-trips through it correctly.

## Build roadmap (from the spec)
M0 deterministic spine (done) → M1 local model summaries (done: policy-gated
escalation + true per-function summarization, each summary grounded in its
own decompile evidence; validated live against a real Ollama instance) → M2
headless-Ghidra decompilation (done: `pyghidra`-based adapter, capa-ranked
function selection, budget enforcement; **verified live** against Ghidra
12.1.2 -- see "Verified live" below) → M3 cloud escalation + egress
enforcement (done) → M4 ATT&CK + YARA (YARA: deterministic baseline from
grounded literal evidence; ATT&CK: 692-technique local reference table
grounds every technique ID to a human-readable name, verified against real
capa output; the RAG narrative synthesizing technique *combinations* is not
started) → M5 dynamic detonation (gated, stubbed as planned) → M6 evaluation
and calibration (not started -- and now empirically motivated, see below).

See `docs/TODO.md` for the full task breakdown.

## Verified live (real tools, not mocks)
Ran the full pipeline against a real, benign PE (`notepad.exe`) with real
`capa` (+ rules/sigs), real headless Ghidra 12.1.2 (via `pyghidra`), a real
local Ollama model, and real Postgres persistence.

- **Verdict scoring was producing a real false positive; fixed.** The
  original heuristic summed every capa capability match with equal
  severity="medium" weight, so 35 correctly-detected but entirely mundane
  capabilities (read file, create directory, get disk size, ...) on a stock
  Windows binary scored `MALICIOUS` at 0.9 confidence. Fixed two ways,
  grounded in capa's own real rule-namespace taxonomy (not guessed):
  1. `CapaTool` now assigns severity by namespace category
     (`tools.py: _capa_severity`) -- only namespaces that are inherently
     attacker-relevant on their own (`anti-analysis`, `collection`,
     `communication`, `exploitation`, `impact`, `load-code`, `persistence`,
     `malware-family`) count as `medium`; ordinary capabilities
     (`host-interaction`, `linking`, `executable`, ...) are `info`.
     `load-code/pe` needed a further carve-out: it mixes benign PE-structure
     introspection with genuine manual-loading/injection rules, found by
     inspecting the real capa-rules corpus directly.
  2. `reporter.py` now requires corroboration across **≥3 distinct**
     high-signal categories before calling a verdict `suspicious`/
     `malicious` -- a pile of matches within just one or two categories
     (which can themselves be false-positive-prone individually) shouldn't
     alone convict.
  Result on notepad.exe: `MALICIOUS 0.9` → `UNDETERMINED 0.35`. Not a false
  `benign` either -- there genuinely are 2 high-signal-category matches
  (anti-analysis, collection), just not enough to corroborate a verdict
  either way. This is a heuristic improvement grounded in real data, **not
  validated calibration** -- that still needs labeled malware/benign
  datasets (M6). Treat `suspicious`/`malicious` as higher-precision now, but
  don't assume the thresholds (3 categories, score bands) are tuned against
  anything but this one real, benign sample.
- **`--no-cloud` runs will usually report per-function analysis as
  `undetermined`, even with a working local model.** Ghidra's own
  "decompiled, available for review" findings carry confidence 0.5, which
  fires the `low_confidence` escalation trigger; per D6, escalation blocked
  by policy fails closed rather than silently falling back to local. This is
  the documented, intended behavior (not a bug), but it means local-only
  operation needs `EgressPolicy.escalation_triggers` tuned deliberately if you
  want real per-function summaries without cloud.
- **Known-good hash allowlist + Authenticode check, both verified live.**
  notepad.exe with its real hash allowlisted: full pipeline in 0.88s
  (vs. several minutes) instead of running Ghidra/capa/LLM on a file already
  known to be trusted, verdict `benign` 0.97. Authenticode check against the
  same file correctly reports `CN=Microsoft Windows, O=Microsoft
  Corporation, ...`. Full writeup in `docs/AUDIT.md`.

## Tests
```bash
pip install pytest && pytest -q
```

> Research/IP note: framework names here are placeholders. Resolve tool ownership
> (company vs personal research) before publishing.
