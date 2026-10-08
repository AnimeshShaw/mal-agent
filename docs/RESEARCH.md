---
title: Research: bounded LLM adjudication for hybrid malware triage
---

# Research: bounded LLM adjudication for hybrid malware triage

This is the reproduction guide for the research pivot recorded on
2026-09-27/28: testing whether a frontier LLM, used only as a bounded
*adjudicator* on cases a static classifier is genuinely unsure about (not
as a free-standing judge of every file), improves on EMBER2024 alone —
and whether its narratives and verdicts hold up under adversarial and
reliability pressure. It supersedes the older
`ML_CLASSIFIER_PLAN.md`/`ABLATION_LLM.md`/`EFFICIENCY.md` working docs
(kept locally, gitignored — their headline numbers were measured on a
71–90 sample set with a benign-set/known-good-allowlist overlap that made
several reported precision/recall/F1 figures artifacts of a hash lookup,
not analysis; see the 2026-09-27 audit for the full account).

## 1. The question and why it's open

`malagent/reporter.py`'s default (`fusion_mode="simple"`) lets EMBER2024
decide malicious/benign alone for PE files — validated (elsewhere in this
project's history) as strong on Windows executables, but:

- **EMBER only applies to PE files.** Measured: 94/117 real benign non-PE
  files (Markdown, Python, PDF, docx, zip, PowerShell, JS) score ≥0.15,
  the production threshold — `mal-agent analyze docs/SETUP.md` came back
  `MALICIOUS 0.95` before this was fixed (now: non-PE scores are shown as
  context, never decide; see `malagent/reporter.py`'s
  `_ember_in_distribution`).
- **Real campaigns lead with exactly these formats** — MalwareBazaar's
  recent feed is full of `.lnk`, `.js`, `.one`, `.iso`, `.hta`, macro
  documents — which is why `malagent/format_triage.py` exists at all.
- The field's own literature (surveyed in the earlier
  `AI-Malware-Analysis-Research-and-Framework.md`) independently
  converges on "LLMs describe code well, judge maliciousness poorly" —
  but that literature tests LLMs *deciding everything*, not LLMs used
  narrowly on the specific cases a calibrated classifier is uncertain
  about, with a hard requirement to cite tool evidence.

**Contribution shape**: not "an LLM judge is better than a classifier" —
it's *where* (if anywhere) a bounded, evidence-gated LLM adjudicator adds
real value over a classifier's own abstention/gray-zone handling, measured
honestly, including the negative result if that's what the data shows.

## 2. Architecture: bundles, routing, adjudication

Every experimental arm reads from the same frozen **evidence bundle**
(`malagent/judge/bundle.py`) — the sample's deterministic triage output
(every tool, its status, its findings, EMBER's score) plus a **provenance
tag on every evidence item**: `tool` (a fact a tool computed) or
`sample_text` (text copied verbatim out of the file — attacker-
controlled). This is what makes the four arms comparable: they differ
only in decision rule, never in what evidence they saw.

**Routing** (`malagent/judge/routing.py`) decides which samples are "hard"
— fixed *before* any judge result was seen, from the original 71-sample
calibration only:

| Reason | Condition |
|---|---|
| `ember_ood` | no in-distribution PE score (non-PE, no PE payload inside a container) |
| `ember_gray` | in-distribution score in (0.05, 0.30) — the band no calibration sample ever fell into |
| `ember_gate_conflict` | EMBER says benign but the deterministic gate is corroborated, or EMBER says malicious on a validly-signed file with zero high-signal categories |

Everything else keeps the EMBER-alone verdict. The **adjudicator**
(`malagent/judge/judge.py`) sees only the rendered bundle (never raw
bytes, never the label), must answer strict JSON, and is validated
fail-closed: unparseable output, an unknown verdict, a citation to an
alias that doesn't exist, or a non-abstain verdict with zero citations →
scored `abstain`, `valid=False`. In `provenance` render mode
(`malagent/judge/render.py`), a **support gate** additionally requires
every non-abstain verdict to cite at least one *tool-derived* item — a
verdict resting only on the sample's own words about itself is coerced to
abstain (`gated=True`). The `flat` render mode (tool facts and sample text
interleaved, no gate) is the adversarial-robustness control condition.

## 3. Dataset v2

`dataset/manifest_v2.csv` (built by `scripts/make_manifest_v2.py`), 1,504
samples:

| | dev | test |
|---|---|---|
| malicious | 550 | 335 |
| benign | 270 | 349 |

**Split protocol, fixed before any experiment ran:** malicious samples
split *temporally* (`first_seen < 2026-09-05` → dev, else → test — every
v1 sample is dev, since all were first seen before that cutoff); benign
samples (no first-seen date exists) split by a seeded 40/60 draw,
stratified by file type. Only `dev` is ever used to develop prompts,
thresholds, or routing; every headline number is reported on `test`.

**Malicious sources**: the original 90-sample v1 set, plus MalwareBazaar
daily-batch archives (`scripts/select_mb_daily.py`, content-sniffed by
`malagent.format_triage.detect_format` — never by extension) and targeted
file-type/signature queries (`scripts/fetch_malwarebazaar.py`). File-type
spread: 220 PE, 60 JS, 60 VBS, 52 PS1, 50 ELF, 41 ZIP, 30 LNK, 30 plain
text, 28 ISO, 25 each of DOCM/HTA/OneNote/PDF/RTF/XLSM, 21 OLE, 20
unrecognized, 12 BAT, 10 Mach-O.

**Benign sources** (`scripts/collect_benign.py`) — deliberately never a
user's personal files, only system/application/public-corpus material,
mirroring the malicious file-type mix so benign non-PE files exist at all
(the 2026-09-27 audit found *zero* in every prior evaluation): vendor-
stratified Program Files executables, cached MSIs, Start-menu `.lnk`
shortcuts, System32 admin scripts, PowerShell module scripts, Office
templates/add-ins (`.dotx`/`.xlam`/…), OneNote stationery, the public
GovDocs1 corpus (real `.gov` documents: PDF/DOC/XLS/PPT), and `.so` files
extracted from manylinux wheels.

Rebuild from scratch: `python scripts/collect_benign.py`,
`python scripts/fetch_malwarebazaar.py --file-types ... --out ...`,
`python scripts/select_mb_daily.py` (needs `dataset/_sources/mb_daily_*.zip`
from `https://datalake.abuse.ch/malware-bazaar/daily/<date>.zip`, password
`infected`), then `python scripts/make_manifest_v2.py`. None of this data
is committed — malware and third-party binaries don't belong in a public
git repo; `dataset/` is gitignored.

## 4. Running the experiments

**Quickest path in:** `python scripts/reproduce.py check` reports exactly what's
installed/configured on your machine (deterministic tools, Ollama, the EMBER
model file, a dataset manifest) and what's missing for each. `python
scripts/reproduce.py smoke` then runs the real pipeline end to end in ~10
seconds against a handful of safe, synthesized multi-format files (no
malware, no network, no LLM required) — this proves the tool itself works on
your machine, distinct from reproducing the paper's numbers. `python
scripts/reproduce.py paper` is a cross-platform wrapper around the exact
commands below, with the same idempotent/resumable/stop-on-critical-failure
behavior as `scripts/run_research_jobs.ps1` (below); use whichever you're more
comfortable reading.

**Real measured timings**, from the run that produced this paper's numbers (16GB
Windows machine, 4 parallel bundle-building workers, local Ollama): building
1,504 evidence bundles took ~1h56m; `qwen3:8b`'s full main-experiment arm
~1h32m, `gemma4:12b`'s ~3h16m (larger model, slower); the adversarial axis
(4 attacks × flat/provenance, ~530 judged cases) ~1h34m; the reliability axis
(1,100 jobs: 5 repeats + 3 orders + 3 ablations × 100 routed samples) ~2h14m.
Budget the better part of a day for both local-model arms end to end; the
claims-verification axis is comparatively fast (a few claims judged per
narrative, ~1-2 LLM calls per claim).

The commands themselves, unwrapped:

```bash
export EMBER_MODEL_PATH=/path/to/EMBER2024_all.model
unset KNOWN_GOOD_HASHES_PATH   # never let the allowlist decide research numbers

# 1. Freeze every sample's deterministic triage into a bundle (resumable,
#    parallel, survives a crashed worker pool -- see collect.py).
mal-agent research build-bundles dataset/manifest_v2.csv --out bundles/v2 --workers 4

# 2. Judge every bundle once (temperature 0) -- the LLM-alone arm is these
#    verdicts on everything; the hybrid arm uses them only where routed.
mal-agent research judge-run --model ollama:qwen3:8b --exp main --split test
mal-agent research judge-run --model ollama:gemma4:12b --exp main --split test

# 3. Adversarial + reliability, on the routed (hard-case) subset only.
mal-agent research judge-run --model ollama:qwen3:8b --exp adversarial --split test --routed-only --limit 160
mal-agent research judge-run --model ollama:qwen3:8b --exp reliability --split test --routed-only --limit 100

# 4. Claim-level verification of narratives (one model narrates, another judges each claim).
mal-agent research judge-claims --narrator ollama:gemma4:12b --judge ollama:qwen3:8b --split test --limit 60

# 5. Build the report (tables in research_out/report/report.md + .json).
mal-agent research judge-report --split test
```

`scripts/run_research_jobs.ps1` runs all of the above unattended and
resumably (every step is idempotent: bundles skip existing files, judge
runs skip already-recorded `(sample, variant)` pairs, every generation is
disk-cached in `research_out/llm_cache/`) — launch detached with
`Start-Process powershell -WindowStyle Hidden -ArgumentList '-NoProfile','-File','scripts\run_research_jobs.ps1'`.
It stops on a failed critical step (manifest/bundles) instead of scoring
judge experiments against a dataset it never confirmed was complete — a
real incident this project hit once (see below).

**Frontier models**: any `<provider>:<model>` spec
(`malagent/judge/providers.py`: `ollama`, `anthropic`, `openai`, `gemini`,
`xai`) works everywhere `--model`/`--narrator`/`--judge` appears; cloud
providers read their SDK's normal API-key environment variable.

## 5. Metrics (`malagent/judge/metrics.py`)

Stated once, applied everywhere: **recall is strict** (an abstention on
real malware is a miss, not excluded from the denominator); **FPR is
computed over committed calls on benign samples**, with the benign
abstention rate reported separately; **coverage** = committed calls / all
samples. Bootstrap 95% CIs on every headline number; Cohen's/Fleiss'
kappa for agreement; ECE and AURC for calibration/selective-risk;
McNemar's test for the paired comparison against EMBER-alone.

## 6. Known limitations, stated up front

- **Single machine, single run per config.** No multi-seed variance
  bars beyond what the reliability experiment's repeated-sampling axis
  already gives.
- **EMBER2024 decides only PE files**; the "in-distribution" claim is
  therefore about PE specifically, not malware in general.
- **Local models tested (qwen3:8b, gemma4:12b) are 7–12B quantized.**
  One frontier model (Gemini 3.1 Pro, via its standard API) has now also
  been run on the full 681-sample main experiment: Hybrid[Gemini] reaches
  F1 0.837 at 0.8% FPR, the best F1 and by far the best FPR of the three
  models — but on raw per-sample correctness, `qwen3:8b`'s Hybrid arm still
  beats Gemini's (McNemar 68 vs. 45, p=0.038), driven by qwen3:8b's higher
  coverage, not higher accuracy. The frontier model's own adversarial and
  reliability numbers have **not** been run — that axis remains local-model
  only, and is the most valuable next experiment this result points at.
  Other frontier arms (Claude, GPT) still need API keys this environment
  doesn't have configured by default.
- **A real infrastructure incident is part of this project's own
  evidence for why reproducibility engineering matters**: an earlier run
  of this exact pipeline used 12 parallel workers, exhausted the
  machine's 16GB of RAM loading the EMBER classifier in each one,
  crashed the worker pool, and — because the driving script didn't check
  the exit code — silently proceeded to score judge experiments against
  267 of the intended 1,504 bundles. Caught before any number was
  reported; fixed at both layers (`build_bundles()` now recovers from a
  crashed pool and gives an honest count instead of losing samples
  silently, and the orchestration script now stops on a critical-step
  failure). Default workers lowered to 4. Documented here rather than
  quietly fixed, because a hybrid-classifier evaluation pipeline that can
  silently truncate its own dataset is exactly the kind of methodology
  bug the "Transcending"/TESSERACT literature this project already cites
  warns about in a different form.
- **A second, smaller incident of the same species**: a local `research_out/`
  cleanup pass performed while the reliability/claims experiments were still
  running attempted to relocate `jobs.log` and `llm_cache/`. The log file's
  move silently failed (the OS held it open for append), which was safe by
  luck; the cache directory's move *succeeded*, and the still-running worker
  immediately recreated an empty `llm_cache/` at the old path and started
  writing new entries there — splitting the cache in two. Caught within
  minutes by checking whether the old path had been recreated; fixed by
  merging the small number of newly-written entries back with a
  non-clobbering copy before restoring the original path. No experiment data
  was lost, but it is the same lesson as above in miniature: never
  reorganize storage a live process is reading or writing, and when in doubt,
  merge rather than overwrite. See `research_out/README.md` for the standing
  rule this produced (which paths are safe to reorganize and which aren't).

## 7. Where the code lives

| Concern | Path |
|---|---|
| Evidence bundles | `malagent/judge/bundle.py`, `malagent/judge/collect.py` |
| Rendering (flat vs. provenance-separated) | `malagent/judge/render.py` |
| Adjudication + strict output validation | `malagent/judge/judge.py` |
| Routing (hard-case definition) | `malagent/judge/routing.py` |
| Providers + disk cache | `malagent/judge/providers.py`, `malagent/judge/cache.py` |
| Metrics | `malagent/judge/metrics.py` |
| Adversarial transforms | `malagent/judge/adversarial.py` |
| Claim-level verification | `malagent/judge/claims.py` |
| Experiment runner + report | `malagent/judge/experiments.py`, `malagent/judge/analysis.py` |
| CLI | `malagent/judge/cli.py` (`mal-agent research build-bundles|judge-run|judge-claims|judge-report`) |
| Non-PE format triage (scripts, LNK, Office, PDF) | `malagent/format_triage.py` |
| Opt-in production integration | `fusion_mode="judge"` in `malagent/pipeline.py`/`reporter.py`, `--judge-model` on the CLI, and the web UI's "Secondary inspection" mode |
