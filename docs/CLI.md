# CLI reference

Every subcommand below is real `--help` output from this exact checkout —
not hand-written and liable to drift. If you see a mismatch after a code
change, that's a doc bug; `python -m malagent.cli <command> --help` is
always the ground truth.

## Everyday use

### `mal-agent <path>` — analyze a sample

```
usage: mal-agent [-h] [--source {soc,cdc,manual,dataset}] [--ticket TICKET]
                 [--enable-models] [--no-cloud] [--allow-pseudocode-egress]
                 [--local-model LOCAL_MODEL]
                 [--escalation-provider {openai,anthropic,gemini,xai}]
                 [--fusion-mode {simple,cgef,judge}]
                 [--judge-model JUDGE_MODEL] [--out OUT]
                 path

Evidence-grounded static malware analysis

positional arguments:
  path                  path to the sample

options:
  --source {soc,cdc,manual,dataset}
  --ticket TICKET
  --enable-models       enable local/cloud model stage (needs Ollama or API keys)
  --no-cloud            disable cloud escalation (local only)
  --allow-pseudocode-egress
  --local-model LOCAL_MODEL
                        Ollama model tag to use locally (default: qwen3:8b)
  --escalation-provider {openai,anthropic,gemini,xai}
  --fusion-mode {simple,cgef,judge}
                        verdict decision method: 'simple' (default) lets the
                        EMBER classifier alone decide PE files; 'cgef' lets
                        the deterministic corroboration gate vote in EMBER's
                        gray zone; 'judge' (opt-in) sends only routed hard
                        cases (non-PE, gray zone, EMBER-vs-evidence conflict)
                        to an LLM adjudicator (see docs/RESEARCH.md)
  --judge-model JUDGE_MODEL
                        adjudicator for --fusion-mode judge,
                        '<provider>:<model>', e.g. ollama:qwen3:8b or
                        anthropic:claude-opus-5-5 (cloud needs egress)
  --out OUT             dir to write report.md + verdict.json + the mandatory
                        report.txt (default: ./mal-agent-reports; always
                        written, files are namespaced by sample hash)
```

The positional form (`mal-agent path/to/sample`, no `analyze` keyword) is
the original invocation and still works exactly this way — there is no
separate `analyze` subcommand to learn.

**Examples:**

```bash
# Deterministic spine only, no models, no network
mal-agent suspicious.exe

# Full pipeline with local reasoning agents
mal-agent suspicious.exe --enable-models --no-cloud

# Let the bounded LLM adjudicator decide only the hard cases
mal-agent suspicious.exe --fusion-mode judge --judge-model ollama:qwen3:8b

# Cloud escalation for pseudocode review (opt-in egress)
mal-agent suspicious.exe --enable-models --escalation-provider anthropic \
  --allow-pseudocode-egress
```

### `mal-agent doctor` — toolchain health check

No flags. Checks every optional dependency (pefile, capa+rules+sigs,
Ghidra+pyghidra+Java, Ollama+model, cloud API keys, database, known-good
allowlist, IOC reputation lists, YARA, `die`, VirusTotal, EMBER, the web
UI's built frontend) and reports `PASS`/`WARN`/`FAIL` per check. `FAIL`
means something was explicitly configured but is broken — not merely
absent, which is `WARN` or `PASS` depending on whether it's optional.

```
$ mal-agent doctor
MAL-AGENT DOCTOR
============================================================
[PASS] pefile                   importable
[PASS] capa                     rules=<path>, sigs=<path>
[PASS] floss                    on PATH
[PASS] ghidra                   GHIDRA_HOME=<path>
[PASS] java                     on PATH
[WARN] ollama                   not reachable at http://localhost:11434
[WARN] cloud_keys               no cloud provider API keys set
[PASS] database                 DATABASE_URL not set -- using in-memory repository
[PASS] known_good_allowlist     not configured (optional)
[PASS] ioc_reputation           not configured (optional)
[PASS] yara_match               not configured (optional)
[WARN] die                      'diec' not on PATH
[PASS] virustotal               not configured (optional)
[PASS] ember_classifier         not configured (optional)
[PASS] web_ui                   backend + built frontend ready
============================================================
0 FAIL, 3 WARN, 12 PASS
```

### `mal-agent web` — launch the local web UI

```
usage: mal-agent web [-h] [--host HOST] [--port PORT]

Launch the local web UI
```

Requires `pip install -e ".[web]"` and a built frontend
(`cd web/frontend && npm install && npm run build`) first — `doctor`'s
`web_ui` check tells you if the build is missing. Serves the API and the
built frontend from one process, one port (default
`http://127.0.0.1:8765`).

## Research / reproduction commands

These produced every number in `docs/RESEARCH.md` — needed to reproduce
the paper's results, not for everyday single-sample analysis. All live
under `mal-agent research <subcommand>` (the older flat form without
`research` still works as an undocumented alias).

```
usage: mal-agent research <subcommand> [args...]
subcommands: ablate-critic, ablate-llm, build-bundles, evaluate,
             family-attribution, judge-claims, judge-report, judge-run,
             make-manifest, suggest-verdict
```

### `research make-manifest <dataset_dir>`

Scans `<dir>/benign` and `<dir>/malicious`, writes the manifest CSV every
other research command consumes.

```
options:
  --out OUT    default: <dataset_dir>/manifest.csv
```

### `research build-bundles <manifest>`

Runs the full deterministic pipeline once per sample and freezes the
result as an evidence bundle — the frozen input every adjudicator model
is evaluated against, so a model comparison never needs to re-run tools.

```
options:
  --out OUT
  --workers WORKERS
  --limit LIMIT
  --capa-timeout CAPA_TIMEOUT        per-sample capa timeout, seconds (default 180)
  --max-pool-restarts MAX_POOL_RESTARTS
                                     restarts after a worker-pool crash
                                     (e.g. OOM) before giving up on the rest
                                     (default 3; each restart resumes only
                                     what's left)
```

### `research judge-run --model <provider:model> --exp <axis>`

Runs one adjudicator model against the frozen bundles for one evaluation
axis.

```
options:
  --bundles BUNDLES
  --model MODEL         e.g. ollama:qwen3:8b, anthropic:claude-opus-5-5
  --exp {main,adversarial,reliability}
  --split SPLIT          dev | test | all
  --limit LIMIT
  --routed-only
  --out OUT
  --repeats REPEATS
  --orders ORDERS
```

### `research judge-report`

Aggregates one or more `judge-run` outputs into the precision/recall/F1/
FPR/coverage/calibration report `docs/RESEARCH.md`'s numbers come from.

```
options:
  --bundles BUNDLES
  --results RESULTS
  --split SPLIT
  --out OUT
```

### `research evaluate <manifest>` — score verdicts against ground truth

```
options:
  --enable-models
  --no-cloud
  --local-model LOCAL_MODEL          default: qwen3:8b
  --escalation-provider {openai,anthropic,gemini,xai}
  --fusion-mode {simple,cgef}
  --out OUT
  --with-known-good     keep KNOWN_GOOD_HASHES_PATH active (off by default:
                         an allowlist containing the benign set makes TN a
                         hash lookup, not analysis)
```

### `research suggest-verdict <manifest>` — non-binding LLM opinion

Asks an LLM to holistically judge malicious/benign from all gathered
evidence, scored against ground truth for comparison — **never** used to
influence the real verdict.

### `research ablate-critic` — does the fact-checking critic work?

Measures whether `verifier_critic` catches overclaiming, against a
bundled synthetic fixture set (no real malware needed). Without
`--enable-models`, no model is configured and every case is
conservatively flagged unverified — honest, but degenerate.

### `research ablate-llm <manifest>` — does the LLM ever move the score?

Runs each sample through the full pipeline twice (deterministic-only vs.
+LLM) and checks whether the verdict label/score ever differs. It
shouldn't — LLMs narrate, they never judge — and this is the regression
test that proves it on real data, not just in a unit test.

### `research family-attribution` — malware family clustering

Predicts malware family via leave-one-out imphash clustering (+ optional
real `capa` malware-family rule hits) and scores macro-F1 against real
MalwareBazaar ground truth.

```
options:
  --dataset-dir DATASET_DIR      default: dataset/malicious
  --ground-truth GROUND_TRUTH    default: dataset/family_ground_truth.csv
  --use-capa                     also run capa per sample (slow; see
                                   --help for why it's off by default)
  --out OUT
```
