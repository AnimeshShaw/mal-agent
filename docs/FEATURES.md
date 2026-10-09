# Turn on more

Everything below is optional — the [Quick start](getting-started.md)
works with none of it. Each item follows the same structure: enable,
what it adds, why it's there, and whether it's been verified live.

## Known-good hash allowlist

- **Enable:** set `KNOWN_GOOD_HASHES_PATH` to a hash-per-line file or
  `hash,name` CSV (an NSRL RDS export works directly).
- **Adds:** skips expensive stages outright on a hash match.
- **Why it's more than a speed shortcut:** without it, the deterministic
  corroboration gate (`docs/ARCHITECTURE.md` §6, no LLM involved) could
  false-positive `malicious` at 0.9 confidence on legitimate Windows
  admin binaries — their real, intended function genuinely spans
  attacker-relevant capa namespaces (task scheduling *is* MITRE
  T1053.005; remote admin tools legitimately need networking). A
  validly-signed binary now needs one *additional* corroborating
  category before conviction.
- **Verified live:**
  - ~1s instead of several minutes on a matched sample, verdict
    `benign` at high confidence.
  - The extra-category rule fixes most of the known false positives
    (`powershell.exe`, `wmic.exe`, `certutil.exe`, `magnify.exe`,
    `mstsc.exe`, `dxdiag.exe`) — but not all: `schtasks.exe` genuinely
    spans 4 distinct categories even signed, and correctly still
    escalates. A signature raises the bar, it doesn't grant immunity.
  - In production, still configure this against as complete a
    trusted-binary set as practical (a full NSRL RDS import, not a
    hand-picked few) rather than relying on the corroboration gate
    alone for this class of file.

## Authenticode signature check

- **Enable:** nothing — on by default on Windows.
- **Adds:** signer identity as informational context.
- **Why:** stolen/abused code-signing certificates are a well-documented
  real attack vector, so this is deliberately *not* a trust
  short-circuit — a valid signature corroborates, it never proves
  benignity on its own.

## Capabilities + ATT&CK + MBC (capa)

- **Enable:** `pip install flare-capa` (puts `capa` on PATH), then
  download rules/sigs and set `CAPA_RULES_PATH` / `CAPA_SIGS_PATH` (see
  `.env.example`). A plain pip install does **not** bundle them — capa
  fails with "default embedded rules not found" without this step.
- **Adds:** capability detection mapped to ATT&CK techniques and MBC
  behaviors.

## PE structural analysis

- **Enable:** `pip install pefile`.
- **Adds:** imports, imphash, per-section entropy, overlay detection,
  Rich header, `.rsrc` resource parsing (finds embedded PEs / packed
  blobs hidden in resources).

## ELF / Mach-O support

- **Enable:** `pip install pyelftools` (or `pip install -e ".[full]"`).
- **Adds:** ELF dynamic-symbol imports + non-standard-section entropy.
- **Scope note:** Mach-O gets header identification only
  (cputype/filetype) — deliberately no segment/import heuristics; there
  was no real macOS sample in this project's own dev environment to
  verify a stronger check against (see `docs/ARCHITECTURE.md` §5).

## YARA rule matching

- **Enable:** `pip install yara-python`, set `YARA_RULES_PATH` to a
  `.yar`/`.yara` file or directory.
- **Adds:** matches against *your own* rule set — distinct from this
  project's own YARA rule *generation*, which always runs regardless.
- **Note:** never bundled into this repo — third-party rule sets carry
  their own licenses.

## Packer/compiler identification (DIE)

- **Enable:** install [`diec`](https://github.com/horsicq/DIE-engine),
  no other config.
- **Adds:** identifies the *specific, named* packer/compiler, a
  stronger signal than generic entropy heuristics.
- **Verified live:** not yet — no `die` installation was available to
  test against in this project's own development.

## VirusTotal hash lookup

- **Enable:** `pip install requests`, set `VIRUSTOTAL_API_KEY`, **and**
  explicitly set `EgressPolicy.allow_hash_lookup=True`.
- **Why two separate switches:** a hash isn't raw bytes or pseudocode,
  but it's still egress — it gets its own opt-in rather than silently
  reusing a different one already granted (see `docs/ARCHITECTURE.md`
  §7).
- **Verified live:** not yet — no API key was available in this
  project's own development.

## EMBER2024 ML classifier (decides PE verdicts)

- **Enable:**
  1. `pip install thrember` from
     [FutureComputing4AI/EMBER2024](https://github.com/FutureComputing4AI/EMBER2024)
     (Apache-2.0) **and** `pip install "signify==0.7.1"` specifically —
     `thrember` pins `signify>=0.7.1` with no upper bound, and the
     latest release renamed a class it imports (a real dependency-drift
     bug found live during setup).
  2. Download a `.model` file from
     [huggingface.co/joyce8/EMBER2024-benchmark-models](https://huggingface.co/joyce8/EMBER2024-benchmark-models)
     (~3.5MB — no need for the full 3.2M-file dataset).
  3. Set `EMBER_MODEL_PATH`.
- **Adds:** a real, pretrained LightGBM classifier (3.2M training
  files) that decides malicious/benign alone by default
  (`--fusion-mode=simple`) — **only for PE files**.
- **Why PE-only:** a real, measured check found 94/117 benign non-PE
  files (documents, scripts, archives) scoring above the production
  threshold. A non-PE score is shown as context, never decides (see
  [Research & Benchmarks](RESEARCH.md) §1).
- **What the other tools become once EMBER decides:** evidence and
  explanation, not a vote. Every finding is annotated with what it
  indicates and whether it supports/contradicts the verdict, and every
  tool is accounted for whether it ran, was skipped, or errored
  (format-aware triage for scripts/LNK/Office/PDF —
  `malagent/format_triage.py` — included).
- **Two opt-in research modes, preserved not deleted:**
  - `--fusion-mode=cgef` — the deterministic gate votes in EMBER's gray
    zone instead of EMBER deciding alone.
  - `--fusion-mode=judge` — a bounded LLM adjudicator
    (`--judge-model provider:model`) decides only the routed hard
    cases and must cite tool evidence. Full design + reproduction:
    [Research & Benchmarks](RESEARCH.md).

## Ghidra decompilation + call graphs

- **Enable:** `pip install -e ".[ghidra]"` (pyghidra), install Ghidra
  itself, set `GHIDRA_HOME` to the install root.
- **Adds:** headless decompilation of capa-ranked functions plus
  caller/callee call-graph tracing.
- **Note:** Ghidra ≥11 no longer bundles Jython for scripting by
  default — `pyghidra` drives Ghidra's Java API directly instead.

## LLM reasoning agents (local or cloud)

- **Enable:** `pip install -e ".[providers]"`, set keys in `.env`, add
  `--enable-models` (`--no-cloud` to stay local-only).
- **Local models:** install [Ollama](https://ollama.com), then
  `ollama pull qwen3:8b` and/or `ollama pull gemma4:12b` — **the only
  two local models this project's own research has actually evaluated**
  (see [Research & Benchmarks](RESEARCH.md)). Either works with
  `--judge-model ollama:<model>`; other Ollama models will run but
  haven't been measured here.

## Postgres persistence

- **Enable:** `docker compose up -d db`, set `DATABASE_URL`.
- **Note:** host port is **5433**, not 5432 — see the comment in
  `docker-compose.yml` for why. The in-memory repository is the
  supported default; Postgres is purely optional.

## IOC reputation (local, zero-egress)

- **Enable:** set `IP_BLOCKLIST_PATH` and/or `DOMAIN_BLOCKLIST_PATH` to
  plain-text lists you download yourself — e.g.
  [ShadowWhisperer/IPs](https://github.com/ShadowWhisperer/IPs),
  [hagezi/dns-blocklists](https://github.com/hagezi/dns-blocklists)
  (Threat Intelligence Feeds subset).
- **Adds:** cross-references IPs/domains/URLs already extracted from
  the sample; matches count toward the corroboration gate.
- **Note:** never bundled into this repo — some of these lists are
  GPL-3.0, this project is MIT.
