# Turn on more

Everything below is optional — the [Quick start](getting-started.md)
works with none of it. Each item: what it adds, how to enable it, and
whether it's been verified running live.

- **Known-good hash allowlist** (skips expensive stages on a match): set
  `KNOWN_GOOD_HASHES_PATH` to a hash-per-line file or `hash,name` CSV (an
  NSRL RDS export works directly). Verified live: ~1s instead of several
  minutes on a matched sample, verdict `benign` at high confidence. This
  is more than a performance shortcut — verified live that without it,
  the deterministic corroboration gate itself (`docs/ARCHITECTURE.md`
  §6, no LLM involved) could false-positive `malicious` at 0.9 confidence
  on legitimate Windows admin binaries, because their real, intended
  function genuinely spans attacker-relevant capa namespaces (task
  scheduling *is* MITRE T1053.005; remote admin tools legitimately need
  networking). A validly-signed binary now needs one *additional*
  corroborating category before conviction — verified live this fixes
  most of these cases (`powershell.exe`, `wmic.exe`, `certutil.exe`,
  `magnify.exe`, `mstsc.exe`, `dxdiag.exe`), but not all: `schtasks.exe`
  genuinely spans 4 distinct categories even signed, and correctly still
  escalates — a signature raises the bar, it doesn't grant immunity. In
  production, still configure this against as complete a trusted-binary
  set as practical (a full NSRL RDS import, not just a hand-picked few)
  rather than relying on the corroboration gate alone for this class of
  file.

- **Authenticode signature check:** on by default on Windows, no setup
  needed — reports signer identity as informational context (deliberately
  not a trust short-circuit: stolen/abused code-signing certificates are
  a well-documented real attack vector, so a valid signature is treated
  as corroborating context, never proof of benignity).

- **Capabilities + ATT&CK + MBC:** `pip install flare-capa` (puts `capa`
  on PATH). A plain pip install does **not** bundle capa's rules or FLIRT
  signatures — download them and set `CAPA_RULES_PATH` / `CAPA_SIGS_PATH`
  (see `.env.example`), or capa fails with "default embedded rules not
  found".

- **PE imports + imphash + entropy + Rich header + `.rsrc` resource
  parsing** (embedded-PE and packed-blob detection in resources):
  `pip install pefile`.

- **ELF dynamic-symbol imports + non-standard-section entropy:**
  `pip install pyelftools` (or `pip install -e ".[full]"`). Mach-O gets
  header identification only (cputype/filetype) — deliberately no
  segment/import heuristics; there's no real macOS sample in this
  project's own dev environment to verify them against the way ELF's
  were (see `docs/ARCHITECTURE.md` §5).

- **YARA rule matching** against your own rule set (distinct from this
  project's own YARA rule *generation*, which always runs): `pip install
  yara-python`, set `YARA_RULES_PATH` to a `.yar`/`.yara` file or a
  directory of them (see `.env.example`). Never bundled — third-party
  rule sets carry their own licenses.

- **Packer/compiler identification** via [die (Detect It
  Easy)](https://github.com/horsicq/DIE-engine): install `diec`, no other
  setup needed. Not live-verified in this project's own development — no
  `die` installation was available to test against.

- **VirusTotal hash lookup:** `pip install requests`, set
  `VIRUSTOTAL_API_KEY`, **and** explicitly set
  `EgressPolicy.allow_hash_lookup=True` — a hash isn't raw bytes or
  pseudocode, but it's still egress, so it gets its own opt-in rather than
  silently reusing an existing one (see `docs/ARCHITECTURE.md` §7). Not
  live-verified — no API key was available in this project's own
  development.

- **ML classifier decides the verdict, for PE files (EMBER2024):** a real
  pretrained LightGBM classifier (3.2M training files) that, when
  configured, decides malicious/benign alone by default
  (`--fusion-mode=simple`) — but **only for PE files**: EMBER2024 is
  PE-trained, and a real, measured check found 94/117 benign non-PE files
  (documents, scripts, archives) scoring above the production threshold,
  so a non-PE score is now shown as context and never decides (see
  [Research & Benchmarks](RESEARCH.md) §1). The other triage tools (now
  including format-aware analysis of scripts, LNK shortcuts, Office/RTF
  documents and PDFs — `malagent/format_triage.py`) become evidence and
  explanation: every finding is annotated with what it indicates and
  whether it supports or contradicts the verdict, and every tool is
  accounted for in the report whether it ran, was skipped, or errored.
  Two research fusion modes are preserved as opt-in:
  `--fusion-mode=cgef` (the deterministic gate votes in EMBER's gray
  zone) and `--fusion-mode=judge` (an LLM adjudicator,
  `--judge-model provider:model`, decides only routed hard cases and
  must cite tool evidence — see [Research & Benchmarks](RESEARCH.md) for
  the full design and how to reproduce its evaluation). `pip install
  thrember` from
  [FutureComputing4AI/EMBER2024](https://github.com/FutureComputing4AI/EMBER2024)
  (Apache-2.0) **and** `pip install "signify==0.7.1"` specifically —
  `thrember` pins `signify>=0.7.1` with no upper bound, and the latest
  release renamed a class it imports (a real dependency-drift bug found
  live during setup). Download a `.model` file from
  [huggingface.co/joyce8/EMBER2024-benchmark-models](https://huggingface.co/joyce8/EMBER2024-benchmark-models)
  (~3.5MB, no need to download the full 3.2M-file dataset), set
  `EMBER_MODEL_PATH`. See [Research & Benchmarks](RESEARCH.md) for the
  full reasoning, current numbers, and honest caveats.

- **Per-function decompilation + call-graph tracing** between decompiled
  functions: `pip install -e ".[ghidra]"` (pyghidra),
  install Ghidra itself, and set `GHIDRA_HOME` to the install root. Ghidra
  ≥11 no longer bundles Jython for scripting by default — `pyghidra`
  drives Ghidra's Java API directly from this process instead.

- **LLM reasoning agents:** `pip install -e ".[providers]"`, set keys in
  `.env`, add `--enable-models` (and `--no-cloud` to stay local-only).
  Local: install [Ollama](https://ollama.com), then `ollama pull qwen3:8b`
  and/or `ollama pull gemma4:12b` — the two local models this project's
  own research actually evaluated (see [Research & Benchmarks](RESEARCH.md));
  either works with `--judge-model ollama:<model>`.

- **Postgres** (optional — in-memory repository is the supported
  default): `docker compose up -d db`, set `DATABASE_URL` (host port
  **5433**, not 5432 — see the comment in `docker-compose.yml` for why).

- **IOC reputation (local, zero-egress):** set `IP_BLOCKLIST_PATH` and/or
  `DOMAIN_BLOCKLIST_PATH` to plain-text lists you download yourself —
  e.g. [ShadowWhisperer/IPs](https://github.com/ShadowWhisperer/IPs),
  [hagezi/dns-blocklists](https://github.com/hagezi/dns-blocklists)
  (Threat Intelligence Feeds subset). Cross-references IPs/domains/URLs
  already extracted from the sample; matches count toward the
  corroboration gate. Never bundled into this repo — some of these lists
  are GPL-3.0, this project is MIT.
