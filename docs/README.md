# Documentation index

**Start here, in this order:**

1. **[ARCHITECTURE.md](ARCHITECTURE.md)** — how the system is put
   together and why. Read this first.
2. **[PIPELINE.md](PIPELINE.md)** — the exact tool-by-tool pipeline, one
   diagram + a plain-language table: what each tool does, why it's
   there, what it adds.
3. **[SETUP.md](SETUP.md)** — install instructions, both quick
   (Python-only) and full-automation paths.
4. **[RESEARCH.md](RESEARCH.md)** — the current research question
   (bounded LLM adjudication for hybrid malware triage), the evidence-
   bundle/routing/adjudication architecture, dataset v2, how to run and
   reproduce every experiment, and the metrics used.

A handful of earlier working documents (the original research dossier,
the deterministic-gate-vs-EMBER decision log, an LLM ablation study, and
per-stage timing numbers) are kept locally for reference but are not
tracked in this repo — some contained personal/hardware context, and
their headline numbers were superseded by the 2026-09-27/28 audit (a
benign-set/known-good-allowlist overlap had made several reported
precision/recall/F1 figures artifacts of a hash lookup, not analysis).
`RESEARCH.md` is the current, accurate account.
