---
title: mal-agent
---

**Evidence-grounded, agentic static malware analysis.** Every verdict
traces to tool evidence — nothing is guessed, and an LLM's opinion can
never move the deterministic score.

[View on GitHub](https://github.com/AnimeshShaw/mal-agent) ·
[Full README](https://github.com/AnimeshShaw/mal-agent#readme) ·
[Dataset (Hugging Face)](https://huggingface.co/datasets/AnimeshShaw/mal-agent-llm-adjudication-eval)

## Start here

1. **[Architecture](ARCHITECTURE)** — how the system is put together and
   why: the evidence-grounding model, why an LLM narrative can never
   move the verdict score, the tool inventory, model routing, the audit
   trail.
2. **[Pipeline](PIPELINE)** — the exact tool-by-tool flow: what each
   stage does, why it's there, what it adds.
3. **[Setup](SETUP)** — install instructions, quick (Python-only) and
   full-automation (Ghidra/JDK/Ollama/Postgres/EMBER, one script) paths.
4. **[CLI reference](CLI)** — every subcommand and flag, captured from
   real `--help` output so it can't silently drift from the code.
5. **[Research](RESEARCH)** — the current research question (bounded LLM
   adjudication for hybrid malware triage), the evidence-bundle/routing/
   adjudication architecture, the dataset, and how to reproduce every
   number below.

## Results at a glance

Main experiment, 681 held-out test samples, three adjudicator models
under the same bounded routing policy. Full breakdown (per-format,
adversarial, calibration, significance tests) in [Research](RESEARCH).

| Arm | Precision | Recall | F1 | FPR | Coverage |
|---|---|---|---|---|---|
| EMBER2024 alone (PE, no LLM) | 0.983 | 0.338 | 0.503 | 1.9% | 32.5% |
| Hybrid[qwen3:8b] (local) | 0.886 | 0.766 | 0.822 | 11.5% | **84.9%** |
| Hybrid[gemma4:12b] (local) | 0.953 | 0.728 | 0.825 | 8.3% | 57.0% |
| Hybrid[Gemini 3.1 Pro] (frontier) | **0.992** | **0.725** | **0.837** | **0.8%** | 74.4% |

## Quick start

```bash
pip install -e .
mal-agent path/to/sample --source dataset --out ./out
mal-agent doctor   # toolchain health check
mal-agent web      # local web UI
```

Full quick-start, feature list, and "turn on more" options for every
optional tool: see the [project README](https://github.com/AnimeshShaw/mal-agent#readme).
