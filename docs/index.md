# mal-agent

**Evidence-grounded, agentic static malware analysis.** Every verdict
traces to tool evidence — nothing is guessed, and an LLM's opinion can
never move the deterministic score.

[:material-rocket-launch: Get started](getting-started.md){ .md-button .md-button--primary }
[View on GitHub](https://github.com/AnimeshShaw/mal-agent){ .md-button }

[Dataset on Hugging Face](https://huggingface.co/datasets/AnimeshShaw/mal-agent-llm-adjudication-eval) ·
[Full README](https://github.com/AnimeshShaw/mal-agent#readme) ·
[CLI Reference](CLI.md)

## Results at a glance

Main experiment, 681 held-out test samples, three adjudicator models
under the same bounded routing policy. Full breakdown (per-format,
adversarial, calibration, significance tests) in
[Research & Benchmarks](RESEARCH.md).

| Arm | Precision | Recall | F1 | FPR | Coverage |
|---|---|---|---|---|---|
| EMBER2024 alone (PE, no LLM) | 0.983 | 0.338 | 0.503 | 1.9% | 32.5% |
| Hybrid[qwen3:8b] (local) | 0.886 | 0.766 | 0.822 | 11.5% | **84.9%** |
| Hybrid[gemma4:12b] (local) | 0.953 | 0.728 | 0.825 | 8.3% | 57.0% |
| Hybrid[Gemini 3.1 Pro] (frontier) | **0.992** | **0.725** | **0.837** | **0.8%** | 74.4% |

## Start here

- **[Getting Started](getting-started.md)** — 30-second path, full
  install, web UI. Start here.
- **[CLI Reference](CLI.md)** — every command and flag
- **[Architecture](ARCHITECTURE.md)** — how it's put together and why
- **[Pipeline](PIPELINE.md)** — the exact tool-by-tool flow
- **[Research & Benchmarks](RESEARCH.md)** — the full numbers, how to
  reproduce them

## Quick start

```bash
pip install -e .
mal-agent path/to/sample --out ./out
mal-agent doctor   # toolchain health check
mal-agent web      # local web UI
```

No API keys, no Ghidra, no network required for this path. Full detail:
[Getting Started](getting-started.md).
