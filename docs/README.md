# Documentation index

**Start here, in this order:**

1. **[ARCHITECTURE.md](ARCHITECTURE.md)** — how the system is put
   together and why. Read this first.
2. **[PIPELINE.md](PIPELINE.md)** — the exact tool-by-tool pipeline, one
   diagram + a plain-language table: what each tool does, why it's
   there, what it adds.
3. **[SETUP.md](SETUP.md)** — install instructions, both quick
   (Python-only) and full-automation paths.
4. **[EFFICIENCY.md](EFFICIENCY.md)** — real measured wall-clock timing
   per pipeline stage, and why cost isn't computed yet.
5. **[ABLATION_LLM.md](ABLATION_LLM.md)** — real, executed ablation:
   deterministic-only vs. deterministic + LLM, over real samples. Checks
   the "LLMs narrate, never judge" invariant empirically, not just via
   unit test.
6. **[ML_CLASSIFIER_PLAN.md](ML_CLASSIFIER_PLAN.md)** — why the
   deterministic gate abstains on 81.6% of samples, the decision to
   adopt a pretrained classifier (EMBER2024) instead of training from
   71 labels, and the phased plan to add it as a decision layer.
7. **[AI-Malware-Analysis-Research-and-Framework.md](AI-Malware-Analysis-Research-and-Framework.md)**
   — the research framing this project grew out of.
