# Contributing to MAL-AGENT

Thanks for considering a contribution. This project is early-stage
(v0.1) and welcomes issues, discussion, and pull requests.

## Before you start

- Read **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** — the evidence-grounding
  model and the "LLMs never decide the verdict" invariant are the two
  design rules every change must respect.
- For anything non-trivial, open an issue to discuss the approach before
  writing code — saves both of us rework.

## Development setup

```bash
git clone https://github.com/AnimeshShaw/mal-agent.git
cd mal-agent
./scripts/install.ps1   # Windows
./scripts/install.sh    # Linux/macOS
mal-agent doctor        # confirm your toolchain
```

Full detail, including the full-automation path: `docs/SETUP.md`.

## Workflow

This codebase was built test-first and stays that way:

1. **Write a failing test** for the behavior you're adding or fixing.
   Run it, confirm it fails for the reason you expect (not a typo or
   import error).
2. **Write the minimal implementation** that makes it pass.
3. **Run the full suite** before opening a PR:
   ```bash
   pytest -q
   ```
4. Keep commits focused — one logical change per commit, clear message
   explaining *why*, not just *what*.

## Ground rules for changes

- **No finding influences the verdict score unless it's grounded**
  (`finding.evidence` resolves to real `EvidenceRecord`s and
  `verifier_agent` confirms it). Don't bypass this.
- **LLM-derived findings must never carry weight in
  `reporter.build_verdict()`.** If you touch `behavioral_analyst`,
  `verifier_critic`, or the scoring function, run
  `tests/test_llm_agents_never_score.py` and make sure it still fails if
  you deliberately break the invariant (mutation-test it once, then fix
  your code) before submitting.
- **Egress fails closed.** If a cloud escalation is blocked by policy,
  the correct behavior is `undetermined`, never a silent fallback that
  looks like a real answer.
- **Live-verify tool integrations where possible.** Unit tests with
  hand-written fakes are necessary but not sufficient — this project has
  twice caught real API-shape bugs (a `pefile` attribute that doesn't
  exist under `fast_load`, a pipeline-ordering bug) only by running
  against the real tool. If you're changing a `*Tool` adapter, run it
  against a real sample if you can.

## Reporting bugs / requesting features

Open a GitHub issue. Include:
- What you ran (command, sample type — no need to attach real malware;
  a description or a benign PE reproducing the issue is fine)
- What you expected vs. what happened
- `mal-agent doctor` output, if the issue might be environment-related

## Code of conduct

Be respectful, assume good faith, keep discussion technical. Reports of
abusive behavior can be sent to the maintainer directly.
