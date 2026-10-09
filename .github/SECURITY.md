# Security Policy

mal-agent processes untrusted, often actively malicious files by design.
That makes its own security posture more than boilerplate — a real
vulnerability here has a correspondingly real blast radius (the exact
thing it's meant to analyze safely).

## Supported versions

Pre-1.0 (`0.x`), single rolling release on `main`. Security fixes land
on `main` and are not backported to older tags.

## Reporting a vulnerability

**Please do not open a public GitHub issue for a security report.**

Use GitHub's private vulnerability reporting instead:
[github.com/AnimeshShaw/mal-agent/security/advisories/new](https://github.com/AnimeshShaw/mal-agent/security/advisories/new).
If that's unavailable, email **animeshshaw@pm.me** with:

- A clear description of the issue and its impact
- Steps to reproduce (a minimal sample or request, if applicable — see
  [Sending a sample safely](#sending-a-sample-safely))
- Affected version/commit

You should get an initial response within **5 business days**. This is
an independent, single-maintainer project — there's no SLA beyond best
effort, but reports are taken seriously and fixed promptly once
confirmed.

## Sending a sample safely

If a report depends on a specific malicious file: **do not attach the
raw file to a public issue, email, or anywhere it could be auto-executed
by a mail client or issue previewer.** Zip it with a password (`infected`
is the informal industry convention, e.g. 7-Zip/WinRAR with
`-pinfected`) or share a hash + a link to where you sourced it (e.g.
MalwareBazaar) instead of the bytes themselves.

## What's in scope

- **Agent/tool security**: a crafted sample causing command injection,
  path traversal, or arbitrary code execution via any of the
  deterministic tools or the LLM reasoning stages (`malagent/*.py`,
  `malagent/judge/`).
- **Prompt injection that escapes its boundary**: `security.py`'s
  `scan_for_injection`/`wrap_untrusted` exist specifically to stop
  attacker-controlled sample text from being treated as an instruction
  by an LLM stage. A bypass of that boundary is a real finding.
- **Web UI (`web/backend/`, `web/frontend/`)**: authentication bypass,
  CSRF, XSS (the HTML report renders text extracted from the sample
  itself — see the `report.html` CSP and ticket-based navigation in
  `app.py` for the existing mitigation), SSRF, path traversal via the
  server-side-path analysis feature, or anything that defeats the
  loopback-only-without-a-token binding rule.
- **Secrets/credential handling**: anything that could leak
  `.env`-configured API keys or the web UI's bearer token.
- **Supply chain**: a malicious or typosquatted dependency reachable
  from a default install.

## What's explicitly out of scope

- **The deterministic verdict being wrong on a specific sample.** This
  is a static-analysis heuristic system, not a guarantee — a false
  positive/negative on a particular file is a quality bug (open a normal
  issue), not a security vulnerability, unless it's caused by one of the
  items above.
- **Resource exhaustion from analyzing a file you deliberately chose to
  be huge/malformed**, when done against your *own* local instance.
  (A remotely-triggerable DoS against a *shared* deployment, e.g. via
  the web API's upload endpoint, **is** in scope.)
- **Vulnerabilities in third-party tools this project orchestrates**
  (Ghidra, capa, YARA, Ollama, cloud LLM providers) — report those
  upstream. If this project uses one of them in a way that *creates* a
  new vulnerability (e.g. passing untrusted input to a known-unsafe API),
  that integration bug is in scope here.

## Design decisions that already exist for this reason

Documented in depth in [`docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md)
and the module docstrings themselves — summarized here so a reporter
can tell "known, intentional tradeoff" from "bug":

- Binding to a non-loopback host without `MAL_AGENT_WEB_TOKEN` set
  refuses to start outright.
- Uploaded samples are streamed to disk under a size cap, stored under a
  neutral filename (never the client's own name/extension), and the
  evidence-bundle/report pipeline defangs IOCs rather than rendering
  them live.
- Every LLM-touched pipeline stage is hardcoded to zero scoring weight —
  an LLM's output, however convincing, cannot move the deterministic
  verdict (enforced by `tests/test_llm_agents_never_score.py`, not just
  documented).
- Network egress (cloud LLM calls, VirusTotal, hash lookups) requires
  explicit, separately-scoped opt-in via `EgressPolicy` — nothing phones
  home by default.
