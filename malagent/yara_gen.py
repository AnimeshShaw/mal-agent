"""Deterministic YARA rule synthesis (M4, first slice). Builds one rule per
sample from grounded, tool-derived literal evidence (suspicious strings, risky
imports, IOCs found in the file). Capa rule-name matches and decompiled
pseudo-code are NOT literal byte sequences in the file, so they're excluded --
only excerpts that are themselves substrings actually present in the sample
belong in a YARA `strings:` block. RAG/narrative-driven rule generation is a
later step; this is the cheap, honest deterministic baseline."""
from __future__ import annotations
from .contracts import AnalysisState

_LITERAL_PREFIXES = ("string:", "import:", "ioc:")
_MAX_STRINGS = 20


def _escape(literal: str) -> str:
    return literal.replace("\\", "\\\\").replace('"', '\\"')


def generate_yara_rules(state: AnalysisState) -> list[str]:
    grounded_ev_ids = {eid for f in state.findings if f.grounded for eid in f.evidence}
    if not grounded_ev_ids:
        return []

    literals: list[str] = []
    seen: set[str] = set()
    for ev in state.evidence:
        if ev.evidence_id not in grounded_ev_ids or ev.trust != "tool":
            continue
        if not ev.locator or not ev.locator.startswith(_LITERAL_PREFIXES):
            continue
        if not ev.excerpt or ev.excerpt in seen:
            continue
        seen.add(ev.excerpt)
        literals.append(ev.excerpt)
    if not literals:
        return []

    literals = literals[:_MAX_STRINGS]
    lines = [
        f"rule mal_agent_{state.sample.sha256[:16]}",
        "{",
        "    meta:",
        f"        sha256 = \"{state.sample.sha256}\"",
        "        generated_by = \"mal-agent\"",
        "    strings:",
    ]
    for i, lit in enumerate(literals):
        lines.append(f"        $s{i} = \"{_escape(lit)}\"")
    threshold = min(2, len(literals))
    lines.append("    condition:")
    lines.append(f"        uint16(0) == 0x5A4D and {threshold} of them")
    lines.append("}")
    return ["\n".join(lines)]
