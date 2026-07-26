"""Deterministic YARA rule synthesis (M4, first slice; capability-combination
logic added later). Builds one rule per sample from grounded, tool-derived
literal evidence (suspicious strings, risky imports, IOCs found in the
file). Capa rule-name matches and decompiled pseudo-code are NOT literal
byte sequences in the file, so they're excluded -- only excerpts that are
themselves substrings actually present in the sample belong in a YARA
`strings:` block. RAG/narrative-driven rule generation is a later step;
this is the cheap, honest deterministic baseline."""
from __future__ import annotations
from .contracts import AnalysisState

# Locator prefix -> YARA string-variable group prefix. Order matters only
# for the single-category fallback's determinism (dict preserves insertion
# order), not for correctness.
_PREFIX_TO_GROUP = {"import:": "imp", "ioc:": "ioc", "string:": "str"}
_MAX_STRINGS_PER_GROUP = 20


def _escape(literal: str) -> str:
    return literal.replace("\\", "\\\\").replace('"', '\\"')


def generate_yara_rules(state: AnalysisState) -> list[str]:
    grounded_ev_ids = {eid for f in state.findings if f.grounded for eid in f.evidence}
    if not grounded_ev_ids:
        return []

    groups: dict[str, list[str]] = {g: [] for g in _PREFIX_TO_GROUP.values()}
    seen: set[str] = set()
    for ev in state.evidence:
        if ev.evidence_id not in grounded_ev_ids or ev.trust != "tool":
            continue
        if not ev.locator or not ev.excerpt or ev.excerpt in seen:
            continue
        for prefix, group in _PREFIX_TO_GROUP.items():
            if ev.locator.startswith(prefix):
                seen.add(ev.excerpt)
                groups[group].append(ev.excerpt)
                break

    present = [g for g, lits in groups.items() if lits]
    if not present:
        return []

    lines = [
        f"rule mal_agent_{state.sample.sha256[:16]}",
        "{",
        "    meta:",
        f"        sha256 = \"{state.sample.sha256}\"",
        "        generated_by = \"mal-agent\"",
        "    strings:",
    ]
    for group in present:
        for i, lit in enumerate(groups[group][:_MAX_STRINGS_PER_GROUP]):
            lines.append(f"        ${group}{i} = \"{_escape(lit)}\"")

    lines.append("    condition:")
    if len(present) >= 2:
        # Capability-combination logic: evidence spanning >=2 distinct
        # categories (e.g. a risky import AND a suspicious string, not
        # just two coincidental string hits) requires a match from EACH
        # present category -- mirrors the same "corroboration across
        # categories, not just count" principle reporter.py already uses
        # for the deterministic verdict score, making the generated rule
        # more specific than a flat "any N of them" threshold.
        group_conditions = " and ".join(f"1 of (${g}*)" for g in present)
        lines.append(f"        uint16(0) == 0x5A4D and ({group_conditions})")
    else:
        # Only one category present -- no combination is possible, fall
        # back to the original flat threshold.
        only = present[0]
        threshold = min(2, len(groups[only]))
        lines.append(f"        uint16(0) == 0x5A4D and {threshold} of them")
    lines.append("}")
    return ["\n".join(lines)]
