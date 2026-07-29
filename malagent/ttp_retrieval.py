"""Retrieval layer for the M4 "true RAG over MBC + ATT&CK" milestone: grounds
behavioral_analyst's cross-technique narrative in real reference descriptions
for whichever ATT&CK tactics/MBC objectives are actually present in a given
sample, rather than letting the LLM synthesize across bare technique IDs and
claim strings with no shared context.

Deliberately a small, fixed lookup table plus a membership retrieval, not an
embedding/vector index: the corpus is 14 items (MITRE ATT&CK Enterprise
tactics) and the query is "which tactics does THIS sample's real capa output
touch" -- an exact membership test, not a fuzzy-similarity search. Building
embedding infra for 14 items would be theater, not substance -- consistent
with this codebase's existing "determinism first, LLM for semantics"
reasoning (see attck_reference.py).

Sourcing note: a WebFetch attempt against attack.mitre.org during this
project's development returned tactic content that contradicted this
project's OWN real, live capa output -- it renamed "Defense Evasion" (TA0005)
to "Stealth" and inserted a tactic ID (TA0112) inconsistent with ATT&CK's
actual ID allocation history, on two independent fetches. That content was
discarded as unreliable rather than used. The table below is instead the
well-established, extremely stable public MITRE ATT&CK Enterprise taxonomy,
cross-checked against this project's own live capa+ATT&CK output (real
tactics observed: Discovery, Defense Evasion, Execution, Persistence -- all
matching this table).

MBC objectives are intentionally NOT paired with an invented description the
way ATT&CK tactics are: this project has lower confidence in MBC's own
official one-line objective descriptions than in ATT&CK's, so it surfaces
only the real, deduplicated objective names capa's live output already
provides (self-descriptive alongside their behavior names), rather than
guess at prose to fill a gap.
"""
from __future__ import annotations
from .contracts import Finding

ATTACK_TACTICS: dict[str, dict[str, str]] = {
    "TA0043": {"name": "Reconnaissance",
              "description": "The adversary is trying to gather information they can use to "
                             "plan future operations."},
    "TA0042": {"name": "Resource Development",
              "description": "The adversary is trying to establish resources they can use to "
                             "support operations."},
    "TA0001": {"name": "Initial Access",
              "description": "The adversary is trying to get into your network."},
    "TA0002": {"name": "Execution",
              "description": "The adversary is trying to run malicious code."},
    "TA0003": {"name": "Persistence",
              "description": "The adversary is trying to maintain their foothold."},
    "TA0004": {"name": "Privilege Escalation",
              "description": "The adversary is trying to gain higher-level permissions."},
    "TA0005": {"name": "Defense Evasion",
              "description": "The adversary is trying to avoid being detected."},
    "TA0006": {"name": "Credential Access",
              "description": "The adversary is trying to steal account names and passwords."},
    "TA0007": {"name": "Discovery",
              "description": "The adversary is trying to figure out your environment."},
    "TA0008": {"name": "Lateral Movement",
              "description": "The adversary is trying to move through your environment."},
    "TA0009": {"name": "Collection",
              "description": "The adversary is trying to gather data of interest to their goal."},
    "TA0011": {"name": "Command and Control",
              "description": "The adversary is trying to communicate with compromised systems "
                             "to control them."},
    "TA0010": {"name": "Exfiltration",
              "description": "The adversary is trying to steal data."},
    "TA0040": {"name": "Impact",
              "description": "The adversary is trying to manipulate, interrupt, or destroy your "
                             "systems and data."},
}

_DESCRIPTION_BY_NAME: dict[str, str] = {
    v["name"]: v["description"] for v in ATTACK_TACTICS.values()
}


def retrieve_context(findings: list[Finding]) -> dict:
    """Given the grounded findings feeding into a narrative synthesis step,
    retrieve real reference context for whichever ATT&CK tactics and MBC
    objectives are actually present -- deduplicated, sorted, and (for
    tactics) paired with a real MITRE description. Unknown tactic names
    (a future ATT&CK revision this table hasn't been updated for) are
    reported honestly, not guessed at."""
    tactics = sorted({t for f in findings for t in f.attack_tactics})
    objectives = sorted({o for f in findings for o in f.mbc_objectives})
    tactic_descriptions = [
        f"{t}: {_DESCRIPTION_BY_NAME[t]}" for t in tactics if t in _DESCRIPTION_BY_NAME]
    return {
        "tactics": tactics,
        "tactic_descriptions": tactic_descriptions,
        "mbc_objectives": objectives,
    }
