"""Retrieval layer for the M4 "true RAG over MBC + ATT&CK" milestone
(docs/TODO.md M4: "no narrative synthesis across techniques... no retrieval
over MBC"). Grounds behavioral_analyst's cross-technique narrative in real,
retrieved reference context instead of bare technique IDs/claim strings.

Deliberately NOT an embedding/vector index: the corpus is a small, fixed set
(14 MITRE ATT&CK Enterprise tactics), and the query is "which tactics are
actually present in this sample's real capa matches" -- a discrete
membership lookup, not a fuzzy-similarity search. Building embedding infra
for 14 items would be theater, not substance (matches this project's
existing "determinism first" reasoning in attck_reference.py).

The 14 tactic names/descriptions below are NOT sourced from a live fetch:
a WebFetch attempt against attack.mitre.org during this session returned
tactic content that contradicted this project's own real, live capa output
(renamed "Defense Evasion" to "Stealth", inserted a tactic ID -- TA0112 --
inconsistent with ATT&CK's actual ID allocation history) on two independent
fetches. That fetched content was discarded as unreliable/corrupted rather
than used. These names/IDs are instead the well-established, extremely
stable public MITRE ATT&CK Enterprise taxonomy, cross-checked against this
project's own real, live capa+ATT&CK output (see test_capa_tool.py's
test_attack_tactic_names_captured_alongside_technique_ids and a live run
against dataset/malicious/b65652fadf25dda777fe0374fdae972d1bd8b2321df47da858fe3a3dce28851e.bin,
which surfaced real tactics: Discovery, Defense Evasion, Execution,
Persistence -- all matching this table, none matching the discarded fetch).
"""
from __future__ import annotations
from malagent.contracts import Finding
from malagent.ttp_retrieval import ATTACK_TACTICS, retrieve_context


def _finding(tactics=(), objectives=(), category="capability"):
    return Finding(finding_id="f1", claim="x", category=category, severity="info",
                  confidence=0.5, attack_tactics=list(tactics), mbc_objectives=list(objectives))


def test_all_14_enterprise_tactics_present_with_real_ids():
    # Real, stable MITRE ATT&CK Enterprise tactic IDs -- TA0001-TA0011,
    # TA0040, TA0042, TA0043 (14 total). Guards against the corpus
    # silently losing entries or drifting to fabricated IDs.
    expected_ids = {"TA0043", "TA0042", "TA0001", "TA0002", "TA0003", "TA0004",
                    "TA0005", "TA0006", "TA0007", "TA0008", "TA0009", "TA0011",
                    "TA0010", "TA0040"}
    assert set(ATTACK_TACTICS) == expected_ids
    assert len(ATTACK_TACTICS) == 14


def test_defense_evasion_name_matches_live_verified_capa_output():
    """The exact bug this guards against: a WebFetch attempt renamed this
    tactic to 'Stealth' -- must never regress to that."""
    assert ATTACK_TACTICS["TA0005"]["name"] == "Defense Evasion"
    assert ATTACK_TACTICS["TA0005"]["name"] != "Stealth"


def test_no_fabricated_ta0112_tactic():
    assert "TA0112" not in ATTACK_TACTICS


def test_retrieve_context_returns_descriptions_only_for_present_tactics():
    findings = [_finding(tactics=["Defense Evasion"]), _finding(tactics=["Discovery"])]
    ctx = retrieve_context(findings)
    assert ctx["tactics"] == ["Defense Evasion", "Discovery"]
    assert len(ctx["tactic_descriptions"]) == 2
    assert any("Defense Evasion" in d for d in ctx["tactic_descriptions"])
    assert any("hide" in d.lower() or "detect" in d.lower() or "evade" in d.lower()
              or "avoid" in d.lower() for d in ctx["tactic_descriptions"])


def test_retrieve_context_deduplicates_across_findings():
    findings = [_finding(tactics=["Discovery"]), _finding(tactics=["Discovery"])]
    ctx = retrieve_context(findings)
    assert ctx["tactics"] == ["Discovery"]
    assert len(ctx["tactic_descriptions"]) == 1


def test_retrieve_context_includes_real_mbc_objectives_without_inventing_descriptions():
    """MBC objectives are surfaced as real, retrieved-and-deduplicated names
    (self-descriptive alongside their behaviors), not paired with an
    invented one-line gloss the way ATT&CK tactics are -- this project has
    lower confidence in MBC's own official descriptions than in ATT&CK's
    extremely stable, universally-documented ones, so it doesn't guess."""
    findings = [_finding(objectives=["File System"]), _finding(objectives=["Process"])]
    ctx = retrieve_context(findings)
    assert ctx["mbc_objectives"] == ["File System", "Process"]


def test_retrieve_context_empty_when_nothing_present():
    ctx = retrieve_context([_finding()])
    assert ctx == {"tactics": [], "tactic_descriptions": [], "mbc_objectives": []}


def test_unknown_tactic_name_not_in_table_is_skipped_not_crashed():
    """Defensive: if capa's live output ever reports a tactic name that
    doesn't match this table (a future ATT&CK revision adds/renames one),
    retrieval must degrade honestly (omit it) rather than raise."""
    findings = [_finding(tactics=["Some Future Tactic Nobody Has Heard Of"])]
    ctx = retrieve_context(findings)
    assert ctx["tactics"] == ["Some Future Tactic Nobody Has Heard Of"]
    assert ctx["tactic_descriptions"] == []
