"""Deterministic YARA rule synthesis (M4) from grounded, tool-derived literal
evidence (suspicious strings, risky imports, IOCs). No RAG yet -- this is the
cheap deterministic slice; narrative-driven rule generation is a later step."""
from __future__ import annotations
from malagent.contracts import EvidenceRecord, Finding
from malagent.yara_gen import generate_yara_rules
from tests.test_escalation import _sample
from malagent.contracts import AnalysisState


def _state_with(evidence, findings):
    s = AnalysisState(run_id="r1", sample=_sample())
    s.evidence = evidence
    s.findings = findings
    return s


def _grounded_finding(fid, ev_id):
    return Finding(finding_id=fid, claim="x", category="capability",
                   evidence=[ev_id], grounded=True)


def test_no_qualifying_evidence_yields_no_rules():
    state = _state_with(evidence=[], findings=[])
    assert generate_yara_rules(state) == []


def test_suspicious_string_evidence_produces_a_rule():
    ev = EvidenceRecord(evidence_id="ev1", artifact_id="art1",
                        locator="string:powershell", excerpt="powershell", trust="tool")
    state = _state_with(evidence=[ev], findings=[_grounded_finding("f1", "ev1")])
    rules = generate_yara_rules(state)
    assert len(rules) == 1
    assert "powershell" in rules[0]
    assert rules[0].startswith("rule mal_agent_")
    assert "uint16(0) == 0x5A4D" in rules[0]


def test_rule_name_uses_sha256_prefix_and_is_a_valid_identifier():
    ev = EvidenceRecord(evidence_id="ev1", artifact_id="art1",
                        locator="import:WinExec", excerpt="WinExec", trust="tool")
    state = _state_with(evidence=[ev], findings=[_grounded_finding("f1", "ev1")])
    rules = generate_yara_rules(state)
    first_line = rules[0].splitlines()[0]
    assert first_line == f"rule mal_agent_{state.sample.sha256[:16]}"


def test_deduplicates_identical_string_literals():
    ev1 = EvidenceRecord(evidence_id="ev1", artifact_id="art1",
                         locator="string:cmd.exe", excerpt="cmd.exe", trust="tool")
    ev2 = EvidenceRecord(evidence_id="ev2", artifact_id="art1",
                         locator="import:cmd.exe", excerpt="cmd.exe", trust="tool")
    state = _state_with(evidence=[ev1, ev2],
                        findings=[_grounded_finding("f1", "ev1"), _grounded_finding("f2", "ev2")])
    rules = generate_yara_rules(state)
    assert rules[0].count('"cmd.exe"') == 1


def test_escapes_double_quotes_in_string_literal():
    ev = EvidenceRecord(evidence_id="ev1", artifact_id="art1",
                        locator="ioc:url", excerpt='http://evil.example/"payload',
                        trust="tool")
    state = _state_with(evidence=[ev], findings=[_grounded_finding("f1", "ev1")])
    rules = generate_yara_rules(state)
    assert 'http://evil.example/\\"payload' in rules[0]


def test_ignores_ungrounded_findings_and_model_trust_evidence():
    ev = EvidenceRecord(evidence_id="ev1", artifact_id="art1",
                        locator="string:foo", excerpt="foo", trust="model")
    state = _state_with(evidence=[ev], findings=[_grounded_finding("f1", "ev1")])
    assert generate_yara_rules(state) == []


def test_non_literal_locator_prefixes_are_excluded():
    # capa rule-name matches and function-decompile evidence aren't literal
    # byte sequences in the file -- they shouldn't become YARA string literals.
    ev = EvidenceRecord(evidence_id="ev1", artifact_id="art1",
                        locator="capa:some-rule", excerpt="some-rule", trust="tool")
    state = _state_with(evidence=[ev], findings=[_grounded_finding("f1", "ev1")])
    assert generate_yara_rules(state) == []
