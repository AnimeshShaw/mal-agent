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


def test_single_category_evidence_falls_back_to_flat_count_threshold():
    """With only one evidence category present, capability-combination
    logic isn't possible -- preserves the original flat 'N of them'
    threshold behavior."""
    evs = [
        EvidenceRecord(evidence_id="ev1", artifact_id="art1",
                       locator="string:cmd.exe", excerpt="cmd.exe", trust="tool"),
        EvidenceRecord(evidence_id="ev2", artifact_id="art1",
                       locator="string:powershell", excerpt="powershell", trust="tool"),
    ]
    findings = [_grounded_finding("f1", "ev1"), _grounded_finding("f2", "ev2")]
    state = _state_with(evidence=evs, findings=findings)
    rules = generate_yara_rules(state)
    assert "2 of" in rules[0]


def test_multi_category_evidence_requires_a_match_from_each_category():
    """Real refinement: evidence spanning >=2
    distinct categories (e.g. a risky import AND a suspicious string, not
    just two coincidental string hits) should produce a more specific
    rule requiring a match from EACH present category -- mirrors the same
    'corroboration across categories, not just count' principle already
    used for the deterministic verdict score (reporter.py)."""
    evs = [
        EvidenceRecord(evidence_id="ev1", artifact_id="art1",
                       locator="import:WinExec", excerpt="WinExec", trust="tool"),
        EvidenceRecord(evidence_id="ev2", artifact_id="art1",
                       locator="string:powershell", excerpt="powershell", trust="tool"),
    ]
    findings = [_grounded_finding("f1", "ev1"), _grounded_finding("f2", "ev2")]
    state = _state_with(evidence=evs, findings=findings)
    rules = generate_yara_rules(state)
    condition_line = [l for l in rules[0].splitlines() if "uint16" in l][0]
    assert "1 of ($imp*)" in condition_line
    assert "1 of ($str*)" in condition_line
    assert " and " in condition_line


def test_three_category_evidence_requires_all_three():
    evs = [
        EvidenceRecord(evidence_id="ev1", artifact_id="art1",
                       locator="import:WinExec", excerpt="WinExec", trust="tool"),
        EvidenceRecord(evidence_id="ev2", artifact_id="art1",
                       locator="string:powershell", excerpt="powershell", trust="tool"),
        EvidenceRecord(evidence_id="ev3", artifact_id="art1",
                       locator="ioc:url", excerpt="http://evil.example/x", trust="tool"),
    ]
    findings = [_grounded_finding(f"f{i}", f"ev{i}") for i in (1, 2, 3)]
    state = _state_with(evidence=evs, findings=findings)
    rules = generate_yara_rules(state)
    condition_line = [l for l in rules[0].splitlines() if "uint16" in l][0]
    assert "1 of ($imp*)" in condition_line
    assert "1 of ($str*)" in condition_line
    assert "1 of ($ioc*)" in condition_line


def test_multi_category_rule_still_compiles_as_valid_yara():
    """The whole point is a real, usable rule -- must actually compile."""
    import yara
    evs = [
        EvidenceRecord(evidence_id="ev1", artifact_id="art1",
                       locator="import:WinExec", excerpt="WinExec", trust="tool"),
        EvidenceRecord(evidence_id="ev2", artifact_id="art1",
                       locator="string:powershell", excerpt="powershell", trust="tool"),
    ]
    findings = [_grounded_finding("f1", "ev1"), _grounded_finding("f2", "ev2")]
    state = _state_with(evidence=evs, findings=findings)
    rules = generate_yara_rules(state)
    yara.compile(source=rules[0])  # raises on invalid syntax
