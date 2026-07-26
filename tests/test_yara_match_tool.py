"""YARA rule MATCHING against a real corpus (docs/TODO.md Phase 2) --
distinct from the existing rule GENERATION in yara_gen.py. Same
env-var-configured-external-data pattern as CAPA_RULES_PATH/
KNOWN_GOOD_HASHES_PATH/IP_BLOCKLIST_PATH: the operator supplies their own
rules (never bundled -- third-party YARA rule sets have their own
licenses), pointed at via YARA_RULES_PATH."""
from __future__ import annotations
from malagent.contracts import AnalysisState, Provenance, Sample
from malagent.yara_match import YaraMatchTool


def _sample(tmp_path):
    p = tmp_path / "sample.malz"
    p.write_bytes(b"MZ" + b"this contains a marker string" + b"\x00" * 32)
    return p, Sample(sha256="a" * 64, md5="b" * 32, path=str(p),
                     file_type="PE", size=64, provenance=Provenance())


def _state(sample):
    return AnalysisState(run_id="r1", sample=sample)


def test_skips_when_no_rules_configured(monkeypatch, tmp_path):
    monkeypatch.delenv("YARA_RULES_PATH", raising=False)
    _, sample = _sample(tmp_path)
    sr = YaraMatchTool().run(_state(sample))
    assert sr.status == "skipped"
    assert "not configured" in (sr.unresolved[0] if sr.unresolved else "")


def test_skips_when_configured_path_does_not_exist(monkeypatch, tmp_path):
    monkeypatch.setenv("YARA_RULES_PATH", str(tmp_path / "nope.yar"))
    _, sample = _sample(tmp_path)
    sr = YaraMatchTool().run(_state(sample))
    assert sr.status == "skipped"


def test_matching_rule_produces_finding(monkeypatch, tmp_path):
    rules_file = tmp_path / "test.yar"
    rules_file.write_text(
        'rule marker_string { strings: $a = "marker string" condition: $a }')
    monkeypatch.setenv("YARA_RULES_PATH", str(rules_file))
    _, sample = _sample(tmp_path)
    sr = YaraMatchTool().run(_state(sample))
    assert sr.status == "ok"
    assert len(sr.findings) == 1
    assert "marker_string" in sr.findings[0].claim
    assert sr.findings[0].severity == "medium"


def test_no_match_produces_no_findings(monkeypatch, tmp_path):
    rules_file = tmp_path / "test.yar"
    rules_file.write_text(
        'rule not_present { strings: $a = "definitely_not_in_the_sample_xyz" '
        'condition: $a }')
    monkeypatch.setenv("YARA_RULES_PATH", str(rules_file))
    _, sample = _sample(tmp_path)
    sr = YaraMatchTool().run(_state(sample))
    assert sr.status == "ok"
    assert sr.findings == []


def test_rules_directory_compiles_all_files(monkeypatch, tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "a.yar").write_text(
        'rule rule_a { strings: $a = "marker string" condition: $a }')
    (rules_dir / "b.yar").write_text(
        'rule rule_b { strings: $a = "MZ" condition: $a }')
    monkeypatch.setenv("YARA_RULES_PATH", str(rules_dir))
    _, sample = _sample(tmp_path)
    sr = YaraMatchTool().run(_state(sample))
    assert sr.status == "ok"
    matched_rules = {f.claim for f in sr.findings}
    assert len(sr.findings) == 2
    assert any("rule_a" in c for c in matched_rules)
    assert any("rule_b" in c for c in matched_rules)


def test_invalid_rule_syntax_reports_error_not_crash(monkeypatch, tmp_path):
    rules_file = tmp_path / "bad.yar"
    rules_file.write_text("this is not valid yara syntax {{{")
    monkeypatch.setenv("YARA_RULES_PATH", str(rules_file))
    _, sample = _sample(tmp_path)
    sr = YaraMatchTool().run(_state(sample))
    assert sr.status == "error"


def test_evidence_locator_recognizable_for_corroboration_gate(monkeypatch, tmp_path):
    rules_file = tmp_path / "test.yar"
    rules_file.write_text(
        'rule marker_string { strings: $a = "marker string" condition: $a }')
    monkeypatch.setenv("YARA_RULES_PATH", str(rules_file))
    _, sample = _sample(tmp_path)
    sr = YaraMatchTool().run(_state(sample))
    assert sr.evidence[0].locator.startswith("yara_match:")


def test_rule_tags_included_in_claim(monkeypatch, tmp_path):
    rules_file = tmp_path / "test.yar"
    rules_file.write_text(
        'rule tagged_rule : ransomware trojan { strings: $a = "marker string" '
        'condition: $a }')
    monkeypatch.setenv("YARA_RULES_PATH", str(rules_file))
    _, sample = _sample(tmp_path)
    sr = YaraMatchTool().run(_state(sample))
    assert "ransomware" in sr.findings[0].claim
