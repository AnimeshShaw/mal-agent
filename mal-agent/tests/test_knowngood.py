"""Known-good hash allowlist (D6-adjacent triage optimization): if a sample's
SHA256 matches a trusted reference hash (e.g. an NSRL export, or a curated
list of known-good vendor binaries), the pipeline can stop early rather than
running expensive decompilation/LLM stages on something already known to be
exactly byte-for-byte a trusted file. Cryptographic hash equality is about as
strong a "this IS that exact file" signal as exists -- much stronger than
heuristic capability scoring, which is why notepad.exe needed a scoring fix
at all in the first place."""
from __future__ import annotations
from malagent.contracts import AnalysisState, Provenance, Sample, StepBudget
from malagent.knowngood import KnownGoodTool, is_known_good_match, load_known_good_hashes


def _sample(sha256="a" * 64):
    return Sample(sha256=sha256, md5="b" * 32, path="/tmp/x.malz",
                  file_type="PE", size=10, provenance=Provenance())


def _state(sha256="a" * 64):
    return AnalysisState(run_id="r1", sample=_sample(sha256), budget=StepBudget())


# ---------- load_known_good_hashes ----------

def test_loads_plain_hash_list(tmp_path):
    p = tmp_path / "hashes.txt"
    p.write_text("AAAA\nbbbb\n")
    hashes = load_known_good_hashes(str(p))
    assert hashes == {"aaaa", "bbbb"}


def test_ignores_blank_lines_and_comments(tmp_path):
    p = tmp_path / "hashes.txt"
    p.write_text("# NSRL export\naaaa\n\n  \nbbbb\n")
    assert load_known_good_hashes(str(p)) == {"aaaa", "bbbb"}


def test_supports_csv_hash_name_format(tmp_path):
    p = tmp_path / "hashes.csv"
    p.write_text("aaaa,notepad.exe\nbbbb,calc.exe\n")
    assert load_known_good_hashes(str(p)) == {"aaaa", "bbbb"}


def test_missing_file_returns_empty_set(tmp_path):
    assert load_known_good_hashes(str(tmp_path / "nope.txt")) == set()


# ---------- KnownGoodTool ----------

def test_skipped_when_no_allowlist_configured(monkeypatch):
    monkeypatch.delenv("KNOWN_GOOD_HASHES_PATH", raising=False)
    sr = KnownGoodTool().run(_state())
    assert sr.status == "skipped"


def test_matches_configured_allowlist(monkeypatch, tmp_path):
    p = tmp_path / "hashes.txt"
    p.write_text("a" * 64 + "\n")
    monkeypatch.setenv("KNOWN_GOOD_HASHES_PATH", str(p))
    state = _state(sha256="a" * 64)
    sr = KnownGoodTool().run(state)
    assert sr.status == "ok"
    assert len(sr.findings) == 1
    f = sr.findings[0]
    assert f.category == "verdict_factor"
    assert f.confidence >= 0.9
    assert f.evidence


def test_no_match_produces_no_findings(monkeypatch, tmp_path):
    p = tmp_path / "hashes.txt"
    p.write_text("c" * 64 + "\n")
    monkeypatch.setenv("KNOWN_GOOD_HASHES_PATH", str(p))
    state = _state(sha256="a" * 64)
    sr = KnownGoodTool().run(state)
    assert sr.status == "ok"
    assert sr.findings == []


def test_match_is_case_insensitive(monkeypatch, tmp_path):
    p = tmp_path / "hashes.txt"
    p.write_text("A" * 64 + "\n")
    monkeypatch.setenv("KNOWN_GOOD_HASHES_PATH", str(p))
    state = _state(sha256="a" * 64)
    sr = KnownGoodTool().run(state)
    assert len(sr.findings) == 1


# ---------- is_known_good_match (used by the orchestrator to skip stages) ----------

def test_is_known_good_match_true_when_verdict_factor_finding_present():
    state = _state()
    KnownGoodTool  # noqa: keep import used
    from malagent.contracts import EvidenceRecord, Finding
    state.evidence.append(EvidenceRecord(evidence_id="ev1", artifact_id="a1",
                                         locator="known_good:sha256", excerpt="a"*64, trust="tool"))
    state.findings.append(Finding(finding_id="f1", claim="x", category="verdict_factor",
                                  severity="info", confidence=0.97, evidence=["ev1"]))
    assert is_known_good_match(state) is True


def test_is_known_good_match_false_otherwise():
    assert is_known_good_match(_state()) is False
