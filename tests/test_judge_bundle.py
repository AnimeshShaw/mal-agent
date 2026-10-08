"""Evidence bundles: one frozen, JSON-serializable record per sample that
every experimental arm reads, so arms differ only in their decision rule."""
from __future__ import annotations
import json

from malagent.contracts import (AnalysisState, EvidenceRecord, Finding, Provenance, Sample,
                                StageResult)
from malagent.judge.bundle import (BUNDLE_SCHEMA, build_bundle, load_bundles, provenance_of,
                                   save_bundle)


def _state(file_type="PE", ember=0.9):
    s = AnalysisState(run_id="r1", sample=Sample(sha256="c" * 64, md5="d" * 32, path="x",
                      file_type=file_type, size=123, provenance=Provenance()))
    s.evidence = [
        EvidenceRecord(evidence_id="e_ember", artifact_id="a", locator="ember:score",
                       excerpt=f"{ember:.4f}"),
        EvidenceRecord(evidence_id="e_capa", artifact_id="a",
                       locator="capa:communication:connect to URL", excerpt="connect to URL"),
        EvidenceRecord(evidence_id="e_ioc", artifact_id="a", locator="ioc:url",
                       excerpt="http://evil.example/x"),
        EvidenceRecord(evidence_id="e_scr", artifact_id="a", locator="script:excerpt",
                       excerpt="IEX (New-Object Net.WebClient)", trust="sample"),
        EvidenceRecord(evidence_id="e_fmt", artifact_id="a", locator="format:type", excerpt="pe"),
    ]
    s.findings = [
        Finding(finding_id="f_ember", claim="EMBER", category="capability", severity="info",
                evidence=["e_ember"], grounded=True, source_stage="triage"),
        Finding(finding_id="f_capa", claim="connect to URL", category="capability",
                severity="medium", confidence=0.7, evidence=["e_capa"], grounded=True,
                attack_techniques=["T1071"], source_stage="triage"),
    ]
    s.stage_results = [StageResult(stage="triage", status="ok", tool="capa"),
                       StageResult(stage="triage", status="skipped", tool="die",
                                   unresolved=["diec not on PATH"])]
    return s


def test_provenance_marks_sample_text():
    assert provenance_of(EvidenceRecord(evidence_id="1", artifact_id="a", locator="ioc:url")) == "sample_text"
    assert provenance_of(EvidenceRecord(evidence_id="1", artifact_id="a", locator="x",
                                        trust="sample")) == "sample_text"
    assert provenance_of(EvidenceRecord(evidence_id="1", artifact_id="a",
                                        locator="capa:communication:x")) == "tool"
    assert provenance_of(EvidenceRecord(evidence_id="1", artifact_id="a",
                                        locator="unpacker:contains:a/b.exe")) == "sample_text"


def test_bundle_core_fields():
    b = build_bundle(_state(), label="malicious", meta={"source": "unit"})
    assert b["schema"] == BUNDLE_SCHEMA
    assert b["sha256"] == "c" * 64
    assert b["label"] == "malicious"
    assert b["format"] == "pe"
    assert b["ember"]["score"] == 0.9 and b["ember"]["decisive"] == 0.9
    ev = {e["id"]: e for e in b["evidence"]}
    assert ev["e_ioc"]["provenance"] == "sample_text"
    assert ev["e_capa"]["provenance"] == "tool"
    assert b["tools"] and any(t["tool"] == "die" and t["status"] == "skipped" for t in b["tools"])


def test_bundle_carries_baseline_verdicts_for_every_arm():
    b = build_bundle(_state(ember=0.9))
    assert b["baselines"]["simple"]["verdict"] == "malicious"
    assert set(b["baselines"]) == {"simple", "cgef", "gate"}
    # gate-only ignores EMBER entirely: one medium category -> not corroborated
    assert b["baselines"]["gate"]["verdict"] in ("undetermined", "benign")


def test_non_pe_bundle_has_no_decisive_ember():
    b = build_bundle(_state(file_type="unknown", ember=0.95))
    assert b["ember"]["score"] == 0.95
    assert b["ember"]["decisive"] is None


def test_bundle_excerpts_are_truncated():
    s = _state()
    s.evidence.append(EvidenceRecord(evidence_id="e_long", artifact_id="a",
                                     locator="script:excerpt", excerpt="A" * 10000, trust="sample"))
    b = build_bundle(s)
    long = next(e for e in b["evidence"] if e["id"] == "e_long")
    assert len(long["excerpt"]) <= 1500


def test_save_and_load_roundtrip(tmp_path):
    b = build_bundle(_state(), label="benign")
    save_bundle(b, tmp_path)
    loaded = load_bundles(tmp_path)
    assert len(loaded) == 1 and loaded[0]["sha256"] == "c" * 64
    json.dumps(loaded[0])  # fully JSON-serializable
