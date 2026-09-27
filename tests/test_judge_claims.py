"""Claim-level verification of analyst narratives."""
from __future__ import annotations
import csv
import json

from malagent.judge.claims import (check_claim_deterministic, export_annotation_csv,
                                   import_annotations, judge_claim, split_claims, verify_narrative)
from malagent.judge.providers import GenResult
from malagent.judge.render import render_evidence


def _bundle():
    return {"sha256": "e" * 64, "format": "pe", "size": 10, "label": "malicious",
            "ember": {"score": 0.9, "decisive": 0.9},
            "gate": {"categories": ["communication"], "signed": False, "required": 3},
            "evidence": [
                {"id": "ev_capa", "locator": "capa:communication:connect to URL", "tool": "capa",
                 "excerpt": "connect to URL", "provenance": "tool"},
                {"id": "ev_imp", "locator": "import:CreateRemoteThread", "tool": "import",
                 "excerpt": "kernel32.dll!CreateRemoteThread", "provenance": "tool"},
                {"id": "ev_ioc", "locator": "ioc:url", "tool": "ioc",
                 "excerpt": "http://evil.example/gate.php", "provenance": "sample_text"}],
            "findings": [{"id": "f1", "claim": "connect to URL", "severity": "medium",
                          "category": "capability", "evidence": ["ev_capa"], "attack": ["T1071"],
                          "stage": "triage", "grounded": True}],
            "tools": [], "iocs": []}


def test_split_claims_keeps_citations_per_sentence():
    claims = split_claims("It connects to a URL [E1]. It injects code via CreateRemoteThread [E2, E3]. "
                          "Overall it is a loader.")
    assert [c["cited"] for c in claims] == [["E1"], ["E2", "E3"], []]


def test_deterministic_checks():
    r = render_evidence(_bundle(), mode="provenance")
    alias = {v: k for k, v in r.id_map.items()}
    ok = check_claim_deterministic(
        {"text": f"It calls CreateRemoteThread [{alias['ev_imp']}].", "cited": [alias["ev_imp"]]},
        _bundle(), r)
    assert ok["citations_valid"] and ok["entities_grounded"] and not ok["uncited"]

    bad = check_claim_deterministic(
        {"text": "It uses T1486 to encrypt files and calls VirtualAllocEx [E99].", "cited": ["E99"]},
        _bundle(), r)
    assert not bad["citations_valid"]
    assert "T1486" in bad["attack_not_observed"]
    assert "VirtualAllocEx" in bad["ungrounded_entities"]


def test_uncited_claim_flagged():
    r = render_evidence(_bundle(), mode="provenance")
    c = check_claim_deterministic({"text": "This is definitely ransomware.", "cited": []}, _bundle(), r)
    assert c["uncited"]


class _Fake:
    name, model = "fake", "fake"

    def __init__(self, label):
        self.label = label

    def generate(self, system, prompt, **kw):
        return GenResult(text=json.dumps({"label": self.label, "reason": "x"}),
                         provider="fake", model="fake")


def test_judge_claim_parses_label_and_fails_closed():
    r = render_evidence(_bundle(), mode="provenance")
    claim = {"text": "It connects to a URL [E1].", "cited": ["E1"]}
    assert judge_claim(claim, _bundle(), r, _Fake("SUPPORTED"))["label"] == "SUPPORTED"
    assert judge_claim(claim, _bundle(), r, _Fake("banana"))["label"] == "UNPARSEABLE"


def test_verify_narrative_summary():
    out = verify_narrative("It connects to a URL [E1]. It is ransomware.", _bundle(),
                           _Fake("NOT_SUPPORTED"))
    assert out["n_claims"] == 2
    assert out["summary"]["uncited"] == 1


def test_annotation_roundtrip(tmp_path):
    rows = [{"claim_id": "c1", "sha256": "e" * 64, "claim": "x", "evidence": "y",
             "judge_label": "SUPPORTED", "deterministic_flags": ""}]
    p = tmp_path / "ann.csv"
    export_annotation_csv(rows, p)
    data = list(csv.DictReader(open(p, encoding="utf-8")))
    data[0]["human_label"] = "SUPPORTED"
    with open(p, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(data[0]))
        w.writeheader()
        w.writerows(data)
    res = import_annotations(p)
    assert res["n"] == 1 and res["agreement"] == 1.0


def test_claims_summary_rates():
    from malagent.judge.analysis import claims_summary
    rec = {"claims": [
        {"deterministic": {"uncited": True, "citations_valid": True, "entities_grounded": True,
                           "attack_not_observed": []}, "judge": {"label": "NOT_SUPPORTED"}},
        {"deterministic": {"uncited": False, "citations_valid": True, "entities_grounded": False,
                           "attack_not_observed": ["T1486"]}, "judge": {"label": "SUPPORTED"}}]}
    s = claims_summary([rec])
    assert s["uncited_rate"] == 0.5 and s["judge_unsupported_rate"] == 0.5
    assert s["attack_not_observed_rate"] == 0.5
