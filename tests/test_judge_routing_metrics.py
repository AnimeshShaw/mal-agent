"""Routing (which samples are 'hard' and go to the judge), the evaluation
metrics, and the adversarial bundle transforms."""
from __future__ import annotations
import math

from malagent.judge.adversarial import ATTACKS, apply_attack
from malagent.judge.metrics import (aurc, bootstrap_ci, cohen_kappa, confusion, ece, fleiss_kappa,
                                    normalize_verdict)
from malagent.judge.routing import hybrid_verdict, route


def _b(fmt="pe", score=0.9, decisive=0.9, cats=(), signed=False, simple="malicious"):
    return {"sha256": "a" * 64, "format": fmt, "label": "malicious",
            "ember": {"score": score, "decisive": decisive},
            "gate": {"categories": list(cats), "signed": signed, "required": 4 if signed else 3},
            "baselines": {"simple": {"verdict": simple, "confidence": 0.9}},
            "evidence": [{"id": "e1", "locator": "strings:sample", "tool": "strings",
                          "excerpt": "hello world", "provenance": "sample_text"}],
            "findings": [], "tools": []}


# ---------------- routing
def test_confident_pe_is_not_routed():
    r = route(_b(decisive=0.99))
    assert not r.routed and r.reasons == []


def test_non_pe_is_routed_as_ood():
    r = route(_b(fmt="script_js", decisive=None, simple="undetermined"))
    assert r.routed and "ember_ood" in r.reasons


def test_gray_zone_is_routed():
    assert "ember_gray" in route(_b(decisive=0.12)).reasons


def test_ember_benign_but_gate_corroborated_is_conflict():
    r = route(_b(decisive=0.01, cats=("persistence", "communication", "anti-analysis"),
                 simple="benign"))
    assert "ember_gate_conflict" in r.reasons


def test_ember_malicious_but_signed_with_no_categories_is_conflict():
    r = route(_b(decisive=0.95, signed=True))
    assert "ember_gate_conflict" in r.reasons


def test_hybrid_uses_judge_only_on_routed():
    assert hybrid_verdict(_b(decisive=0.99), "benign") == "malicious"
    ood = _b(fmt="lnk", decisive=None, simple="undetermined")
    assert hybrid_verdict(ood, "malicious") == "malicious"
    assert hybrid_verdict(ood, "abstain") == "undetermined"
    assert hybrid_verdict(ood, None) == "undetermined"


# ---------------- metrics
def test_normalize_verdict():
    assert normalize_verdict("suspicious") == "malicious"
    assert normalize_verdict("abstain") == "undetermined"
    assert normalize_verdict(None) == "undetermined"


def test_confusion_strict_recall_and_coverage():
    pairs = [("malicious", "malicious"), ("malicious", "undetermined"), ("benign", "benign"),
             ("benign", "malicious")]
    c = confusion(pairs)
    assert (c["tp"], c["fp"], c["tn"], c["fn"]) == (1, 1, 1, 0)
    assert c["recall"] == 0.5          # abstention on malware counts as a miss
    assert c["coverage"] == 0.75
    assert c["fpr"] == 0.5


def test_cohen_kappa_perfect_and_chance():
    assert cohen_kappa(["a", "b", "a", "b"], ["a", "b", "a", "b"]) == 1.0
    assert abs(cohen_kappa(["a", "a", "b", "b"], ["a", "b", "a", "b"])) < 1e-9


def test_fleiss_kappa_perfect_agreement():
    assert fleiss_kappa([["m", "m", "m"], ["b", "b", "b"], ["m", "m", "m"]]) == 1.0


def test_ece_perfectly_calibrated_is_zero():
    assert ece([0.9] * 10, [True] * 9 + [False], bins=10) < 1e-9


def test_aurc_perfect_ranking_is_lower():
    good = aurc([0.9, 0.8, 0.2], [True, True, False])
    bad = aurc([0.2, 0.8, 0.9], [True, True, False])
    assert good < bad


def test_bootstrap_ci_contains_point():
    vals = [1, 0, 1, 1, 0, 1, 1, 1]
    lo, hi = bootstrap_ci(vals, lambda xs: sum(xs) / len(xs), n=200, seed=1)
    assert lo <= 0.75 <= hi


# ---------------- adversarial
def test_every_attack_adds_only_sample_text():
    b = _b()
    for name in ATTACKS:
        adv = apply_attack(b, name)
        new = [e for e in adv["evidence"] if e not in b["evidence"]]
        assert new and all(e["provenance"] == "sample_text" for e in new), name
        assert adv["baselines"] == b["baselines"] and adv["gate"] == b["gate"]
        assert b["evidence"][0]["excerpt"] == "hello world"  # original untouched


def test_fake_tool_output_attack_mimics_tool_evidence():
    adv = apply_attack(_b(), "fake_tool_output")
    text = "\n".join(e["excerpt"] for e in adv["evidence"])
    assert "authenticode" in text.lower() and "ember" in text.lower()
