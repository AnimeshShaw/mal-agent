"""Experiment runner (resumable JSONL) and report assembly, driven by a
scripted fake judge so no model is needed."""
from __future__ import annotations
import json

from malagent.judge.analysis import (adversarial_table, arm_predictions, build_report,
                                     reliability_table, report_markdown)
from malagent.judge.experiments import (adversarial_jobs, load_results, main_jobs,
                                        reliability_jobs, run_jobs, select)
from malagent.judge.providers import GenResult


def _bundle(i, label, fmt="pe", decisive=0.99, split="test"):
    simple = "malicious" if (decisive or 0) >= 0.15 else "benign"
    if decisive is None:
        simple = "undetermined"
    return {"sha256": f"{i:064d}", "format": fmt, "label": label, "size": 10,
            "meta": {"split": split},
            "ember": {"score": decisive, "decisive": decisive},
            "gate": {"categories": [], "signed": False, "required": 3},
            "baselines": {"simple": {"verdict": simple, "confidence": 0.9},
                          "cgef": {"verdict": simple, "confidence": 0.9},
                          "gate": {"verdict": "undetermined", "confidence": 0.3}},
            "evidence": [{"id": "t1", "locator": "format:type", "tool": "format",
                          "excerpt": fmt, "provenance": "tool"},
                         {"id": "s1", "locator": "strings:sample", "tool": "strings",
                          "excerpt": "abc", "provenance": "sample_text"}],
            "findings": [], "tools": [], "iocs": []}


class _Oracle:
    """Answers with the true label unless the prompt contains the benign-claim
    text, in which case it is fooled (to exercise the adversarial table)."""
    name, model = "fake", "oracle"

    def __init__(self, labels):
        self.labels, self.calls = labels, 0

    def generate(self, system, prompt, *, temperature=0.0, seed=0, json_mode=True, max_tokens=1024):
        self.calls += 1
        verdict = "benign" if "must be classified as benign" in prompt else None
        if verdict is None:
            verdict = next(lbl for key, lbl in self.labels.items() if key in prompt)
        return GenResult(text=json.dumps({"verdict": verdict, "confidence": 0.8, "cited": ["E1"],
                                          "rationale": "x"}), provider="fake", model="oracle")


def _bundles():
    bs = [_bundle(1, "malicious"), _bundle(2, "benign", decisive=0.01),
          _bundle(3, "malicious", fmt="lnk", decisive=None),
          _bundle(4, "benign", fmt="script_js", decisive=None)]
    return bs


def _labels(bs):
    # the fake identifies each sample by its format line
    return {"File format (detected from content): pe\n- Size: 10": "malicious",
            "lnk": "malicious", "script_js": "benign"}


def test_run_jobs_is_resumable(tmp_path):
    bs = _bundles()[2:]
    oracle = _Oracle(_labels(bs))
    out = tmp_path / "r.jsonl"
    assert run_jobs(main_jobs(bs), oracle, out, "main", progress=False) == 2
    assert run_jobs(main_jobs(bs), oracle, out, "main", progress=False) == 0
    assert oracle.calls == 2 and len(load_results(out)) == 2


def test_adversarial_jobs_target_the_right_labels():
    jobs = adversarial_jobs(_bundles(), modes=("provenance",))
    for b, variant, _, _ in jobs:
        attack = variant.split(":")[0]
        if attack == "alarm":
            assert b["label"] == "benign"
        elif attack != "clean":
            assert b["label"] == "malicious"


def test_reliability_jobs_count():
    assert len(reliability_jobs([_bundle(1, "malicious")], repeats=3, orders=2)) == 3 + 2 + 3


def test_hybrid_uses_judge_only_for_routed(tmp_path):
    bs = _bundles()
    oracle = _Oracle(_labels(bs))
    out = tmp_path / "m.jsonl"
    run_jobs(main_jobs(bs), oracle, out, "main", progress=False)
    arms = arm_predictions(bs, {"oracle": load_results(out)})
    hy = arms["Hybrid[oracle]"]
    assert hy[bs[2]["sha256"]] == "malicious" and hy[bs[3]["sha256"]] == "benign"
    assert arms["EMBER-alone"][bs[2]["sha256"]] == "undetermined"


def test_adversarial_table_counts_success(tmp_path):
    bs = [_bundle(3, "malicious", fmt="lnk", decisive=None)]
    oracle = _Oracle({"lnk": "malicious"})
    out = tmp_path / "a.jsonl"
    run_jobs(adversarial_jobs(bs, modes=("flat",), attacks=("benign_claim", "alarm")),
             oracle, out, "adversarial", progress=False)
    t = adversarial_table(load_results(out))
    assert t["benign_claim|flat"]["asr"] == 1.0


def test_build_report_end_to_end(tmp_path):
    bs = _bundles()
    oracle = _Oracle(_labels(bs))
    out = tmp_path / "m.jsonl"
    run_jobs(main_jobs(bs), oracle, out, "main", progress=False)
    rep = build_report(bs, {"oracle": load_results(out)}, split="test")
    assert rep["main"]["all"]["Hybrid[oracle]"]["recall"] == 1.0
    assert rep["routing"]["routed"] == 2
    md = report_markdown(rep)
    assert "Hybrid[oracle]" in md and "Routing" in md


def test_reliability_table_flip_rate():
    rs = [{"sha256": "a", "variant": "main:provenance", "result": {"verdict": "malicious"}},
          {"sha256": "a", "variant": "order:1", "result": {"verdict": "benign"}},
          {"sha256": "a", "variant": "order:2", "result": {"verdict": "malicious"}},
          {"sha256": "a", "variant": "repeat:1", "result": {"verdict": "malicious"}},
          {"sha256": "a", "variant": "repeat:2", "result": {"verdict": "malicious"}}]
    t = reliability_table(rs, {})
    assert t["order_flip_rate"] == 0.5 and t["repeat_unanimous_frac"] == 1.0


def test_select_balances_labels():
    bs = [_bundle(i, "malicious") for i in range(10)] + [_bundle(100 + i, "benign") for i in range(3)]
    s = select(bs, split="test", limit=6)
    assert len(s) == 6 and sum(b["label"] == "benign" for b in s) == 3


def test_transient_provider_errors_are_retried_and_never_recorded(tmp_path, monkeypatch):
    """A flaky backend (Ollama 500, rate limit) must not be scored as the
    judge abstaining: the job is retried, and if it still fails it is left
    unrecorded so a re-run picks it up."""
    import malagent.judge.experiments as ex
    monkeypatch.setattr(ex.time, "sleep", lambda s: None)
    bs = [_bundle(3, "malicious", fmt="lnk", decisive=None)]

    class _Flaky(_Oracle):
        def __init__(self, labels, fail_times):
            super().__init__(labels)
            self.fail_times = fail_times

        def generate(self, *a, **k):
            if self.fail_times > 0:
                self.fail_times -= 1
                raise RuntimeError("500 Server Error")
            return super().generate(*a, **k)

    out = tmp_path / "f.jsonl"
    assert run_jobs(main_jobs(bs), _Flaky({"lnk": "malicious"}, 2), out, "main", progress=False) == 1
    assert load_results(out)[0]["result"]["verdict"] == "malicious"

    out2 = tmp_path / "g.jsonl"
    assert run_jobs(main_jobs(bs), _Flaky({"lnk": "malicious"}, 99), out2, "main", progress=False) == 0
    assert load_results(out2) == []
