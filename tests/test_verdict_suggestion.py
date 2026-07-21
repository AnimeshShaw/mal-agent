"""Non-binding LLM verdict-suggestion harness (research artifact only).

This is deliberately NOT part of the scoring pipeline -- it asks an LLM to
look at all gathered evidence and holistically guess malicious/suspicious/
benign/undetermined, purely so its suggestion can be measured against
ground truth and compared to the deterministic score. Nothing here ever
writes to reporter.py or influences AnalysisState's actual verdict --
the same invariant test_llm_agents_never_score.py protects for the live
pipeline holds here by construction: this module has no path into
build_verdict() at all."""
from __future__ import annotations
from malagent.contracts import AnalysisState, Finding, Provenance, Sample, Verdict
from malagent.evaluation import LabeledSample
from malagent import verdict_suggestion
from malagent.verdict_suggestion import evaluate_llm_suggestions, suggest_verdict


def _sample():
    return Sample(sha256="a" * 64, md5="b" * 32, path="/tmp/x.malz",
                  file_type="PE", size=10, provenance=Provenance())


def _state_with_findings():
    state = AnalysisState(run_id="r1", sample=_sample())
    state.findings = [Finding(finding_id="f1", claim="Capability detected: connect to URL",
                              category="capability", severity="medium", confidence=0.7,
                              evidence=["ev1"], grounded=True)]
    return state


def _verdict(v="suspicious", conf=0.5):
    return Verdict(sample_sha256="a" * 64, verdict=v, confidence=conf)


class _FakeResponse:
    def __init__(self, text):
        self.text = text
        self.provider = "fake"
        self.location = "local"


class _FakeRouter:
    def __init__(self, response_text=None, always_none=False):
        self.calls = []
        self._response_text = response_text
        self._always_none = always_none

    def analyze(self, *, system, untrusted_label, untrusted_text, escalate=False,
                artifact_class="derived"):
        self.calls.append({"label": untrusted_label, "text": untrusted_text})
        return None if self._always_none else _FakeResponse(self._response_text)


# ---------- suggest_verdict ----------

def test_no_router_returns_none():
    assert suggest_verdict(_state_with_findings(), _verdict(), router=None) is None


def test_model_unavailable_returns_none():
    router = _FakeRouter(always_none=True)
    assert suggest_verdict(_state_with_findings(), _verdict(), router=router) is None


def test_well_formed_response_parsed_correctly():
    router = _FakeRouter(response_text=(
        "VERDICT: malicious\nREASONING: connects to a URL with no legitimate purpose evident."))
    result = suggest_verdict(_state_with_findings(), _verdict(), router=router)
    assert result.suggested_verdict == "malicious"
    assert "no legitimate purpose" in result.reasoning


def test_evidence_summary_sent_to_model_includes_findings():
    router = _FakeRouter(response_text="VERDICT: suspicious\nREASONING: x")
    suggest_verdict(_state_with_findings(), _verdict(), router=router)
    assert "connect to URL" in router.calls[0]["text"]


def test_malformed_response_degrades_to_undetermined_not_a_crash():
    router = _FakeRouter(response_text="I think this file seems kind of sketchy honestly.")
    result = suggest_verdict(_state_with_findings(), _verdict(), router=router)
    assert result.suggested_verdict == "undetermined"


def test_invalid_verdict_word_degrades_to_undetermined():
    router = _FakeRouter(response_text="VERDICT: definitely-bad\nREASONING: vibes")
    result = suggest_verdict(_state_with_findings(), _verdict(), router=router)
    assert result.suggested_verdict == "undetermined"


# ---------- evaluate_llm_suggestions ----------

def _fake_analyze_factory(verdict_by_path):
    def _fake_analyze(path, **kwargs):
        state = AnalysisState(run_id="r", sample=Sample(
            sha256="a" * 64, md5="b" * 32, path=path, file_type="PE", size=1,
            provenance=Provenance()))
        v = Verdict(sample_sha256="a" * 64, verdict=verdict_by_path[path])
        return (state, v, "", "", None)
    return _fake_analyze


def test_evaluate_llm_suggestions_uses_llm_guess_not_deterministic_verdict():
    """The whole point: the confusion matrix here must reflect the LLM's
    suggestion, not the deterministic pipeline verdict returned by
    analyze_fn -- otherwise this harness wouldn't be measuring anything
    different from evaluate()."""
    samples = [LabeledSample(path="mal1", label="malicious")]
    # deterministic verdict says undetermined, but the LLM confidently
    # (and correctly) suggests malicious -- the report must reflect the LLM.
    fake_analyze = _fake_analyze_factory({"mal1": "undetermined"})
    router = _FakeRouter(response_text="VERDICT: malicious\nREASONING: x")
    report = evaluate_llm_suggestions(samples, router=router, analyze_fn=fake_analyze)
    assert report.tp == 1
    assert report.undetermined_malicious == 0


def test_evaluate_llm_suggestions_prints_both_verdicts_for_comparison(capsys):
    samples = [LabeledSample(path="mal1", label="malicious")]
    fake_analyze = _fake_analyze_factory({"mal1": "undetermined"})
    router = _FakeRouter(response_text="VERDICT: malicious\nREASONING: x")
    evaluate_llm_suggestions(samples, router=router, analyze_fn=fake_analyze)
    out = capsys.readouterr().out
    assert "deterministic=undetermined" in out
    assert "llm_suggests=malicious" in out


def test_evaluate_llm_suggestions_no_response_counts_as_undetermined():
    samples = [LabeledSample(path="ben1", label="benign")]
    fake_analyze = _fake_analyze_factory({"ben1": "benign"})
    router = _FakeRouter(always_none=True)
    report = evaluate_llm_suggestions(samples, router=router, analyze_fn=fake_analyze)
    assert report.undetermined_benign == 1
