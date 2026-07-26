"""Prompt/response logging separate from the audit hash (docs/TODO.md M1).
Before this, ONLY a truncated SHA256 hash of the prompt was ever recorded
(ModelCall.prompt_hash / audit log) -- the actual prompt and response text
were never persisted anywhere, making prompt-quality iteration impossible
without re-running live. Opt-in via MAL_AGENT_PROMPT_LOG_PATH (unset by
default): the logged content includes untrusted, attacker-controllable
text extracted from the sample, so this must never be on by default."""
from __future__ import annotations
import json
from malagent.contracts import AnalysisState, EgressPolicy, Provenance, Sample, StepBudget
from malagent.models import ModelRouter


def _sample():
    return Sample(sha256="a" * 64, md5="b" * 32, path="/tmp/x.malz",
                  file_type="PE", size=10, provenance=Provenance())


def _state(policy=None):
    return AnalysisState(run_id="r1", sample=_sample(),
                         policy=policy or EgressPolicy(), budget=StepBudget())


class _FakeProvider:
    def __init__(self, name="fake", model="fake-model", response="the response", raises=None):
        self.name = name
        self.model = model
        self.location = "local"
        self._response = response
        self._raises = raises

    def complete(self, system, prompt):
        if self._raises:
            raise self._raises
        return self._response


def test_no_log_file_written_when_env_var_unset(monkeypatch, tmp_path):
    monkeypatch.delenv("MAL_AGENT_PROMPT_LOG_PATH", raising=False)
    router = ModelRouter(_state(), local=_FakeProvider())
    router.analyze(system="sys", untrusted_label="lbl", untrusted_text="hello")
    assert not (tmp_path / "log.jsonl").exists()


def test_successful_call_logged_with_full_prompt_and_response(monkeypatch, tmp_path):
    log_path = tmp_path / "log.jsonl"
    monkeypatch.setenv("MAL_AGENT_PROMPT_LOG_PATH", str(log_path))
    router = ModelRouter(_state(), local=_FakeProvider(response="the real answer"))
    router.analyze(system="You are an analyst", untrusted_label="evidence",
                   untrusted_text="suspicious string xyz")
    lines = log_path.read_text().splitlines()
    assert len(lines) == 1
    entry = json.loads(lines[0])
    assert entry["response"] == "the real answer"
    assert "suspicious string xyz" in entry["prompt"]
    assert entry["system"] == "You are an analyst"
    assert entry["provider"] == "fake"
    assert entry["location"] == "local"
    assert entry["error"] is None


def test_provider_error_logged_with_error_not_response(monkeypatch, tmp_path):
    log_path = tmp_path / "log.jsonl"
    monkeypatch.setenv("MAL_AGENT_PROMPT_LOG_PATH", str(log_path))
    router = ModelRouter(_state(), local=_FakeProvider(raises=RuntimeError("model down")))
    resp = router.analyze(system="sys", untrusted_label="lbl", untrusted_text="hello")
    assert resp is None
    entry = json.loads(log_path.read_text().splitlines()[0])
    assert entry["response"] is None
    assert "model down" in entry["error"]


def test_escalation_blocked_logged_before_any_provider_call(monkeypatch, tmp_path):
    log_path = tmp_path / "log.jsonl"
    monkeypatch.setenv("MAL_AGENT_PROMPT_LOG_PATH", str(log_path))
    policy = EgressPolicy(allow_cloud=False)
    router = ModelRouter(_state(policy=policy), local=_FakeProvider(),
                         escalation=_FakeProvider(name="cloud-provider"))
    resp = router.analyze(system="sys", untrusted_label="lbl", untrusted_text="hello",
                          escalate=True)
    assert resp is None
    entry = json.loads(log_path.read_text().splitlines()[0])
    assert entry["response"] is None
    assert entry["error"] is not None
    assert entry["provider"] == "cloud-provider"


def test_multiple_calls_append_multiple_lines(monkeypatch, tmp_path):
    log_path = tmp_path / "log.jsonl"
    monkeypatch.setenv("MAL_AGENT_PROMPT_LOG_PATH", str(log_path))
    router = ModelRouter(_state(), local=_FakeProvider())
    router.analyze(system="sys", untrusted_label="lbl", untrusted_text="one")
    router.analyze(system="sys", untrusted_label="lbl", untrusted_text="two")
    lines = log_path.read_text().splitlines()
    assert len(lines) == 2


def test_logging_failure_never_breaks_analysis(monkeypatch, tmp_path):
    """A logging misconfiguration (e.g. an unwritable path) must never
    take down real analysis -- this is a debugging aid, not a critical
    path."""
    monkeypatch.setenv("MAL_AGENT_PROMPT_LOG_PATH", str(tmp_path / "no" / "such" / "dir" / "log.jsonl"))
    router = ModelRouter(_state(), local=_FakeProvider(response="ok"))
    resp = router.analyze(system="sys", untrusted_label="lbl", untrusted_text="hello")
    assert resp is not None
    assert resp.text == "ok"


def test_prompt_hash_still_recorded_on_model_call_unchanged():
    """This is an ADDITIONAL logging mechanism, not a replacement -- the
    existing ModelCall.prompt_hash audit trail behavior must be unchanged."""
    state = _state()
    router = ModelRouter(state, local=_FakeProvider())
    router.analyze(system="sys", untrusted_label="lbl", untrusted_text="hello")
    assert len(state.model_calls) == 1
    assert len(state.model_calls[0].prompt_hash) == 16
