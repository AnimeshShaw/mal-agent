"""End-to-end skeleton test on a SAFE synthetic binary (no model, no cloud)."""
import struct
from pathlib import Path
from malagent.pipeline import _maybe_router, analyze
from malagent.contracts import AnalysisState, EgressPolicy, Provenance, Sample, StepBudget


def _make_fake_pe(tmp: Path) -> str:
    # Minimal benign 'MZ' file containing suspicious strings + a fake IP/URL so the
    # deterministic triage has something to find. NOT executable malware.
    body = (b"MZ" + b"\x00" * 64 +
            b"This program cannot be run in DOS mode.\n" +
            b"powershell -enc ZQBjAGgAbwo=\n" +
            b"http://malicious.example.top/payload\n" +
            b"203.0.113.45\n" +
            b"CreateRemoteThread VirtualAlloc WriteProcessMemory\n" +
            b"\x00" * 256)
    p = tmp / "fake_sample.bin"
    p.write_bytes(body)
    return str(p)


def test_end_to_end(tmp_path):
    path = _make_fake_pe(tmp_path)
    state, verdict, report_md, report_txt, audit = analyze(
        path, provenance=Provenance(source="dataset", ticket_id="TEST-1"),
        enable_models=False)

    # spine produced a verdict object
    assert verdict.sample_sha256
    assert verdict.verdict in ("malicious", "suspicious", "benign", "undetermined")
    # triage found IOCs from the strings
    assert any(i.type == "url" for i in verdict.iocs)
    # honest reporting: dynamic was skipped -> unresolved is populated
    assert any("Dynamic detonation not run" in u for u in verdict.unresolved)
    # audit chain is intact and non-trivial
    assert audit.verify() is True
    assert len(audit.records) >= 5
    # report mentions the "could NOT determine" section
    assert "could NOT determine" in report_md
    # M4: grounded suspicious-string evidence synthesizes a YARA rule, surfaced in the report
    assert verdict.yara_rules
    assert "YARA" in report_md
    # M0: the mandatory txt report is always produced, unabridged
    assert "MAL-AGENT DETAILED ANALYSIS REPORT" in report_txt
    assert "APPENDIX A" in report_txt
    assert "END OF REPORT" in report_txt


def _synthetic_state(allow_cloud: bool) -> AnalysisState:
    sample = Sample(sha256="a" * 64, md5="b" * 32, path="/tmp/x.malz",
                    file_type="PE", size=10, provenance=Provenance())
    return AnalysisState(run_id="r1", sample=sample,
                         policy=EgressPolicy(allow_cloud=allow_cloud), budget=StepBudget())


def test_no_cloud_policy_means_no_escalation_provider_at_all():
    """Real bug, live-verified: --no-cloud only ever set policy.allow_cloud
    -- _maybe_router() built a real escalation provider regardless, and
    ModelRouter.analyze() checks `self.escalation is not None` BEFORE
    consulting the policy, so a triggered escalation still took the
    cloud-or-fail-closed branch and never fell back to the already-
    configured local provider. A user who explicitly passes --no-cloud
    (reasonably expecting pure local/offline operation) got the exact
    same degraded 'local model down and cloud egress blocked' result as
    someone with no cloud credentials at all, on every case that would
    otherwise escalate. Fixed by only constructing the escalation
    provider when policy.allow_cloud is True."""
    state = _synthetic_state(allow_cloud=False)
    router = _maybe_router(state, audit=None, local_name="ollama", local_model="qwen2.5-coder:7b",
                           escalation_name="anthropic", escalation_model="claude-sonnet-4-6",
                           enable_models=True)
    assert router is not None
    assert router.escalation is None


def test_cloud_allowed_policy_still_builds_escalation_provider():
    """Baseline: normal behavior (cloud allowed by policy) must be
    unaffected -- an escalation provider should still be constructed so
    real escalation can work when the operator wants it."""
    state = _synthetic_state(allow_cloud=True)
    router = _maybe_router(state, audit=None, local_name="ollama", local_model="qwen2.5-coder:7b",
                           escalation_name="anthropic", escalation_model="claude-sonnet-4-6",
                           enable_models=True)
    assert router is not None
    assert router.escalation is not None
