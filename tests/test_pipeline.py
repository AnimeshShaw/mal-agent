"""End-to-end skeleton test on a SAFE synthetic binary (no model, no cloud)."""
import struct
from pathlib import Path
from malagent.pipeline import analyze
from malagent.contracts import Provenance


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
