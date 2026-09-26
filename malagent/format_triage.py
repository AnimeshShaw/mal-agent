"""Format-aware static triage for non-PE lures: scripts (JS/VBS/PS1/BAT/
HTA), Windows shortcuts (LNK), Office/RTF documents and PDFs.

capa, pefile, Ghidra and EMBER all target executables; the lures real
campaigns deliver first (MalwareBazaar's recent feed is full of .lnk, .js,
.one, .iso, macro documents) produced almost no deterministic evidence
before this module, so neither the corroboration gate nor an LLM
adjudicator had anything to reason over for them.

Each indicator maps to one corroboration category via its locator
(`<tool>:indicator:<category>:<name>`), reusing the gate's category
vocabulary (execution / communication / anti-analysis / persistence /
load-code / exploitation). Text copied out of the sample itself -- script
bodies, macro source, LNK command lines, URLs -- is emitted under
`*:excerpt` / `*:source` / `*:arguments` / `*:uri` locators, which the
evidence-bundle layer marks as attacker-controlled (provenance
'sample_text') so a judge can never cite it as tool-derived support."""
from __future__ import annotations
import io
import re
from typing import Optional

from .contracts import AnalysisState, EvidenceRecord, Finding, StageResult
from .tools import _artifact, _id

_EXCERPT_CHARS = 2000


# ---------------------------------------------------------------- detection
_OLE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
_LNK = b"L\x00\x00\x00\x01\x14\x02\x00"
_ONENOTE = bytes.fromhex("e4525c7b8cd8a74daeb15378d02996d3")


def _is_texty(data: bytes) -> bool:
    head = data[:4096]
    if not head:
        return False
    if head.startswith((b"\xff\xfe", b"\xfe\xff")):  # UTF-16 text (common for .ps1/.vbs)
        return True
    if head.count(b"\x00") > len(head) // 20:
        return False
    printable = sum(1 for b in head if b in (9, 10, 13) or 32 <= b < 127 or b >= 0x80)
    return printable / len(head) > 0.95


def _decode_text(data: bytes) -> str:
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", errors="replace")
    return data.decode("utf-8", errors="replace")


_SCRIPT_HINTS = [
    ("script_hta", re.compile(r"<\s*hta:application", re.I)),
    ("script_ps1", re.compile(r"\$[A-Za-z_]\w*\s*=|Invoke-Expression|New-Object\s|Get-\w+|"
                              r"\[System\.|Set-ExecutionPolicy|param\s*\(", re.I)),
    ("script_bat", re.compile(r"^\s*@?echo\s+off|^\s*set\s+\w+=|%~dp0|^\s*goto\s+\w", re.I | re.M)),
    ("script_vbs", re.compile(r"CreateObject\s*\(|\bDim\s+\w|\bEnd\s+Sub\b|\bWScript\.Echo\b|"
                              r"\bSet\s+\w+\s*=", re.I)),
    ("script_js", re.compile(r"\bvar\s+\w+\s*=|\bfunction\s*\w*\s*\(|ActiveXObject|\bconst\s+\w|"
                             r"\blet\s+\w|=>|require\s*\(", re.I)),
]


def detect_format(data: bytes) -> str:
    if data[:2] == b"MZ":
        return "pe"
    if data[:4] == b"\x7fELF":
        return "elf"
    if data[:4] in (b"\xfe\xed\xfa\xce", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
        return "macho"
    if data[:5] == b"%PDF-" or b"%PDF-" in data[:1024]:
        return "pdf"
    if data[:5] == b"{\\rtf" or data[:4] == b"{\\rt":
        return "rtf"
    if data[:8] == _OLE:
        return "ole"
    if data[:8] == _LNK:
        return "lnk"
    if data[:16] == _ONENOTE:
        return "onenote"
    if data[:4] == b"PK\x03\x04":
        return "ooxml" if b"[Content_Types].xml" in data[:65536] else "zip"
    if len(data) > 0x8006 and data[0x8001:0x8006] == b"CD001":
        return "iso"
    if data[:4] == b"Rar!" or data[:6] == b"7z\xbc\xaf\x27\x1c" or data[:2] == b"\x1f\x8b":
        return "archive"
    if _is_texty(data):
        text = _decode_text(data[:65536])
        for fmt, rx in _SCRIPT_HINTS:
            if rx.search(text):
                return fmt
        return "text"
    return "unknown"


def _read(state: AnalysisState) -> bytes:
    with open(state.sample.path, "rb") as fh:
        return fh.read()


def _indicator(input_ref, art, tool, category, name, excerpt, claim, severity="medium"):
    ev = EvidenceRecord(evidence_id=_id("ev", input_ref, tool, category, name),
                        artifact_id=art.artifact_id,
                        locator=f"{tool}:indicator:{category}:{name}",
                        excerpt=excerpt[:300], trust="tool")
    f = Finding(finding_id=_id("f", input_ref, tool, category, name), claim=claim,
                category="capability", severity=severity, confidence=0.6,
                evidence=[ev.evidence_id], source_stage="triage")
    return ev, f


def _excerpt(input_ref, art, locator, text) -> EvidenceRecord:
    return EvidenceRecord(evidence_id=_id("ev", input_ref, locator),
                          artifact_id=art.artifact_id, locator=locator,
                          excerpt=text[:_EXCERPT_CHARS], trust="sample")


# ---------------------------------------------------------------- tools
class FormatTool:
    """Content-based file-format identification (never the extension)."""
    name = "format"

    def run(self, state: AnalysisState) -> StageResult:
        data = _read(state)
        fmt = detect_format(data)
        art = _artifact(self.name, state.sample.sha256, fmt.encode())
        ev = EvidenceRecord(evidence_id=_id("ev", state.sample.sha256, "format"),
                            artifact_id=art.artifact_id, locator="format:type",
                            excerpt=fmt, trust="tool")
        return StageResult(stage="triage", status="ok", artifacts=[art], evidence=[ev],
                           notes=f"format={fmt}")


# (category, name, regex, severity) -- deliberately coarse, readable rules.
_SCRIPT_RULES = [
    ("communication", "http_url", r"https?://[^\s'\"<>]{4,}", "low"),
    ("communication", "downloader_api",
     r"Net\.WebClient|DownloadString|DownloadFile|Invoke-WebRequest|\biwr\b|Start-BitsTransfer|"
     r"bitsadmin|MSXML2\.XMLHTTP|WinHttp\.WinHttpRequest|\bcurl(\.exe)?\s+-|certutil(\.exe)?\s+-urlcache",
     "medium"),
    ("execution", "shell_exec",
     r"WScript\.Shell|Shell\.Application|\.ShellExecute|Invoke-Expression|\bIEX\b|Start-Process|"
     r"\bcmd(\.exe)?\s+/[ck]\b|powershell(\.exe)?\s+[^\n]{0,40}-(e|en|enc|encodedcommand)\b|"
     r"\bmshta\b|\brundll32\b|\bregsvr32\b|\bwscript\b|\bcscript\b|\beval\s*\(|new\s+ActiveXObject",
     "medium"),
    ("anti-analysis", "obfuscation",
     r"FromBase64String|\batob\s*\(|String\.fromCharCode|charCodeAt|\bChrW?\s*\(\s*\d+\s*\)(?:\s*[&+]\s*ChrW?\s*\(\s*\d+\s*\)){5,}|"
     r"StrReverse|-join\s*\(|\[char\]\s*\d+|[A-Za-z0-9+/]{400,}={0,2}",
     "medium"),
    ("anti-analysis", "defense_tamper",
     r"Set-MpPreference|Add-MpPreference|DisableRealtimeMonitoring|AMSI|amsiInitFailed|"
     r"-WindowStyle\s+Hidden|-w\s+hidden|-ExecutionPolicy\s+Bypass|-ep\s+bypass",
     "medium"),
    ("persistence", "autorun",
     r"CurrentVersion\\Run|schtasks(\.exe)?\s+/create|Register-ScheduledTask|\\Start Menu\\Programs\\Startup|"
     r"New-Service|sc(\.exe)?\s+create",
     "medium"),
]
_SCRIPT_RX = [(c, n, re.compile(rx, re.I), sev) for c, n, rx, sev in _SCRIPT_RULES]


class ScriptTool:
    """Indicators + a verbatim excerpt for text-based scripts."""
    name = "script"

    def run(self, state: AnalysisState) -> StageResult:
        data = _read(state)
        fmt = detect_format(data)
        if not (fmt.startswith("script_") or fmt == "text"):
            return StageResult(stage="triage", status="skipped",
                               notes=f"not a text script (format={fmt})")
        text = _decode_text(data[:2_000_000])
        ref = state.sample.sha256
        art = _artifact(self.name, ref, data[:4096])
        evidence = [_excerpt(ref, art, "script:excerpt", text)]
        findings = []
        for cat, name, rx, sev in _SCRIPT_RX:
            m = rx.search(text)
            if not m:
                continue
            ev, f = _indicator(ref, art, "script", cat, name, m.group(0),
                               f"Script ({fmt}) contains a {name.replace('_', ' ')} pattern "
                               f"({cat}).", sev)
            evidence.append(ev)
            findings.append(f)
        longest = max((len(line) for line in text.splitlines()), default=0)
        if longest > 3000:
            ev, f = _indicator(ref, art, "script", "anti-analysis", "long_line", f"{longest} chars",
                               f"Script has a {longest}-character line (packed/obfuscated code).")
            evidence.append(ev)
            findings.append(f)
        return StageResult(stage="triage", status="ok", findings=findings, artifacts=[art],
                           evidence=evidence, notes=f"{fmt}; {len(findings)} indicator(s)")


_PDF_KEYS = {"/JavaScript": "medium", "/JS": "medium", "/OpenAction": "low", "/AA": "low",
             "/Launch": "medium", "/EmbeddedFile": "medium", "/URI": "low", "/SubmitForm": "low",
             "/RichMedia": "medium", "/XFA": "low", "/ObjStm": "low", "/Encrypt": "low"}
_PDF_CATEGORY = {"/JavaScript": "execution", "/JS": "execution", "/Launch": "execution",
                 "/EmbeddedFile": "load-code", "/RichMedia": "exploitation"}


class PdfTool:
    """pdfid-style keyword counting, plus URIs as sample text."""
    name = "pdf"

    def run(self, state: AnalysisState) -> StageResult:
        data = _read(state)
        if detect_format(data) != "pdf":
            return StageResult(stage="triage", status="skipped", notes="not a PDF")
        ref = state.sample.sha256
        art = _artifact(self.name, ref, data[:4096])
        evidence, findings = [], []
        for key, sev in _PDF_KEYS.items():
            n = len(re.findall(re.escape(key.encode()) + rb"(?![A-Za-z])", data))
            if not n:
                continue
            ev = EvidenceRecord(evidence_id=_id("ev", ref, "pdf", key), artifact_id=art.artifact_id,
                                locator=f"pdf:{key}", excerpt=f"{key} x{n}", trust="tool")
            evidence.append(ev)
            cat = _PDF_CATEGORY.get(key)
            if cat and sev == "medium":
                iev, f = _indicator(ref, art, "pdf", cat, key.strip("/"), f"{key} x{n}",
                                    f"PDF contains {key} ({n} occurrence(s)) -- active content.")
                evidence.append(iev)
                findings.append(f)
        if (b"/OpenAction" in data or b"/AA" in data) and (b"/JavaScript" in data or b"/Launch" in data):
            iev, f = _indicator(ref, art, "pdf", "execution", "auto_action", "OpenAction/AA + JS/Launch",
                                "PDF runs JavaScript or a launch action automatically on open.")
            evidence.append(iev)
            findings.append(f)
        uris = sorted({u.decode("latin1") for u in re.findall(rb"/URI\s*\(([^)]{4,300})\)", data)})
        if uris:
            evidence.append(_excerpt(ref, art, "pdf:uri", "\n".join(uris[:20])))
        return StageResult(stage="triage", status="ok", findings=findings, artifacts=[art],
                           evidence=evidence, notes=f"{len(evidence)} pdf keyword record(s)")


_LNK_SUSPICIOUS = re.compile(
    r"powershell|pwsh|cmd(\.exe)?\s*/[ck]|mshta|wscript|cscript|rundll32|regsvr32|msiexec|"
    r"curl|bitsadmin|certutil|-enc|frombase64|https?://|\\\\[\w.-]+@?\d*\\", re.I)


class LnkTool:
    """Windows shortcut target + command line (the whole attack in an LNK lure)."""
    name = "lnk"

    def run(self, state: AnalysisState) -> StageResult:
        data = _read(state)
        if detect_format(data) != "lnk":
            return StageResult(stage="triage", status="skipped", notes="not a Windows shortcut")
        try:
            import LnkParse3
            info = LnkParse3.lnk_file(io.BytesIO(data)).get_json()
        except Exception as e:  # LnkParse3 missing or malformed shortcut
            return StageResult(stage="triage", status="error",
                               unresolved=[f"LNK parsing failed: {type(e).__name__}: {e}"])
        d = info.get("data") or {}
        li = info.get("link_info") or {}
        target = li.get("local_base_path") or d.get("relative_path") or ""
        args = d.get("command_line_arguments") or ""
        ref = state.sample.sha256
        art = _artifact(self.name, ref, data[:4096])
        evidence = [_excerpt(ref, art, "lnk:target", str(target)),
                    _excerpt(ref, art, "lnk:arguments", str(args))]
        findings = []
        cmdline = f"{target} {args}"
        m = _LNK_SUSPICIOUS.search(cmdline)
        if m:
            ev, f = _indicator(ref, art, "lnk", "execution", "suspicious_command", m.group(0),
                               f"Shortcut launches a script host / LOLBin / download command "
                               f"('{m.group(0)}').")
            evidence.append(ev)
            findings.append(f)
        if len(args) > 250:
            ev, f = _indicator(ref, art, "lnk", "anti-analysis", "long_arguments", f"{len(args)} chars",
                               f"Shortcut arguments are {len(args)} characters long (padding "
                               f"hides the command line from the Properties dialog).")
            evidence.append(ev)
            findings.append(f)
        return StageResult(stage="triage", status="ok", findings=findings, artifacts=[art],
                           evidence=evidence, notes=f"target={str(target)[:80]}")


_VBA_CATEGORY = {"AutoExec": "execution", "Suspicious": "execution", "IOC": "communication",
                 "Hex String": "anti-analysis", "Base64 String": "anti-analysis",
                 "Dridex String": "anti-analysis", "VBA string": "anti-analysis"}


class OfficeMacroTool:
    """olevba over OLE/OOXML/RTF documents: macros, auto-exec triggers,
    suspicious keywords; plus remote-template and embedded-object checks."""
    name = "office"

    def run(self, state: AnalysisState) -> StageResult:
        data = _read(state)
        fmt = detect_format(data)
        if fmt not in ("ole", "ooxml", "rtf"):
            return StageResult(stage="triage", status="skipped", notes=f"not an Office/RTF document ({fmt})")
        ref = state.sample.sha256
        art = _artifact(self.name, ref, data[:4096])
        evidence, findings, unresolved = [], [], []
        try:
            from oletools.olevba import VBA_Parser
        except Exception:
            return StageResult(stage="triage", status="skipped",
                               unresolved=["Office macro analysis skipped: 'oletools' not installed."])
        try:
            vp = VBA_Parser("sample", data=data)
            try:
                if vp.detect_vba_macros():
                    code = "\n".join(c for (_, _, _, c) in vp.extract_all_macros() if c)
                    evidence.append(_excerpt(ref, art, "office:source", code))
                    seen = set()
                    for kw_type, keyword, desc in vp.analyze_macros():
                        cat = _VBA_CATEGORY.get(kw_type)
                        key = (kw_type, keyword)
                        if not cat or key in seen:
                            continue
                        seen.add(key)
                        sev = "medium" if kw_type in ("AutoExec", "Suspicious") else "low"
                        ev, f = _indicator(ref, art, "office", cat, f"{kw_type}:{keyword}"[:80],
                                           f"{keyword}: {desc}",
                                           f"VBA macro {kw_type.lower()} keyword '{keyword}': {desc}", sev)
                        evidence.append(ev)
                        findings.append(f)
            finally:
                vp.close()
        except Exception as e:
            unresolved.append(f"olevba failed: {type(e).__name__}: {e}")
        if fmt == "ooxml":
            try:
                import zipfile
                with zipfile.ZipFile(io.BytesIO(data)) as zf:
                    rels = b"".join(zf.read(n) for n in zf.namelist() if n.endswith(".rels"))
                ext = re.findall(rb'Target="(https?://[^"]{4,300})"[^>]*TargetMode="External"', rels)
                if re.search(rb'attachedTemplate[^>]*TargetMode="External"|TargetMode="External"[^>]*attachedTemplate',
                             rels):
                    ev, f = _indicator(ref, art, "office", "communication", "remote_template",
                                       (ext[0].decode("latin1") if ext else "external template"),
                                       "Document loads a remote template (template injection).")
                    evidence.append(ev)
                    findings.append(f)
            except Exception:
                pass
        if fmt == "rtf":
            if re.search(rb"\\objdata|\\objupdate", data, re.I):
                ev, f = _indicator(ref, art, "office", "load-code", "rtf_embedded_object", "\\objdata",
                                   "RTF embeds an OLE object (\\objdata/\\objupdate).")
                evidence.append(ev)
                findings.append(f)
            if re.search(rb"equation\.3|0002ce02-0000-0000-c000-000000000046", data, re.I):
                ev, f = _indicator(ref, art, "office", "exploitation", "equation_editor", "Equation.3",
                                   "RTF references Equation Editor (CVE-2017-11882 family).", "high")
                evidence.append(ev)
                findings.append(f)
        return StageResult(stage="triage", status="ok", findings=findings, artifacts=[art],
                           evidence=evidence, unresolved=unresolved,
                           notes=f"{fmt}; {len(findings)} indicator(s)")
