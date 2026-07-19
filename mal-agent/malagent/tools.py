"""Tool adapters. Lightweight, deterministic analyzers behind one uniform shape
(D3). Each returns a StageResult carrying findings + the raw artifacts and
evidence that ground them. Heavy/external tools (Ghidra, sandbox) get MCP later;
these in-process libs are called directly."""
from __future__ import annotations
import hashlib
import math
import os
import re
from typing import Optional
from .contracts import (AnalysisState, EvidenceRecord, Finding, IOC, RawArtifact,
                        StageResult, now)


def _id(prefix: str, *parts: str) -> str:
    h = hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]
    return f"{prefix}_{h}"


def _capa_command(sample_path: str) -> list[str]:
    """A plain `pip install flare-capa` does not bundle capa's rules or FLIRT
    signatures -- they must be supplied explicitly. CAPA_RULES_PATH /
    CAPA_SIGS_PATH let an operator point at a downloaded capa-rules checkout
    (and optional sigs) without any code change; omitted when unset, which
    keeps capa's own default-path behavior (and its own honest failure if
    nothing is configured)."""
    cmd = ["capa", "-j"]
    rules = os.getenv("CAPA_RULES_PATH")
    if rules:
        cmd += ["-r", rules]
    sigs = os.getenv("CAPA_SIGS_PATH")
    if sigs:
        cmd += ["-s", sigs]
    cmd.append(sample_path)
    return cmd


def _artifact(tool: str, input_ref: str, content: bytes) -> RawArtifact:
    aid = hashlib.sha256(content).hexdigest()[:24]
    return RawArtifact(artifact_id=aid, tool=tool, input_ref=input_ref,
                       produced_at=now(), storage_ref=f"artifact://{aid}")


# ---------- strings + entropy + IOC extraction (no external deps) ----------
_IOC_RX = {
    "ip": re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "url": re.compile(rb"https?://[\w./%?=&:+-]{4,}", re.I),
    "domain": re.compile(rb"\b(?:[a-z0-9-]+\.)+(?:com|net|org|info|biz|ru|cn|io|xyz|top)\b", re.I),
    "email": re.compile(rb"[\w.+-]+@[\w-]+\.[\w.-]+"),
}
_SUSPICIOUS_STR = [b"cmd.exe", b"powershell", b"CreateRemoteThread", b"VirtualAlloc",
                   b"WriteProcessMemory", b"RegSetValue", b"schtasks", b"rundll32",
                   b"WScript.Shell", b"-enc", b"base64", b"socket", b"WinExec"]


def _shannon(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq if c)


def _ascii_strings(data: bytes, minlen: int = 5) -> list[bytes]:
    return re.findall(rb"[\x20-\x7e]{%d,}" % minlen, data)


def _wide_strings(data: bytes, minlen: int = 5) -> list[bytes]:
    """UTF-16LE strings in the ASCII range: printable byte followed by a
    null byte, repeated. Common in Windows PE string tables and invisible
    to the plain ASCII extractor above."""
    matches = re.findall(rb"(?:[\x20-\x7e]\x00){%d,}" % minlen, data)
    return [m.replace(b"\x00", b"") for m in matches]


class StaticFeaturesTool:
    name = "static_features"

    def run(self, state: AnalysisState) -> StageResult:
        path = state.sample.path
        with open(path, "rb") as f:
            data = f.read()
        input_ref = state.sample.sha256
        art = _artifact(self.name, input_ref, data[:4096])
        findings: list[Finding] = []
        evidence: list[EvidenceRecord] = []
        iocs: list[IOC] = []

        ent = _shannon(data)
        ev_ent = EvidenceRecord(evidence_id=_id("ev", input_ref, "entropy"),
                                artifact_id=art.artifact_id, locator="file:entropy",
                                excerpt=f"{ent:.2f}", trust="tool")
        evidence.append(ev_ent)
        if ent > 7.2:
            findings.append(Finding(
                finding_id=_id("f", input_ref, "highentropy"),
                claim=f"High file entropy ({ent:.2f}/8.0) suggests packing or encryption.",
                category="capability", severity="medium", confidence=0.6,
                evidence=[ev_ent.evidence_id], source_stage="triage"))

        strings = _ascii_strings(data)
        joined = b"\n".join(strings)
        for marker in _SUSPICIOUS_STR:
            if marker.lower() in joined.lower():
                ev = EvidenceRecord(evidence_id=_id("ev", input_ref, marker.decode("latin1")),
                                    artifact_id=art.artifact_id,
                                    locator=f"string:{marker.decode('latin1')}",
                                    excerpt=marker.decode("latin1"), trust="tool")
                evidence.append(ev)
                findings.append(Finding(
                    finding_id=_id("f", input_ref, marker.decode("latin1")),
                    claim=f"Suspicious string present: {marker.decode('latin1')}",
                    category="capability", severity="low", confidence=0.55,
                    evidence=[ev.evidence_id], source_stage="triage"))

        wide_strings = _wide_strings(data)
        wide_joined = b"\n".join(wide_strings)
        for marker in _SUSPICIOUS_STR:
            if marker.lower() in wide_joined.lower():
                ev = EvidenceRecord(evidence_id=_id("ev", input_ref, "wide", marker.decode("latin1")),
                                    artifact_id=art.artifact_id,
                                    locator=f"widestring:{marker.decode('latin1')}",
                                    excerpt=marker.decode("latin1"), trust="tool")
                evidence.append(ev)
                findings.append(Finding(
                    finding_id=_id("f", input_ref, "wide", marker.decode("latin1")),
                    claim=f"Suspicious wide (UTF-16) string present: {marker.decode('latin1')}",
                    category="capability", severity="low", confidence=0.55,
                    evidence=[ev.evidence_id], source_stage="triage"))

        seen = set()
        for kind, rx in _IOC_RX.items():
            for m in rx.findall(data)[:50]:
                val = m.decode("latin1")
                if (kind, val) in seen:
                    continue
                seen.add((kind, val))
                ev = EvidenceRecord(evidence_id=_id("ev", input_ref, kind, val),
                                    artifact_id=art.artifact_id,
                                    locator=f"ioc:{kind}", excerpt=val, trust="tool")
                evidence.append(ev)
                iocs.append(IOC(type=kind, value=val, evidence=[ev.evidence_id]))

        return StageResult(stage="triage", status="ok", findings=findings,
                           artifacts=[art], evidence=evidence, iocs=iocs,
                           notes=f"entropy={ent:.2f}, strings={len(strings)}, "
                                 f"wide_strings={len(wide_strings)}, iocs={len(iocs)}")


class PEHeaderTool:
    """PE structure via pefile when available; degrades gracefully otherwise."""
    name = "pe_header"

    def run(self, state: AnalysisState) -> StageResult:
        input_ref = state.sample.sha256
        try:
            import pefile  # type: ignore
        except Exception:
            return StageResult(stage="triage", status="skipped",
                               unresolved=["PE import table not analyzed: 'pefile' not installed."],
                               notes="install with: pip install pefile")
        try:
            pe = pefile.PE(state.sample.path, fast_load=True)
            pe.parse_data_directories()
        except Exception as e:
            return StageResult(stage="triage", status="error",
                               unresolved=[f"PE parse failed: {e}"])
        imports = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        imports.append(imp.name.decode("latin1"))
        art = _artifact(self.name, input_ref, ("\n".join(imports)).encode())
        findings, evidence, iocs = [], [], []
        risky = {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
                 "SetWindowsHookEx", "GetAsyncKeyState", "URLDownloadToFile",
                 "WinExec", "ShellExecuteA", "CryptEncrypt"}
        for fn in sorted(set(imports) & risky):
            ev = EvidenceRecord(evidence_id=_id("ev", input_ref, fn),
                                artifact_id=art.artifact_id, locator=f"import:{fn}",
                                excerpt=fn, trust="tool")
            evidence.append(ev)
            findings.append(Finding(
                finding_id=_id("f", input_ref, "imp", fn),
                claim=f"Imports {fn}, commonly used for {('process injection' if 'Process' in fn or 'Remote' in fn or 'VirtualAlloc' in fn else 'malicious behavior')}.",
                category="capability", severity="medium", confidence=0.6,
                evidence=[ev.evidence_id], source_stage="triage"))

        # imphash: samples built with the same builder/packer/family typically
        # share an identical import table, so this is a standard, cheap
        # clustering/lookup signal (VT and threat-intel platforms track
        # known-bad imphashes). Failure (e.g. no import table at all) is not
        # an error -- just nothing to report.
        try:
            imphash = pe.get_imphash()
        except Exception:
            imphash = None
        if imphash:
            imp_ev = EvidenceRecord(evidence_id=_id("ev", input_ref, "imphash"),
                                    artifact_id=art.artifact_id, locator="imphash",
                                    excerpt=imphash, trust="tool")
            evidence.append(imp_ev)
            iocs.append(IOC(type="hash", value=imphash, evidence=[imp_ev.evidence_id]))

        # Per-section entropy: a single packed/encrypted section is invisible
        # in the whole-file average if the rest of the binary is normal.
        for section in getattr(pe, "sections", []):
            try:
                sec_entropy = section.get_entropy()
            except Exception:
                continue
            if sec_entropy <= 7.2:
                continue
            sec_name = section.Name.rstrip(b"\x00").decode("latin1", "ignore") or "<unnamed>"
            sec_ev = EvidenceRecord(evidence_id=_id("ev", input_ref, "secentropy", sec_name),
                                    artifact_id=art.artifact_id,
                                    locator=f"section:{sec_name}:entropy",
                                    excerpt=f"{sec_entropy:.2f}", trust="tool")
            evidence.append(sec_ev)
            findings.append(Finding(
                finding_id=_id("f", input_ref, "secentropy", sec_name),
                claim=f"High-entropy section {sec_name} ({sec_entropy:.2f}/8.0) "
                      f"suggests packed or encrypted content.",
                category="capability", severity="medium", confidence=0.6,
                evidence=[sec_ev.evidence_id], source_stage="triage"))

        # Overlay detection: data appended after the last section is outside
        # every declared section and invisible to normal PE parsing -- a
        # common way to hide a payload.
        sections = getattr(pe, "sections", [])
        if sections:
            try:
                end_of_sections = max(s.PointerToRawData + s.SizeOfRawData for s in sections)
                overlay_size = state.sample.size - end_of_sections
            except Exception:
                overlay_size = 0
            if overlay_size > 16:
                ov_ev = EvidenceRecord(evidence_id=_id("ev", input_ref, "overlay"),
                                       artifact_id=art.artifact_id, locator="overlay:size",
                                       excerpt=str(overlay_size), trust="tool")
                evidence.append(ov_ev)
                findings.append(Finding(
                    finding_id=_id("f", input_ref, "overlay"),
                    claim=f"File contains {overlay_size} bytes of overlay data appended "
                          f"after the last PE section -- a common technique for hiding payloads.",
                    category="capability", severity="medium", confidence=0.55,
                    evidence=[ov_ev.evidence_id], source_stage="triage"))

        # Rich header: an undocumented but well-known Microsoft linker
        # artifact encoding compiler/toolchain versions -- a standard
        # attribution/clustering correlation key. Evidence only, no
        # standalone Finding: presence/checksum alone isn't a suspicious
        # signal, same treatment as imphash above.
        #
        # NOTE: pe.RICH_HEADER (attribute access) is only populated by
        # full_load -- under fast_load=True (what this tool uses),
        # accessing it directly raises AttributeError. Confirmed live
        # against real notepad.exe/python.exe. parse_rich_header() is the
        # standalone method that works under fast_load and returns the
        # same data as a dict.
        try:
            rich = pe.parse_rich_header()
        except Exception:
            rich = None
        checksum = rich.get("checksum") if rich else None
        if checksum is not None:
            rich_ev = EvidenceRecord(evidence_id=_id("ev", input_ref, "richheader"),
                                     artifact_id=art.artifact_id, locator="rich_header:checksum",
                                     excerpt=hex(checksum), trust="tool")
            evidence.append(rich_ev)

        return StageResult(stage="triage", status="ok", findings=findings,
                           artifacts=[art], evidence=evidence, iocs=iocs,
                           notes=f"imports={len(imports)}, risky={len(findings)}"
                                 + (f", imphash={imphash}" if imphash else ""))


# capa's own rule corpus (confirmed against the real capa-rules-9.4.0 checkout)
# groups every rule under one of these top-level namespaces. Only this subset
# describes behavior that's inherently attacker-relevant on its own; the rest
# (host-interaction, linking, executable, compiler, internal, lib, nursery,
# runtime, targeting) cover ordinary program behavior present in virtually
# all software (file I/O, dynamic linking, PE structure, ...) and scoring
# them as equally significant is what caused a real false positive: capa
# correctly found 35 capabilities in notepad.exe -- a stock, benign Windows
# binary -- and the old blanket severity="medium" scored it MALICIOUS at 0.9
# confidence. This is a heuristic improvement, not validated calibration
# (that needs labeled data -- M6); it fixes an architectural flaw (treating
# "capa matched a rule" as inherently equal signal) that's true regardless.
_HIGH_SIGNAL_NAMESPACES = {
    "anti-analysis", "collection", "communication", "exploitation",
    "impact", "load-code", "persistence", "malware-family",
}

# load-code/pe is a mixed bag (confirmed against the real capa-rules-9.4.0
# corpus): most of its rules are benign PE-structure introspection (parse
# header, enumerate sections, resolve exports -- exactly what caused a real
# false MALICIOUS verdict on notepad.exe, which legitimately does this), but
# a few describe genuine manual code-loading/injection. The other load-code
# subcategories (dotnet/powershell/shellcode dynamic loading) don't have this
# problem and stay uniformly high-signal.
_LOAD_CODE_PE_HIGH_SIGNAL_NAMES = {
    "inject dll reflectively", "inspect section memory permissions",
    "rebuild import table",
}


def _capa_severity(rule_name: str, namespace: str) -> str:
    parts = namespace.split("/") if namespace else []
    top = parts[0] if parts else ""
    if top == "load-code" and len(parts) > 1 and parts[1] == "pe":
        return "medium" if rule_name.lower() in _LOAD_CODE_PE_HIGH_SIGNAL_NAMES else "info"
    return "medium" if top in _HIGH_SIGNAL_NAMESPACES else "info"


class CapaTool:
    """capa capability mapping (already emits ATT&CK/MBC). Optional; via CLI if present."""
    name = "capa"

    def run(self, state: AnalysisState) -> StageResult:
        import shutil
        import subprocess
        import json as _json
        if not shutil.which("capa"):
            return StageResult(stage="triage", status="skipped",
                               unresolved=["Capability mapping skipped: 'capa' not on PATH."],
                               notes="install flare-capa for ATT&CK-mapped capabilities")
        try:
            out = subprocess.run(_capa_command(state.sample.path),
                                 capture_output=True, timeout=300)
            doc = _json.loads(out.stdout.decode("utf-8", "ignore"))
        except Exception as e:
            return StageResult(stage="triage", status="error",
                               unresolved=[f"capa failed: {e}"])
        input_ref = state.sample.sha256
        art = _artifact(self.name, input_ref, out.stdout[:8192])
        findings, evidence = [], []
        rules = (doc or {}).get("rules", {})
        for rule_name, rule in rules.items():
            meta = rule.get("meta", {})
            attack = [a.get("id", "") for a in meta.get("attack", []) if a.get("id")]
            mbc = sorted({m.get("id", "") for m in meta.get("mbc", []) if m.get("id")})
            namespace = meta.get("namespace", "") or ""
            top_ns = namespace.split("/", 1)[0]
            severity = _capa_severity(rule_name, namespace)
            ev = EvidenceRecord(evidence_id=_id("ev", input_ref, rule_name),
                                artifact_id=art.artifact_id, locator=f"capa:{top_ns}:{rule_name}",
                                excerpt=rule_name, trust="tool")
            evidence.append(ev)
            claim = f"Capability detected: {rule_name}"
            if mbc:
                claim += f" (MBC: {', '.join(mbc)})"
            findings.append(Finding(
                finding_id=_id("f", input_ref, "capa", rule_name),
                claim=claim,
                category="capability", severity=severity, confidence=0.7,
                evidence=[ev.evidence_id], attack_techniques=attack, source_stage="triage"))
        return StageResult(stage="triage", status="ok", findings=findings,
                           artifacts=[art], evidence=evidence,
                           notes=f"capa rules matched={len(findings)}")


class AuthenticodeTool:
    """Windows-only: checks whether the sample carries a valid Authenticode
    signature (`Get-AuthenticodeSignature`), and who signed it. A
    complementary "genuine software" signal to the known-good hash allowlist
    for files that aren't byte-identical to a known reference.

    Deliberately informational only (severity="info", zero-weight; category
    "capability", never "verdict_factor"): a valid signature is corroborating
    context, not proof of benignity. Stolen or abused code-signing
    certificates are a well-documented real attack vector (Stuxnet,
    SolarWinds, and others shipped validly signed malware) -- automatically
    trusting "signed" without a publisher-reputation database this project
    doesn't have would trade one false-positive problem for a false-negative
    one."""
    name = "authenticode"

    def run(self, state: AnalysisState) -> StageResult:
        import os as _os
        import subprocess
        import json as _json
        if _os.name != "nt":
            return StageResult(stage="triage", status="skipped",
                               unresolved=["Authenticode signature check skipped: Windows-only."])

        env = dict(_os.environ)
        env["MALAGENT_TARGET_PATH"] = state.sample.path
        cmd = ["powershell", "-NoProfile", "-Command",
              "Get-AuthenticodeSignature -LiteralPath $env:MALAGENT_TARGET_PATH | "
              "Select-Object Status,StatusMessage,"
              "@{N='Signer';E={$_.SignerCertificate.Subject}} | ConvertTo-Json -Compress"]
        try:
            out = subprocess.run(cmd, capture_output=True, timeout=30, text=True, env=env)
            data = _json.loads(out.stdout)
        except Exception as e:
            return StageResult(stage="triage", status="error",
                               unresolved=[f"Authenticode check failed: {e}"])

        input_ref = state.sample.sha256
        status = data.get("Status")
        signer = data.get("Signer")
        message = data.get("StatusMessage", "unknown")
        art = _artifact(self.name, input_ref, _json.dumps(data, sort_keys=True).encode())
        if status == 0:
            claim = f"File carries a valid Authenticode signature (signer: {signer})." \
                if signer else "File carries a valid Authenticode signature."
        else:
            claim = f"File is not validly Authenticode-signed ({message})."
        ev = EvidenceRecord(evidence_id=_id("ev", input_ref, "authenticode"),
                            artifact_id=art.artifact_id, locator="authenticode:status",
                            excerpt=message, trust="tool")
        finding = Finding(finding_id=_id("f", input_ref, "authenticode"), claim=claim,
                          category="capability", severity="info", confidence=0.6,
                          evidence=[ev.evidence_id], source_stage="triage")
        return StageResult(stage="triage", status="ok", findings=[finding],
                           artifacts=[art], evidence=[ev], notes=f"authenticode status={status}")
