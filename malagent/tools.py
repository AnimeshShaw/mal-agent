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
    # Quantifiers bounded to real-world max lengths (DNS label <=63,
    # RFC 5321 local-part <=64 / domain <=255) -- NOT just style. Live-verified
    # ReDoS: the original unbounded `(?:X+\.)+` / `X+@X+\.X+` shapes took
    # ~10s to fail against a 50,000-byte run of plain word characters
    # (O(n^2) backtracking), and hung for many CPU-minutes on a real 3MB
    # malware sample with a large ASCII-heavy section. Bounding every
    # quantifier caps worst-case backtracking to a small constant
    # regardless of input size.
    "domain": re.compile(rb"\b(?:[a-z0-9-]{1,63}\.){1,10}(?:com|net|org|info|biz|ru|cn|io|xyz|top)\b", re.I),
    "email": re.compile(rb"\b[\w.+-]{1,64}@[\w-]{1,63}\.[\w.-]{1,255}\b"),
}
_SUSPICIOUS_STR = [b"cmd.exe", b"powershell", b"CreateRemoteThread", b"VirtualAlloc",
                   b"WriteProcessMemory", b"RegSetValue", b"schtasks", b"rundll32",
                   b"WScript.Shell", b"-enc", b"base64", b"socket", b"WinExec"]


def _looks_like_namespace(val: str) -> bool:
    """.NET/managed-code namespace strings (System.Net, System.IO,
    Microsoft.Win32, ...) are ordinary assembly metadata, not domains --
    but the domain regex's TLD list includes 'net'/'io', so they collide.
    Real C2 domains embedded in malware strings are essentially always
    lowercase; namespace identifiers are PascalCase per segment by
    convention. Live-verified this collision is real, not theoretical:
    'System.Net' matches an actual entry in a real threat-intel blocklist
    (hagezi) that IocReputationTool then scored as a match -- filtering
    on case preserves detection of the genuine lowercase domain
    ('system.net') while dropping the PascalCase metadata artifact."""
    labels = val.split(".")
    return all(label[:1].isupper() for label in labels if label)


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
                if kind == "domain" and _looks_like_namespace(val):
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


_IMAGE_MAGIC = (
    b"\x89PNG\r\n\x1a\n",   # PNG (Vista+ icons embed these for larger sizes)
    b"\xff\xd8\xff",        # JPEG
    b"GIF87a", b"GIF89a",   # GIF
)


def _looks_like_compressed_image(blob: bytes) -> bool:
    return blob.startswith(_IMAGE_MAGIC)


def _iter_pe_resource_blobs(pe):
    """Walks pefile's 3-level resource tree (type -> name -> language) and
    yields each leaf resource's raw bytes. Defensive at every level:
    a malformed or partial resource directory (missing .directory,
    unreadable data) should degrade to "found nothing here", never crash
    triage -- resources are optional PE structure, not something every
    real-world sample has intact."""
    root = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
    if root is None:
        return
    for type_entry in getattr(root, "entries", []):
        name_entries = getattr(getattr(type_entry, "directory", None), "entries", [])
        for name_entry in name_entries:
            lang_entries = getattr(getattr(name_entry, "directory", None), "entries", [])
            for leaf in lang_entries:
                data = getattr(leaf, "data", None)
                struct = getattr(data, "struct", None) if data else None
                if struct is None:
                    continue
                try:
                    blob = pe.get_data(struct.OffsetToData, struct.Size)
                except Exception:
                    continue
                if blob:
                    yield blob


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

        # Resource (.rsrc) parsing: a common way to hide a payload is to
        # embed it as a PE resource -- either a full second PE (dropper/
        # loader pattern, unambiguous once you look) or a high-entropy
        # (packed/encrypted) blob invisible to whole-file/section entropy
        # if the rest of the binary is normal. Resources sit in their own
        # 3-level tree (type -> name -> language); walk defensively since
        # a malformed/partial resource directory shouldn't crash triage.
        for i, blob in enumerate(_iter_pe_resource_blobs(pe)):
            if len(blob) < 64:
                continue  # icons/version-info fragments: too small to be meaningful
            if _looks_like_compressed_image(blob):
                # Real false positive, found live on notepad.exe/explorer.exe:
                # Vista+ Windows icons embed PNG for larger sizes, and PNG's
                # own internal (DEFLATE) compression gives it entropy
                # ~7.9-8.0 -- indistinguishable from a packed/encrypted blob
                # by entropy alone. A recognizable image-format magic header
                # is an innocent, structural explanation for that entropy.
                continue
            if blob[:2] == b"MZ":
                pe_ev = EvidenceRecord(evidence_id=_id("ev", input_ref, "rsrc_pe", str(i)),
                                       artifact_id=art.artifact_id,
                                       locator=f"resource:{i}:embedded_pe", excerpt="MZ",
                                       trust="tool")
                evidence.append(pe_ev)
                findings.append(Finding(
                    finding_id=_id("f", input_ref, "rsrc_pe", str(i)),
                    claim=f"Resource #{i} contains an embedded PE (MZ header) -- a common "
                          f"dropper/loader pattern for hiding a second-stage payload.",
                    category="capability", severity="high", confidence=0.7,
                    evidence=[pe_ev.evidence_id], source_stage="triage"))
                continue
            blob_entropy = _shannon(blob)
            if blob_entropy > 7.2:
                ent_ev = EvidenceRecord(evidence_id=_id("ev", input_ref, "rsrc_entropy", str(i)),
                                        artifact_id=art.artifact_id,
                                        locator=f"resource:{i}:entropy",
                                        excerpt=f"{blob_entropy:.2f}", trust="tool")
                evidence.append(ent_ev)
                findings.append(Finding(
                    finding_id=_id("f", input_ref, "rsrc_entropy", str(i)),
                    claim=f"High-entropy resource blob #{i} ({blob_entropy:.2f}/8.0, "
                          f"{len(blob)} bytes) suggests a packed or encrypted payload "
                          f"hidden in a PE resource.",
                    category="capability", severity="medium", confidence=0.55,
                    evidence=[ent_ev.evidence_id], source_stage="triage"))

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


# capa does not scale gracefully to very large files -- live-verified: a
# real, benign 92MB node.exe caused capa to still be running after several
# minutes in an isolated test (no other process competing for CPU). File-
# size inflation is also a known malware evasion technique (the 87MB
# LockBit sample downloaded for this project's own M6 dataset is plausibly
# an example), so this matters for real samples too, not just large
# legitimate binaries. Below the RedLineStealer-sized samples (~35MB) this
# project's own dataset already analyzes successfully.
_CAPA_MAX_SIZE_BYTES = 50 * 1024 * 1024  # 50MB


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
        if state.sample.size > _CAPA_MAX_SIZE_BYTES:
            return StageResult(stage="triage", status="skipped",
                               unresolved=[f"Capability mapping skipped: sample "
                                          f"({state.sample.size} bytes) exceeds capa's "
                                          f"practical size cap ({_CAPA_MAX_SIZE_BYTES} bytes) "
                                          f"-- capa's analysis does not scale gracefully to "
                                          f"very large files."],
                               notes="skipped: exceeds capa size cap")
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
