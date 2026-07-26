"""VirusTotal hash lookup (docs/TODO.md Phase 0 D6 + Phase 2). Needs a
real API key (VIRUSTOTAL_API_KEY) AND EgressPolicy.allow_hash_lookup=True
-- deliberately gated behind its own explicit opt-in, not reuse of
allow_raw_bytes_egress/allow_pseudocode_egress, since a hash lookup is a
different kind of egress with a different risk profile (see
EgressGuard.allowed() in models.py). NOT live-verified against the real
VirusTotal API: no key was available in this session. Code-complete and
tested via mocked HTTP responses matching VT's documented v3 API shape;
will only function once an operator supplies a real key, same pattern as
CAPA_RULES_PATH/KNOWN_GOOD_HASHES_PATH for other external data."""
from __future__ import annotations
import os

try:
    import requests
except Exception:
    requests = None

from .contracts import AnalysisState, EvidenceRecord, Finding, StageResult
from .models import EgressGuard
from .tools import _artifact, _id

_API_URL = "https://www.virustotal.com/api/v3/files/{sha256}"


class VirusTotalTool:
    """Triage-stage tool: looks up the sample's SHA256 against VirusTotal.
    Never treats an unknown hash (404) as evidence of benignity -- a
    genuinely novel malware sample would also 404 on first submission,
    same "absence of evidence isn't evidence of absence" discipline as
    every other tool in this project."""
    name = "virustotal"

    def run(self, state: AnalysisState) -> StageResult:
        api_key = os.getenv("VIRUSTOTAL_API_KEY")
        if not api_key:
            return StageResult(
                stage="triage", status="skipped",
                unresolved=["VirusTotal hash lookup not performed: set VIRUSTOTAL_API_KEY "
                            "to enable."],
                notes="no API key configured")
        if requests is None:
            return StageResult(stage="triage", status="skipped",
                               unresolved=["VirusTotal hash lookup not performed: "
                                           "'requests' not installed."],
                               notes="install with: pip install requests")

        guard = EgressGuard(state.policy)
        ok, reason = guard.allowed("cloud", "hash_lookup")
        if not ok:
            return StageResult(
                stage="triage", status="skipped",
                unresolved=[f"VirusTotal hash lookup blocked by policy: {reason}. Set "
                            f"EgressPolicy.allow_hash_lookup=True to enable."],
                notes=f"blocked by policy: {reason}")

        input_ref = state.sample.sha256
        try:
            resp = requests.get(_API_URL.format(sha256=input_ref),
                                headers={"x-apikey": api_key}, timeout=15)
        except Exception as e:
            return StageResult(stage="triage", status="error",
                               unresolved=[f"VirusTotal request failed: {e}"])

        if resp.status_code == 404:
            return StageResult(
                stage="triage", status="ok",
                unresolved=["Sample hash not present in VirusTotal's corpus (could be "
                            "genuinely novel malware, not necessarily benign)."],
                notes="hash not found")
        if resp.status_code != 200:
            return StageResult(stage="triage", status="error",
                               unresolved=[f"VirusTotal returned HTTP {resp.status_code}"])

        try:
            stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
            malicious = int(stats.get("malicious", 0))
            suspicious = int(stats.get("suspicious", 0))
            total = sum(int(v) for v in stats.values())
        except Exception as e:
            return StageResult(stage="triage", status="error",
                               unresolved=[f"VirusTotal response parsing failed: {e}"])

        findings: list[Finding] = []
        evidence: list[EvidenceRecord] = []
        artifacts = []
        if malicious > 0 or suspicious > 0:
            art = _artifact(self.name, input_ref, f"{malicious}/{total}".encode())
            artifacts.append(art)
            ev = EvidenceRecord(evidence_id=_id("ev", input_ref, "vt"),
                                artifact_id=art.artifact_id, locator="virustotal:detections",
                                excerpt=f"{malicious}/{total} malicious, {suspicious} suspicious",
                                trust="tool")
            evidence.append(ev)
            findings.append(Finding(
                finding_id=_id("f", input_ref, "vt"),
                claim=f"VirusTotal: {malicious} of {total} engines flag this hash as "
                      f"malicious ({suspicious} more as suspicious).",
                category="capability", severity="high" if malicious >= 5 else "medium",
                confidence=min(0.6 + malicious * 0.02, 0.9),
                evidence=[ev.evidence_id], source_stage="triage"))

        return StageResult(stage="triage", status="ok", findings=findings,
                           artifacts=artifacts, evidence=evidence,
                           notes=f"{malicious}/{total} malicious detections")
