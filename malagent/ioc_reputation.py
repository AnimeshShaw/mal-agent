"""IOC reputation check (D-later): cross-references IPs/domains/URLs already
extracted by StaticFeaturesTool against locally-downloaded threat-intel
blocklists. Zero network egress -- pure local file matching, same
"operator downloads the list, points an env var at it" pattern as
CAPA_RULES_PATH / KNOWN_GOOD_HASHES_PATH. List files are never bundled
into this repo since sources like hagezi/dns-blocklists are GPL-3.0 and
this project is MIT."""
from __future__ import annotations
import os
from pathlib import Path
from urllib.parse import urlparse

from .contracts import AnalysisState, EvidenceRecord, Finding, StageResult
from .tools import _id


def _load_list(path: str) -> set[str]:
    entries = set()
    for line in Path(path).read_text(errors="ignore").splitlines():
        line = line.strip().lower()
        if not line or line.startswith("#"):
            continue
        entries.add(line)
    return entries


def _hostname(value: str) -> str:
    if "://" in value:
        return (urlparse(value).hostname or "").lower()
    return value.lower()


class IocReputationTool:
    """Triage-stage tool: matches state.iocs (populated earlier by
    StaticFeaturesTool) against local IP/domain blocklists. Must run
    after StaticFeaturesTool in the tool order."""
    name = "ioc_reputation"

    def run(self, state: AnalysisState) -> StageResult:
        ip_path = os.getenv("IP_BLOCKLIST_PATH")
        domain_path = os.getenv("DOMAIN_BLOCKLIST_PATH")
        if not ip_path and not domain_path:
            return StageResult(
                stage="triage", status="skipped",
                unresolved=["IOC reputation blocklists not configured: set "
                            "IP_BLOCKLIST_PATH and/or DOMAIN_BLOCKLIST_PATH to "
                            "enable local threat-intel cross-referencing."],
                notes="blocklists not configured")

        ip_list = _load_list(ip_path) if ip_path and Path(ip_path).is_file() else set()
        domain_list = _load_list(domain_path) if domain_path and Path(domain_path).is_file() else set()
        if not ip_list and not domain_list:
            return StageResult(stage="triage", status="skipped",
                               notes="configured blocklist path(s) not found")

        findings = []
        evidence = []
        for ioc in state.iocs:
            if ioc.type == "ip":
                hit = ioc.value.lower() in ip_list
            elif ioc.type in ("domain", "url"):
                hit = _hostname(ioc.value) in domain_list
            else:
                continue
            if not hit:
                continue

            ev = EvidenceRecord(
                evidence_id=_id("ev", ioc.type, ioc.value, "ioc_reputation"),
                artifact_id=_id("art", ioc.type, ioc.value, "ioc_reputation"),
                locator=f"ioc_reputation:{ioc.type}", excerpt=ioc.value, trust="tool")
            findings.append(Finding(
                finding_id=_id("f", ioc.type, ioc.value, "ioc_reputation"),
                claim=f"{ioc.type.upper()} indicator {ioc.value!r} matches a local "
                      f"threat-intel blocklist entry.",
                category="ioc", severity="medium", confidence=0.7,
                evidence=[ev.evidence_id], source_stage="triage"))
            evidence.append(ev)

        return StageResult(stage="triage", status="ok", findings=findings, evidence=evidence,
                           notes=f"{len(findings)} blocklist match(es) "
                                 f"({len(ip_list)} IPs / {len(domain_list)} domains loaded)")
