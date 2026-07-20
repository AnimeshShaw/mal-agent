"""Frozen contracts. These typed boundaries change rarely and deliberately.
Internals behind them are free to churn without forcing a rewrite."""
from __future__ import annotations
from datetime import datetime, timezone
from typing import Callable, Literal, Optional, Protocol, runtime_checkable
from pydantic import BaseModel, Field


def now() -> datetime:
    return datetime.now(timezone.utc)


# ---- provenance / chain of custody (D13) ----
class Provenance(BaseModel):
    source: Literal["soc", "cdc", "manual", "dataset"] = "manual"
    ticket_id: Optional[str] = None
    received_from: Optional[str] = None
    received_at: datetime = Field(default_factory=now)


class Sample(BaseModel):
    sha256: str
    md5: str
    path: str                       # defanged, quarantined location
    file_type: str
    size: int
    classification: str = "restricted"
    provenance: Provenance = Field(default_factory=Provenance)
    received_at: datetime = Field(default_factory=now)


# ---- evidence model (D7) ----
class RawArtifact(BaseModel):
    artifact_id: str                # content hash
    tool: str
    tool_version: str = "0"
    input_ref: str                  # sha256 of tool input
    produced_at: datetime = Field(default_factory=now)
    storage_ref: str = ""


class EvidenceRecord(BaseModel):
    evidence_id: str
    artifact_id: str
    locator: str                    # "function@0x401000", "rule:CreateRemoteThread"
    excerpt: Optional[str] = None   # short, sanitized
    trust: Literal["tool", "model"] = "tool"


class Finding(BaseModel):
    finding_id: str
    claim: str
    category: Literal["capability", "behavior", "ttp", "ioc", "family", "verdict_factor"]
    severity: Literal["info", "low", "medium", "high", "critical"] = "info"
    confidence: float = 0.5
    evidence: list[str] = Field(default_factory=list)      # EvidenceRecord ids
    attack_techniques: list[str] = Field(default_factory=list)
    source_stage: str = ""
    grounded: bool = False          # set only by the verifier


class IOC(BaseModel):
    type: Literal["ip", "domain", "url", "mutex", "registry", "file", "hash", "email"]
    value: str
    evidence: list[str] = Field(default_factory=list)


class StageResult(BaseModel):
    stage: str
    status: Literal["ok", "partial", "skipped", "error"] = "ok"
    findings: list[Finding] = Field(default_factory=list)
    artifacts: list[RawArtifact] = Field(default_factory=list)
    evidence: list[EvidenceRecord] = Field(default_factory=list)
    iocs: list[IOC] = Field(default_factory=list)
    unresolved: list[str] = Field(default_factory=list)     # explicit "could not determine"
    notes: Optional[str] = None


# ---- policy / budget (D6) ----
class EgressPolicy(BaseModel):
    allow_cloud: bool = True
    allow_raw_bytes_egress: bool = False
    allow_pseudocode_egress: bool = False
    redact_strings: bool = True
    log_all_egress: bool = True
    escalation_triggers: list[str] = Field(
        default_factory=lambda: ["low_confidence", "security_critical", "ambiguous_decompile"]
    )


class StepBudget(BaseModel):
    max_functions_decompiled: int = 25
    max_cloud_calls: int = 10
    max_total_steps: int = 200
    cloud_calls_used: int = 0


class ModelCall(BaseModel):
    provider: str
    model: str
    location: Literal["local", "cloud"]
    prompt_hash: str
    egress_allowed: bool
    at: datetime = Field(default_factory=now)


class AnalysisState(BaseModel):
    run_id: str
    sample: Sample
    policy: EgressPolicy = Field(default_factory=EgressPolicy)
    budget: StepBudget = Field(default_factory=StepBudget)
    stage_results: list[StageResult] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)      # accumulated, post-verify
    evidence: list[EvidenceRecord] = Field(default_factory=list)
    iocs: list[IOC] = Field(default_factory=list)
    model_calls: list[ModelCall] = Field(default_factory=list)
    status: Literal["running", "complete", "error"] = "running"


class Verdict(BaseModel):
    sample_sha256: str
    verdict: Literal["malicious", "suspicious", "benign", "undetermined"] = "undetermined"
    confidence: float = 0.0
    family: Optional[str] = None
    attack_techniques: list[str] = Field(default_factory=list)
    iocs: list[IOC] = Field(default_factory=list)
    yara_rules: list[str] = Field(default_factory=list)
    key_findings: list[str] = Field(default_factory=list)
    unresolved: list[str] = Field(default_factory=list)
    evidence_complete: bool = False
    generated_at: datetime = Field(default_factory=now)


# ---- audit (D13) ----
class AuditRecord(BaseModel):
    seq: int
    run_id: str
    action: str
    detail: dict = Field(default_factory=dict)
    at: datetime = Field(default_factory=now)
    prev_hash: str = ""
    record_hash: str = ""


# ---- interfaces (the swappable seams) ----
@runtime_checkable
class ToolAdapter(Protocol):
    name: str
    def run(self, state: "AnalysisState") -> StageResult: ...


Agent = Callable[["AnalysisState"], "AnalysisState"]


@runtime_checkable
class Repository(Protocol):
    def save_run(self, state: "AnalysisState", verdict: "Verdict") -> str: ...
    def get_verdict(self, sha256: str) -> Optional["Verdict"]: ...
    def append_audit(self, record: "AuditRecord") -> None: ...
