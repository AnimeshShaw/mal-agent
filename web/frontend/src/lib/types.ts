// Mirrors malagent.contracts.Verdict / reporter.build_tool_report()'s JSON
// shape. Kept intentionally narrow -- only the fields the UI actually
// renders, not a full 1:1 of every Python field.

export type VerdictLabel = "malicious" | "suspicious" | "benign" | "undetermined";

export interface IOC {
  type: string;
  value: string;
  evidence: string[];
}

export interface Verdict {
  sample_sha256: string;
  verdict: VerdictLabel;
  confidence: number;
  family: string | null;
  attack_techniques: string[];
  iocs: IOC[];
  yara_rules: string[];
  key_findings: string[];
  unresolved: string[];
  evidence_complete: boolean;
  generated_at: string;
}

export type FindingDirection = "supports_malicious" | "supports_benign" | "neutral";
export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type ToolStatus = "ok" | "partial" | "skipped" | "error";

export interface ToolFinding {
  claim: string;
  severity: Severity;
  confidence: number;
  indicates: string;
  direction: FindingDirection;
}

export interface ToolReportEntry {
  tool: string;
  stage: string | null;
  purpose: string;
  status: ToolStatus;
  reason: string | null;
  notes: string | null;
  unresolved: string[];
  findings: ToolFinding[];
}

export type RunStatus = "queued" | "running" | "complete" | "error";

export interface AnalysisStatusResponse {
  run_id: string;
  status: RunStatus;
  error?: string;
  verdict?: Verdict;
  fusion_mode_label?: string;
  tools?: ToolReportEntry[];
  narrative?: string | null;
}

export interface CreateAnalysisResponse {
  run_id: string;
  status: RunStatus;
}

export interface AnalyzeOptions {
  path?: string;
  file?: File;
  fusionMode: "simple" | "cgef";
  enableModels: boolean;
  noCloud: boolean;
}
