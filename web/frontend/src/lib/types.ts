// Mirrors web/backend/malagent_web/payload.py's detail payload and
// runs.Run.summary(). Only the fields the UI renders.

export type VerdictLabel = "malicious" | "suspicious" | "benign" | "undetermined";
export type FusionMode = "simple" | "cgef" | "judge";
export type RunStatus = "queued" | "running" | "complete" | "error";
export type Provenance = "tool" | "sample_text" | "model";
export type FindingDirection = "supports_malicious" | "supports_benign" | "neutral";
export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type ToolStatus = "ok" | "partial" | "skipped" | "error";

export interface Verdict {
  sample_sha256: string;
  verdict: VerdictLabel;
  confidence: number;
  attack_techniques: string[];
  yara_rules: string[];
  key_findings: string[];
  unresolved: string[];
  evidence_complete: boolean;
  generated_at: string;
}

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

export interface EvidenceItem {
  id: string;
  locator: string;
  tool: string;
  excerpt: string;
  provenance: Provenance;
}

export interface Finding {
  id: string;
  claim: string;
  severity: Severity;
  category: string;
  evidence: string[];
  attack: string[];
  stage: string | null;
  grounded: boolean;
  direction: FindingDirection;
  indication: string;
}

export interface JudgeResult {
  verdict: "malicious" | "benign" | "abstain";
  raw_verdict: string | null;
  confidence: number;
  cited: string[];
  cited_provenance: Provenance[];
  rationale: string;
  valid: boolean;
  gated: boolean;
  errors: string[];
  model: string;
  provider: string;
  latency_ms: number;
}

export interface Adjudication {
  routed: boolean;
  reasons: string[];
  result: JudgeResult | null;
}

export interface RunSummary {
  run_id: string;
  status: RunStatus;
  created_at: string;
  finished_at: string | null;
  filename: string | null;
  fusion_mode: FusionMode;
  verdict: VerdictLabel | null;
  confidence: number | null;
  sha256: string | null;
  format: string | null;
  error: string | null;
}

export interface RunDetail extends Omit<RunSummary, "verdict" | "confidence"> {
  verdict?: Verdict;
  fusion_mode_label?: string;
  sample?: { sha256: string; md5: string; size: number; file_type: string; format: string };
  ember?: {
    score: number | null;
    decisive: number | null;
    in_distribution: boolean;
    payloads: EvidenceItem[];
  };
  gate?: { categories: string[]; signed: boolean; required: number };
  route?: { routed: boolean; reasons: string[] };
  adjudication?: Adjudication | null;
  tools?: ToolReportEntry[];
  findings?: Finding[];
  evidence?: EvidenceItem[];
  iocs?: { type: string; value: string }[];
  attack?: { id: string; name: string; tactics: string[] }[];
  narrative?: string | null;
  narrative_grounded?: boolean;
  narrative_check?: string | null;
  durations_ms?: Record<string, number>;
  unresolved?: string[];
  yara_rules?: string[];
  progress?: string[];
}

export interface AppConfig {
  fusion_modes: FusionMode[];
  judge_models: string[];
  allow_server_paths: boolean;
  max_upload_mb: number;
  workers: number;
}

export interface AnalyzeOptions {
  path?: string;
  file?: File;
  fusionMode: FusionMode;
  judgeModel?: string;
  enableModels: boolean;
  noCloud: boolean;
}
