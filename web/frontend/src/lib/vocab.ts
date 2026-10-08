// The product's own words for every coded value the backend returns.
import type { FindingDirection, FusionMode, Provenance, VerdictLabel } from "./types";

export const VERDICT: Record<VerdictLabel, { label: string; tone: Tone; line: string }> = {
  malicious: { label: "Malicious", tone: "alarm", line: "Contain and escalate." },
  suspicious: { label: "Suspicious", tone: "inspect", line: "Signals disagree. An analyst should decide." },
  benign: { label: "Benign", tone: "clear", line: "No evidence of malicious intent." },
  undetermined: {
    label: "Undetermined",
    tone: "idle",
    line: "The evidence does not support a call either way.",
  },
};

export type Tone = "alarm" | "clear" | "inspect" | "idle" | "tool" | "sample";

export const TONE_TEXT: Record<Tone, string> = {
  alarm: "text-alarm",
  clear: "text-clear",
  inspect: "text-inspect",
  idle: "text-ink-3",
  tool: "text-tool",
  sample: "text-sample",
};

export const TONE_CHIP: Record<Tone, string> = {
  alarm: "bg-alarm-bg text-alarm",
  clear: "bg-clear-bg text-clear",
  inspect: "bg-inspect-bg text-inspect",
  idle: "bg-panel-2 text-ink-3",
  tool: "bg-tool-bg text-tool",
  sample: "bg-sample-bg text-sample",
};

export const ROUTE_REASON: Record<string, { label: string; detail: string }> = {
  ember_ood: {
    label: "Outside the classifier's range",
    detail:
      "The PE-trained classifier cannot judge this file type, so its score is shown but not used.",
  },
  ember_gray: {
    label: "Classifier unsure",
    detail: "The classifier score sits in the band where calibration saw no clear separation (0.05–0.30).",
  },
  ember_gate_conflict: {
    label: "Classifier contradicts the evidence",
    detail:
      "The classifier and the deterministic evidence point in opposite directions (e.g. a benign score with three or more corroborated capability categories).",
  },
};

export const FUSION: Record<FusionMode, { label: string; short: string; detail: string }> = {
  simple: {
    label: "Classifier",
    short: "Classifier decides",
    detail: "EMBER decides PE files. Other formats fall back to the deterministic evidence.",
  },
  cgef: {
    label: "Gated fusion",
    short: "Gate votes in gray zone",
    detail: "The deterministic corroboration gate votes where the classifier is unsure.",
  },
  judge: {
    label: "Secondary inspection",
    short: "Judge on hard cases",
    detail:
      "Confident PE files keep the classifier's call. Hard cases go to an LLM adjudicator that must cite tool evidence.",
  },
};

export const PROVENANCE: Record<Provenance, { label: string; tone: Tone; detail: string }> = {
  tool: {
    label: "Tool fact",
    tone: "tool",
    detail: "Computed by an analysis tool. Can support a verdict.",
  },
  sample_text: {
    label: "Sample text",
    tone: "sample",
    detail: "Copied verbatim out of the file. Attacker-controlled: context only, never support.",
  },
  model: { label: "Model", tone: "idle", detail: "Written by a language model." },
};

export const DIRECTION: Record<FindingDirection, { label: string; tone: Tone }> = {
  supports_malicious: { label: "Toward malicious", tone: "alarm" },
  supports_benign: { label: "Toward benign", tone: "clear" },
  neutral: { label: "Neutral", tone: "idle" },
};

const FORMAT_LABELS: Record<string, string> = {
  pe: "Windows PE",
  elf: "ELF",
  macho: "Mach-O",
  pdf: "PDF",
  rtf: "RTF",
  ole: "OLE (Office 97 / MSI)",
  ooxml: "Office Open XML",
  lnk: "Windows shortcut",
  onenote: "OneNote",
  zip: "ZIP archive",
  archive: "Archive",
  iso: "ISO image",
  script_js: "JavaScript",
  script_vbs: "VBScript",
  script_ps1: "PowerShell",
  script_bat: "Batch script",
  script_hta: "HTML application",
  text: "Text",
  unknown: "Unrecognised",
};

export function formatLabel(fmt?: string | null): string {
  if (!fmt) return "—";
  return FORMAT_LABELS[fmt] ?? fmt;
}

export function bytes(n?: number | null): string {
  if (n == null) return "—";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

export function when(iso?: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  const diff = (Date.now() - d.getTime()) / 1000;
  if (diff < 60) return "just now";
  if (diff < 3600) return `${Math.floor(diff / 60)} min ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)} h ago`;
  return d.toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" });
}

export function shortHash(h?: string | null, n = 12): string {
  return h ? `${h.slice(0, n)}…` : "—";
}

export const TOOL_NAMES: Record<string, string> = {
  known_good: "Known-good hashes",
  elf_header: "ELF header",
  macho_header: "Mach-O header",
  file: "File entropy",
  string: "Strings",
  widestring: "Wide strings",
  strings: "Strings sample",
  ember: "EMBER classifier",
  import: "PE imports",
  section: "PE sections",
  resource: "PE resources",
  overlay: "PE overlay",
  rich_header: "Rich header",
  imphash: "Import hash",
  ioc: "Extracted IOC",
  yara_info: "YARA (informational)",
  elf_import: "ELF imports",
  elf_section: "ELF sections",
  format: "Format ID",
  script: "Script indicators",
  lnk: "Shortcut parser",
  office: "Office macros",
  pdf: "PDF keywords",
  static_features: "Strings & entropy",
  ioc_reputation: "IOC reputation",
  unpacker: "Container unpacker",
  pe_header: "PE header",
  elf: "ELF header",
  macho: "Mach-O header",
  capa: "capa capabilities",
  authenticode: "Authenticode",
  yara_match: "YARA rules",
  die: "Detect It Easy",
  virustotal: "VirusTotal",
  ember_classifier: "EMBER classifier",
  ghidra: "Ghidra decompiler",
  floss: "FLOSS strings",
  static_llm_summary: "Function summaries (LLM)",
  dynamic_agent: "Sandbox detonation",
  ttp_agent: "ATT&CK mapping",
  behavioral_analyst: "Behaviour narrative (LLM)",
  verifier_agent: "Grounding gate",
  verifier_critic: "Narrative fact-check (LLM)",
};

export function toolName(t: string): string {
  return TOOL_NAMES[t] ?? t;
}
