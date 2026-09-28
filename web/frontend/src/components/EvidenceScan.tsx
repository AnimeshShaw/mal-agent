import { useMemo, useState } from "react";
import { CaretDown, CaretRight, MagnifyingGlass } from "@phosphor-icons/react";
import type { EvidenceItem, Finding, Provenance } from "../lib/types";
import { DIRECTION, PROVENANCE, toolName } from "../lib/vocab";
import { Chip, Swatch } from "./ui";

type Channel = "all" | Provenance;

function EvidenceRow({ e, highlighted }: { e: EvidenceItem; highlighted: boolean }) {
  const isSample = e.provenance === "sample_text";
  const long = e.excerpt.length > 180 || e.excerpt.includes("\n");
  const [open, setOpen] = useState(false);
  const meta = PROVENANCE[e.provenance];
  return (
    <li
      id={`ev-${e.id}`}
      className={`scroll-mt-24 px-4 py-2.5 ${highlighted ? "bg-tool-bg" : ""} target:bg-tool-bg`}
    >
      <div className="flex items-start gap-3">
        <Swatch tone={meta.tone} className="mt-[7px]" />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
            <span className="text-sm font-medium text-ink">{toolName(e.tool)}</span>
            <span className="data truncate text-ink-3" title={e.locator}>
              {e.locator}
            </span>
          </div>
          {e.excerpt && (
            <div
              className={`data mt-1 whitespace-pre-wrap break-words ${
                isSample ? "rounded bg-sample-bg px-2 py-1.5 text-sample" : "text-ink-2"
              } ${long && !open ? "line-clamp-3" : ""}`}
            >
              {e.excerpt}
            </div>
          )}
          {long && (
            <button
              type="button"
              onClick={() => setOpen(!open)}
              className="mt-1 inline-flex items-center gap-1 text-sm text-tool hover:underline"
            >
              {open ? <CaretDown weight="bold" className="h-3 w-3" /> : <CaretRight weight="bold" className="h-3 w-3" />}
              {open ? "Collapse" : `Show all ${e.excerpt.length.toLocaleString()} characters`}
            </button>
          )}
        </div>
      </div>
    </li>
  );
}

export function EvidenceScan({ evidence, highlight }: { evidence: EvidenceItem[]; highlight?: Set<string> }) {
  const [channel, setChannel] = useState<Channel>("all");
  const [q, setQ] = useState("");
  const counts = useMemo(() => {
    const c = { all: evidence.length, tool: 0, sample_text: 0, model: 0 };
    evidence.forEach((e) => c[e.provenance]++);
    return c;
  }, [evidence]);
  const shown = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return evidence.filter(
      (e) =>
        (channel === "all" || e.provenance === channel) &&
        (!needle || `${e.locator} ${e.excerpt} ${e.tool}`.toLowerCase().includes(needle)),
    );
  }, [evidence, channel, q]);

  const tabs: { v: Channel; label: string }[] = [
    { v: "all", label: "All" },
    { v: "tool", label: PROVENANCE.tool.label + "s" },
    { v: "sample_text", label: PROVENANCE.sample_text.label },
  ];

  return (
    <div>
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-rule px-4 py-3">
        <div role="radiogroup" aria-label="Evidence channel" className="flex gap-1">
          {tabs.map((t) => (
            <button
              key={t.v}
              role="radio"
              aria-checked={channel === t.v}
              onClick={() => setChannel(t.v)}
              className={`inline-flex items-center gap-1.5 rounded-md px-2.5 py-1 font-sign text-sm font-semibold uppercase tracking-wide ${
                channel === t.v ? "bg-panel-2 text-ink" : "text-ink-3 hover:text-ink-2"
              }`}
            >
              {t.v !== "all" && <Swatch tone={PROVENANCE[t.v as Provenance].tone} />}
              {t.label}
              <span className="text-ink-3">{counts[t.v]}</span>
            </button>
          ))}
        </div>
        <label className="flex w-full items-center gap-2 rounded-md border border-rule px-2.5 focus-within:border-tool sm:w-60">
          <MagnifyingGlass weight="bold" className="h-3.5 w-3.5 text-ink-3" aria-hidden />
          <span className="sr-only">Filter evidence</span>
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Filter evidence"
            className="w-full bg-transparent py-1.5 text-sm text-ink outline-none placeholder:text-ink-3"
          />
        </label>
      </div>
      {channel === "sample_text" && (
        <p className="border-b border-rule px-4 py-2 text-sm text-sample">{PROVENANCE.sample_text.detail}</p>
      )}
      {shown.length === 0 ? (
        <p className="px-4 py-6 text-sm text-ink-3">No evidence in this channel.</p>
      ) : (
        <ul className="max-h-[640px] divide-y divide-rule overflow-y-auto">
          {shown.map((e) => (
            <EvidenceRow key={e.id} e={e} highlighted={!!highlight?.has(e.id)} />
          ))}
        </ul>
      )}
    </div>
  );
}

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 } as const;
const DIRECTION_ORDER = { supports_malicious: 0, supports_benign: 1, neutral: 2 } as const;

export function FindingsList({ findings, onFocus }: { findings: Finding[]; onFocus: (ids: string[]) => void }) {
  const [showInfo, setShowInfo] = useState(false);
  const sorted = useMemo(
    () =>
      [...findings]
        .filter((f) => showInfo || f.severity !== "info")
        .sort(
          (a, b) =>
            DIRECTION_ORDER[a.direction] - DIRECTION_ORDER[b.direction] ||
            SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity],
        ),
    [findings, showInfo],
  );
  const infoCount = findings.filter((f) => f.severity === "info").length;
  const tally = useMemo(() => {
    const t = { supports_malicious: 0, supports_benign: 0, neutral: 0 };
    findings.filter((f) => f.severity !== "info").forEach((f) => t[f.direction]++);
    return t;
  }, [findings]);

  return (
    <div>
      <div className="flex flex-wrap items-center gap-3 border-b border-rule px-4 py-3 text-sm">
        {(["supports_malicious", "supports_benign", "neutral"] as const).map((d) => (
          <span key={d} className="inline-flex items-center gap-1.5 text-ink-2">
            <Swatch tone={DIRECTION[d].tone} />
            {DIRECTION[d].label} <span className="text-ink-3">{tally[d]}</span>
          </span>
        ))}
        {infoCount > 0 && (
          <label className="ml-auto inline-flex items-center gap-2 text-ink-3">
            <input type="checkbox" checked={showInfo} onChange={(e) => setShowInfo(e.target.checked)} className="accent-[var(--tool)]" />
            Show {infoCount} informational
          </label>
        )}
      </div>
      {sorted.length === 0 ? (
        <p className="px-4 py-6 text-sm text-ink-3">No findings at this level.</p>
      ) : (
        <ul className="max-h-[640px] divide-y divide-rule overflow-y-auto">
          {sorted.map((f) => (
            <li key={f.id} className="px-4 py-2.5">
              <div className="flex items-start gap-3">
                <Swatch tone={DIRECTION[f.direction].tone} className="mt-[7px]" />
                <div className="min-w-0 flex-1">
                  <p className="break-words text-ink">{f.claim}</p>
                  <div className="mt-1 flex flex-wrap items-center gap-1.5">
                    <Chip tone={f.severity === "high" || f.severity === "critical" ? "alarm" : "idle"}>{f.severity}</Chip>
                    {f.attack.map((t) => (
                      <Chip key={t} tone="tool">
                        {t}
                      </Chip>
                    ))}
                    {f.evidence.length > 0 && (
                      <button
                        type="button"
                        onClick={() => onFocus(f.evidence)}
                        className="text-sm text-tool hover:underline"
                      >
                        {f.evidence.length === 1 ? "Show evidence" : `Show ${f.evidence.length} evidence items`}
                      </button>
                    )}
                  </div>
                  {f.indication && (
                    <details className="mt-1 text-sm">
                      <summary className="cursor-pointer text-ink-3 hover:text-ink-2">How this counts</summary>
                      <p className="mt-1 break-words text-ink-3">{f.indication}</p>
                    </details>
                  )}
                </div>
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
