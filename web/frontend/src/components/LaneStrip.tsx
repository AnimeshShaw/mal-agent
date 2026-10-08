import { ArrowRight, ArrowDown, ShieldCheck, WarningDiamond, Scales } from "@phosphor-icons/react";
import type { RunDetail } from "../lib/types";
import { FUSION, ROUTE_REASON, TONE_TEXT, VERDICT, formatLabel, toolName } from "../lib/vocab";
import { Chip, Swatch } from "./ui";

const GRAY_LOW = 0.05;
const GRAY_HIGH = 0.3;
const THRESHOLD = 0.15;

/** Classifier score on its calibrated scale: the clear zone, the gray band
 *  where calibration saw no separation, the flag zone, and the 0.15 cut. */
function ScoreScale({ score, usable }: { score: number | null; usable: boolean }) {
  const pct = (x: number) => `${Math.max(0, Math.min(1, x)) * 100}%`;
  return (
    <div className="mt-3">
      <div className="relative h-3 overflow-hidden rounded-sm bg-panel-2" aria-hidden>
        <div className="absolute inset-y-0 left-0 bg-clear/35" style={{ width: pct(GRAY_LOW) }} />
        <div
          className="absolute inset-y-0 bg-inspect/35"
          style={{ left: pct(GRAY_LOW), width: pct(GRAY_HIGH - GRAY_LOW) }}
        />
        <div className="absolute inset-y-0 right-0 bg-alarm/30" style={{ left: pct(GRAY_HIGH) }} />
        <div className="absolute inset-y-0 w-px bg-ink-2" style={{ left: pct(THRESHOLD) }} />
      </div>
      {score != null && (
        <div className="relative h-4" aria-hidden>
          <div
            className={`absolute top-0 -translate-x-1/2 border-x-[6px] border-b-[8px] border-x-transparent ${
              usable ? "border-b-ink" : "border-b-ink-3"
            }`}
            style={{ left: pct(score) }}
          />
        </div>
      )}
      <div className="flex justify-between text-[11px] text-ink-3">
        <span>0</span>
        <span>cut 0.15</span>
        <span>1</span>
      </div>
    </div>
  );
}

function Station({
  title,
  children,
  tone = "idle",
  hideTitle = false,
}: {
  title: string;
  children: React.ReactNode;
  tone?: "idle" | "inspect" | "clear" | "alarm";
  // The Verdict station's body is a display-scale headline (the verdict
  // word itself) -- a small-caps label sitting above it would be a kicker
  // over a heading, which the craft floor bans outright. Its lamp still
  // carries the station's identity; the title stays for screen readers.
  hideTitle?: boolean;
}) {
  const lamp: Record<string, string> = {
    idle: "bg-idle",
    inspect: "bg-inspect shadow-[0_0_8px_var(--inspect)]",
    clear: "bg-clear shadow-[0_0_8px_var(--clear)]",
    alarm: "bg-alarm shadow-[0_0_8px_var(--alarm)]",
  };
  return (
    <div className="relative min-w-0 rounded-md border border-rule bg-panel p-4">
      <div
        className={`mb-2 flex items-center gap-2 font-sign text-[13px] font-bold uppercase tracking-wider text-ink-3 ${hideTitle ? "sr-only" : ""}`}
      >
        <span aria-hidden className={`h-2 w-2 rounded-full ${lamp[tone]}`} />
        {title}
      </div>
      {children}
    </div>
  );
}

function Connector({ label, tone }: { label: string; tone: "clear" | "inspect" }) {
  return (
    <div className={`flex items-center justify-center gap-1.5 py-1 lg:mt-14 lg:flex-col lg:py-0 ${TONE_TEXT[tone]}`}>
      <ArrowDown weight="bold" className="h-4 w-4 lg:hidden" aria-hidden />
      <ArrowRight weight="bold" className="hidden h-5 w-5 lg:block" aria-hidden />
      <span className="sr-only font-sign text-[12px] font-bold uppercase tracking-wider lg:not-sr-only lg:max-w-[76px] lg:text-center">
        {label}
      </span>
    </div>
  );
}

export function LaneStrip({ run }: { run: RunDetail }) {
  const v = run.verdict!;
  const evById = new Map((run.evidence ?? []).map((e) => [e.id, e]));
  const verdict = VERDICT[v.verdict];
  const ember = run.ember;
  const route = run.route ?? { routed: false, reasons: [] };
  const adj = run.adjudication;
  const judge = adj?.result ?? null;
  const usable = !!ember?.in_distribution;
  const shown = ember?.decisive ?? ember?.score ?? null;
  const payload = ember?.payloads?.length
    ? ember.payloads.reduce((a, b) => (parseFloat(b.excerpt) > parseFloat(a.excerpt) ? b : a))
    : null;

  return (
    <div className="scan-sweep grid gap-2 lg:grid-cols-[minmax(0,1fr)_84px_minmax(0,1.2fr)_84px_minmax(0,1fr)] lg:items-start">
      <Station title="Primary screening" tone={route.routed ? "inspect" : "clear"}>
        {shown == null ? (
          <p className="text-ink-2">The classifier did not run (no model configured).</p>
        ) : (
          <>
            <div className="flex items-baseline justify-between gap-3">
              <span className="text-ink-2">EMBER2024 P(malicious)</span>
              <span className={`data text-2xl ${usable ? "text-ink" : "text-ink-3 line-through decoration-1"}`}>
                {shown.toFixed(4)}
              </span>
            </div>
            <ScoreScale score={shown} usable={usable} />
            <p className="mt-2 text-sm text-ink-2">
              {usable
                ? payload
                  ? `Scored on the PE inside the container (${payload.locator.replace("ember:payload:", "")}).`
                  : `In range: ${formatLabel(run.sample?.format)} is what this classifier was trained on.`
                : `Out of range: ${formatLabel(run.sample?.format)} is not a PE, so this score is shown but not used.`}
            </p>
          </>
        )}
      </Station>

      <Connector label={route.routed ? "Flagged" : "Cleared"} tone={route.routed ? "inspect" : "clear"} />

      <Station title="Secondary inspection" tone={route.routed ? "inspect" : "idle"}>
        {!route.routed ? (
          <p className="text-ink-2">Not needed. The classifier is confident and the evidence does not contradict it.</p>
        ) : (
          <div className="space-y-2">
            <ul className="space-y-1.5">
              {route.reasons.map((r) => (
                <li key={r} className="flex gap-2 text-sm">
                  <WarningDiamond weight="fill" className="mt-0.5 h-4 w-4 shrink-0 text-inspect" aria-hidden />
                  <span>
                    <span className="font-medium text-ink">{ROUTE_REASON[r]?.label ?? r}.</span>{" "}
                    <span className="break-words text-ink-2">{ROUTE_REASON[r]?.detail}</span>
                  </span>
                </li>
              ))}
            </ul>
            {run.fusion_mode !== "judge" ? (
              <p className="border-t border-rule pt-2 text-sm text-ink-3">
                No adjudicator in this run ({FUSION[run.fusion_mode]?.label ?? run.fusion_mode} mode). Re-screen in
                Secondary inspection mode to have a model rule on it.
              </p>
            ) : !judge ? (
              <p className="border-t border-rule pt-2 text-sm text-ink-3">
                Flagged, but no adjudicator was available (not configured, or blocked by the keep-local setting).
              </p>
            ) : (
              <div className="border-t border-rule pt-2">
                <div className="flex flex-wrap items-center gap-2">
                  <Scales weight="bold" className="h-4 w-4 text-ink-2" aria-hidden />
                  <span className="data text-sm text-ink-2">
                    {judge.provider}:{judge.model}
                  </span>
                  <span className="text-sm text-ink-2">ruled</span>
                  <span
                    className={`font-sign font-bold uppercase tracking-wide ${
                      judge.raw_verdict === "malicious" ? "text-alarm" : judge.raw_verdict === "benign" ? "text-clear" : "text-ink-3"
                    }`}
                  >
                    {judge.raw_verdict ?? "no answer"}
                  </span>
                  <span className="text-sm text-ink-3">{judge.confidence.toFixed(2)}</span>
                </div>
                {judge.gated && (
                  <p className="mt-1.5 text-sm text-inspect">
                    Set aside: the ruling cited only text copied from the sample, which cannot support a verdict.
                  </p>
                )}
                {!judge.valid && (
                  <p className="mt-1.5 text-sm text-inspect">
                    Set aside: {judge.errors.join("; ") || "the answer could not be validated"}.
                  </p>
                )}
                {judge.rationale && (
                  <p className="mt-1.5 break-words text-sm text-ink-2">
                    {judge.rationale.split(/(\bE\d+\b)/).map((part, i) => {
                      const id = /^E\d+$/.test(part) ? judge.aliases?.[part] : undefined;
                      const ev = id ? evById.get(id) : undefined;
                      return ev ? (
                        <a key={i} href={`#ev-${ev.id}`} className="text-tool hover:underline" title={ev.locator}>
                          {toolName(ev.tool)}
                        </a>
                      ) : (
                        <span key={i}>{part}</span>
                      );
                    })}
                  </p>
                )}
                {judge.cited.length > 0 && (
                  <div className="mt-1.5 flex flex-wrap gap-1">
                    {judge.cited.map((id, i) => (
                      <a key={id} href={`#ev-${id}`} className="hover:underline">
                        <Chip tone={judge.cited_provenance[i] === "tool" ? "tool" : "sample"}>
                          {evById.get(id) ? toolName(evById.get(id)!.tool) : "evidence"}
                        </Chip>
                      </a>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </Station>

      <Connector label="Decision" tone={route.routed ? "inspect" : "clear"} />

      <Station title="Verdict" hideTitle
              tone={verdict.tone === "idle" ? "idle" : (verdict.tone as "alarm" | "clear" | "inspect")}>
        <div className="flex flex-wrap items-end justify-between gap-x-3 gap-y-2">
          <div className="flex min-w-0 items-baseline gap-2.5">
            <Swatch tone={verdict.tone} className="mb-1 h-2.5 w-2.5 shrink-0" />
            <div className={`break-words font-sign text-4xl font-bold uppercase leading-none tracking-wide 2xl:text-5xl ${TONE_TEXT[verdict.tone]}`}>
              {verdict.label}
            </div>
          </div>
          <div className="text-right">
            <div className="data text-xl text-ink">{v.confidence.toFixed(2)}</div>
            <div className="text-xs text-ink-3">confidence</div>
          </div>
        </div>
        <p className="mt-2 text-ink-2">{verdict.line}</p>
        <p className="mt-2 flex gap-1.5 text-sm text-ink-3">
          <ShieldCheck weight="bold" className="mt-0.5 h-4 w-4 shrink-0" aria-hidden />
          <span>Decided by: {run.fusion_mode_label}</span>
        </p>
      </Station>
    </div>
  );
}
