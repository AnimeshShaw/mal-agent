import { useState, type ReactNode } from "react";
import { Check, Copy } from "@phosphor-icons/react";
import { TONE_CHIP, TONE_TEXT, VERDICT, type Tone } from "../lib/vocab";
import type { VerdictLabel } from "../lib/types";

export function Chip({ tone, children, title }: { tone: Tone; children: ReactNode; title?: string }) {
  return (
    <span
      title={title}
      className={`inline-flex items-center gap-1 rounded px-1.5 py-0.5 font-sign text-[12.5px] font-semibold uppercase tracking-wide ${TONE_CHIP[tone]}`}
    >
      {children}
    </span>
  );
}

/** A square channel marker in the X-ray false-colour vocabulary. */
export function Swatch({ tone, className = "" }: { tone: Tone; className?: string }) {
  const bg: Record<Tone, string> = {
    alarm: "bg-alarm",
    clear: "bg-clear",
    inspect: "bg-inspect",
    idle: "bg-idle",
    tool: "bg-tool",
    sample: "bg-sample",
  };
  return <span aria-hidden className={`inline-block h-2.5 w-2.5 shrink-0 rounded-[2px] ${bg[tone]} ${className}`} />;
}

export function SectionHead({ title, aside }: { title: string; aside?: ReactNode }) {
  return (
    <div className="mb-3 flex items-baseline justify-between gap-3">
      <h2 className="font-sign text-lg font-bold uppercase tracking-wide text-ink">{title}</h2>
      {aside && <div className="text-sm text-ink-3">{aside}</div>}
    </div>
  );
}

export function VerdictWord({ verdict, className = "" }: { verdict: VerdictLabel | null | undefined; className?: string }) {
  if (!verdict) return <span className={`text-ink-3 ${className}`}>—</span>;
  const v = VERDICT[verdict];
  return <span className={`font-sign font-bold uppercase tracking-wide ${TONE_TEXT[v.tone]} ${className}`}>{v.label}</span>;
}

export function CopyText({ text, display, className = "" }: { text: string; display?: string; className?: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      onClick={() => {
        navigator.clipboard?.writeText(text).then(() => {
          setCopied(true);
          setTimeout(() => setCopied(false), 1200);
        });
      }}
      title="Copy"
      className={`group inline-flex min-w-0 items-center gap-1.5 rounded text-left hover:text-ink ${className}`}
    >
      <span className="data truncate">{display ?? text}</span>
      {copied ? (
        <Check weight="bold" className="h-3.5 w-3.5 shrink-0 text-clear" aria-hidden />
      ) : (
        <Copy weight="bold" className="h-3.5 w-3.5 shrink-0 opacity-40 group-hover:opacity-100" aria-hidden />
      )}
      <span className="sr-only">{copied ? "Copied" : "Copy to clipboard"}</span>
    </button>
  );
}

export function Panel({ children, className = "" }: { children: ReactNode; className?: string }) {
  return <section className={`rounded-lg border border-rule bg-panel ${className}`}>{children}</section>;
}

export function Notice({ tone, children }: { tone: Tone; children: ReactNode }) {
  return <div className={`rounded-md px-3 py-2 text-sm ${TONE_CHIP[tone]} normal-case tracking-normal`}>{children}</div>;
}
