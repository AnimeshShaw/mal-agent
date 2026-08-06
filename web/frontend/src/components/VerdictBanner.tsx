import { ShieldCheck, ShieldWarning, Skull, Question } from "@phosphor-icons/react";
import type { Verdict } from "../lib/types";

const VERDICT_STYLE: Record<
  Verdict["verdict"],
  { bg: string; border: string; icon: typeof ShieldCheck; label: string }
> = {
  malicious: {
    bg: "bg-red-50 dark:bg-red-950/40",
    border: "border-red-300 dark:border-red-900",
    icon: Skull,
    label: "Malicious",
  },
  suspicious: {
    bg: "bg-amber-50 dark:bg-amber-950/40",
    border: "border-amber-300 dark:border-amber-900",
    icon: ShieldWarning,
    label: "Suspicious",
  },
  benign: {
    bg: "bg-emerald-50 dark:bg-emerald-950/40",
    border: "border-emerald-300 dark:border-emerald-900",
    icon: ShieldCheck,
    label: "Benign",
  },
  undetermined: {
    bg: "bg-zinc-100 dark:bg-zinc-900",
    border: "border-zinc-300 dark:border-zinc-700",
    icon: Question,
    label: "Undetermined",
  },
};

const ICON_COLOR: Record<Verdict["verdict"], string> = {
  malicious: "text-red-600 dark:text-red-400",
  suspicious: "text-amber-600 dark:text-amber-400",
  benign: "text-emerald-600 dark:text-emerald-400",
  undetermined: "text-zinc-500 dark:text-zinc-400",
};

export function VerdictBanner({
  verdict,
  fusionModeLabel,
}: {
  verdict: Verdict;
  /** From reporter.fusion_mode_label(state) -- the single most important
   * transparency line in the whole report: which mechanism actually
   * decided this run's verdict. Never guessed client-side. */
  fusionModeLabel: string;
}) {
  const style = VERDICT_STYLE[verdict.verdict];
  const Icon = style.icon;
  const confidencePct = Math.round(verdict.confidence * 100);

  return (
    <div className={`rounded-lg border ${style.border} ${style.bg} p-6`}>
      <div className="flex items-start gap-4">
        <Icon weight="fill" className={`h-10 w-10 shrink-0 ${ICON_COLOR[verdict.verdict]}`} aria-hidden />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
            <h1 className="text-2xl font-semibold tracking-tight text-zinc-900 dark:text-zinc-50">
              {style.label}
            </h1>
            <span className="text-sm text-zinc-600 dark:text-zinc-400">
              {confidencePct}% confidence
            </span>
          </div>
          <p className="mt-1 font-mono text-xs text-zinc-500 dark:text-zinc-500 break-all">
            {verdict.sample_sha256}
          </p>
          <div className="mt-3 flex flex-wrap gap-x-6 gap-y-1 text-sm text-zinc-700 dark:text-zinc-300">
            <span>
              Decision method: <span className="font-medium">{fusionModeLabel}</span>
            </span>
            <span>
              Evidence complete:{" "}
              <span className="font-medium">{verdict.evidence_complete ? "yes" : "no"}</span>
            </span>
            {verdict.family && (
              <span>
                Family: <span className="font-medium">{verdict.family}</span>
              </span>
            )}
          </div>
          {verdict.attack_techniques.length > 0 && (
            <div className="mt-3 flex flex-wrap gap-1.5">
              {verdict.attack_techniques.map((t) => (
                <span
                  key={t}
                  className="rounded border border-zinc-300 bg-white px-1.5 py-0.5 font-mono text-xs text-zinc-700 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-300"
                >
                  {t}
                </span>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
