import { useState } from "react";
import {
  CaretDown,
  CheckCircle,
  MinusCircle,
  WarningCircle,
  XCircle,
} from "@phosphor-icons/react";
import type { ToolReportEntry } from "../lib/types";

const STATUS_META: Record<
  ToolReportEntry["status"],
  { icon: typeof CheckCircle; color: string; label: string }
> = {
  ok: { icon: CheckCircle, color: "text-emerald-600 dark:text-emerald-400", label: "Ran" },
  partial: { icon: WarningCircle, color: "text-amber-600 dark:text-amber-400", label: "Partial" },
  skipped: { icon: MinusCircle, color: "text-zinc-400 dark:text-zinc-500", label: "Skipped" },
  error: { icon: XCircle, color: "text-red-600 dark:text-red-400", label: "Error" },
};

const DIRECTION_META: Record<string, { color: string; label: string }> = {
  supports_malicious: {
    color: "bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300",
    label: "Supports malicious",
  },
  supports_benign: {
    color: "bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300",
    label: "Supports benign",
  },
  neutral: {
    color: "bg-zinc-100 text-zinc-600 dark:bg-zinc-800 dark:text-zinc-400",
    label: "Neutral",
  },
};

export function ToolCard({ entry }: { entry: ToolReportEntry }) {
  const [open, setOpen] = useState(entry.status !== "skipped");
  const status = STATUS_META[entry.status];
  const StatusIcon = status.icon;

  return (
    <div className="rounded-lg border border-zinc-200 bg-white dark:border-zinc-800 dark:bg-zinc-900">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center justify-between gap-3 px-4 py-3 text-left"
        aria-expanded={open}
      >
        <div className="flex min-w-0 items-center gap-2.5">
          <StatusIcon weight="fill" className={`h-5 w-5 shrink-0 ${status.color}`} aria-hidden />
          <span className="truncate font-medium text-zinc-900 dark:text-zinc-100">{entry.tool}</span>
          <span className={`shrink-0 text-xs font-medium ${status.color}`}>{status.label}</span>
          {entry.findings.length > 0 && (
            <span className="shrink-0 rounded-full bg-zinc-100 px-1.5 py-0.5 text-xs text-zinc-600 dark:bg-zinc-800 dark:text-zinc-400">
              {entry.findings.length}
            </span>
          )}
        </div>
        <CaretDown
          weight="bold"
          className={`h-4 w-4 shrink-0 text-zinc-400 transition-transform ${open ? "rotate-180" : ""}`}
          aria-hidden
        />
      </button>

      {open && (
        <div className="border-t border-zinc-200 px-4 py-3 dark:border-zinc-800">
          <p className="text-sm text-zinc-600 dark:text-zinc-400">{entry.purpose}</p>

          {entry.reason && (
            <p className="mt-2 text-sm text-zinc-500 dark:text-zinc-500">
              <span className="font-medium">Reason: </span>
              {entry.reason}
            </p>
          )}
          {entry.notes && (
            <p className="mt-2 text-sm text-zinc-500 dark:text-zinc-500">
              <span className="font-medium">Notes: </span>
              {entry.notes}
            </p>
          )}

          {entry.findings.length > 0 && (
            <ul className="mt-3 space-y-2.5">
              {entry.findings.map((f, i) => {
                const dir = DIRECTION_META[f.direction] ?? DIRECTION_META.neutral;
                return (
                  <li
                    key={i}
                    className="rounded bg-zinc-50 px-3 py-2 dark:bg-zinc-950"
                  >
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="rounded bg-zinc-200 px-1.5 py-0.5 text-xs font-semibold uppercase tracking-wide text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300">
                        {f.severity}
                      </span>
                      <span className={`rounded px-1.5 py-0.5 text-xs font-medium ${dir.color}`}>
                        {dir.label}
                      </span>
                    </div>
                    <p className="mt-1.5 text-sm text-zinc-800 dark:text-zinc-200">{f.claim}</p>
                    <p className="mt-1 text-xs italic text-zinc-500 dark:text-zinc-500">{f.indicates}</p>
                  </li>
                );
              })}
            </ul>
          )}

          {entry.unresolved.length > 0 && (
            <ul className="mt-3 space-y-1">
              {entry.unresolved.map((u, i) => (
                <li key={i} className="text-xs text-amber-700 dark:text-amber-500">
                  Unresolved: {u}
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}
