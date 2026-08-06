import { Info } from "@phosphor-icons/react";

export function NarrativePanel({ narrative }: { narrative: string | null }) {
  if (!narrative) {
    return (
      <div className="rounded-lg border border-zinc-200 bg-white p-4 dark:border-zinc-800 dark:bg-zinc-900">
        <p className="text-sm text-zinc-500 dark:text-zinc-500">
          No behavioral narrative is available for this run (no local/cloud model was configured,
          or there were no grounded findings to synthesize from). See the per-tool findings below.
        </p>
      </div>
    );
  }

  return (
    <div className="rounded-lg border border-zinc-200 bg-white p-4 dark:border-zinc-800 dark:bg-zinc-900">
      <div className="mb-2 flex items-center gap-1.5 text-xs font-medium text-zinc-500 dark:text-zinc-500">
        <Info weight="bold" className="h-4 w-4" aria-hidden />
        Non-binding narrative, does not affect the verdict above
      </div>
      <p className="whitespace-pre-wrap text-sm leading-relaxed text-zinc-800 dark:text-zinc-200">
        {narrative}
      </p>
    </div>
  );
}
