import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ArrowLeft, DownloadSimple, Spinner, Warning } from "@phosphor-icons/react";
import { getAnalysis, reportUrl } from "../lib/api";
import type { AnalysisStatusResponse } from "../lib/types";
import { VerdictBanner } from "../components/VerdictBanner";
import { ToolCard } from "../components/ToolCard";
import { NarrativePanel } from "../components/NarrativePanel";
import { EvidencePanel } from "../components/EvidencePanel";

export function ReportPage() {
  const { runId } = useParams<{ runId: string }>();
  const [data, setData] = useState<AnalysisStatusResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!runId) return;
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout>;

    async function poll() {
      try {
        const status = await getAnalysis(runId!);
        if (cancelled) return;
        setData(status);
        if (status.status === "queued" || status.status === "running") {
          timer = setTimeout(poll, 500);
        }
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : "Failed to load run.");
      }
    }
    poll();
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [runId]);

  if (error) {
    return (
      <div className="mx-auto max-w-2xl px-6 py-10">
        <p className="flex items-center gap-2 rounded-md bg-red-50 px-3 py-2 text-sm text-red-800 dark:bg-red-950/50 dark:text-red-300">
          <Warning weight="bold" className="h-4 w-4 shrink-0" aria-hidden />
          {error}
        </p>
      </div>
    );
  }

  if (!data || data.status === "queued" || data.status === "running") {
    return (
      <div className="mx-auto flex max-w-2xl flex-col items-center gap-3 px-6 py-20 text-center">
        <Spinner weight="bold" className="h-6 w-6 animate-spin text-accent" aria-hidden />
        <p className="text-sm text-zinc-600 dark:text-zinc-400">
          {data?.status === "running" ? "Analysis running" : "Waiting for the analysis to start"}
        </p>
      </div>
    );
  }

  if (data.status === "error") {
    return (
      <div className="mx-auto max-w-2xl px-6 py-10">
        <p className="flex items-center gap-2 rounded-md bg-red-50 px-3 py-2 text-sm text-red-800 dark:bg-red-950/50 dark:text-red-300">
          <Warning weight="bold" className="h-4 w-4 shrink-0" aria-hidden />
          {data.error ?? "The analysis failed."}
        </p>
      </div>
    );
  }

  if (!data.verdict || !data.tools) {
    return null;
  }

  return (
    <div className="mx-auto max-w-4xl px-6 py-10">
      <div className="flex items-center justify-between">
        <Link
          to="/"
          className="flex items-center gap-1.5 text-sm text-zinc-600 hover:text-zinc-900 dark:text-zinc-400 dark:hover:text-zinc-100"
        >
          <ArrowLeft weight="bold" className="h-4 w-4" aria-hidden />
          New analysis
        </Link>
        <div className="flex gap-2">
          <a
            href={reportUrl(runId!, "html")}
            target="_blank"
            rel="noreferrer"
            className="flex items-center gap-1.5 rounded-md border border-zinc-300 px-3 py-1.5 text-xs font-medium text-zinc-700 hover:bg-zinc-50 dark:border-zinc-700 dark:text-zinc-300 dark:hover:bg-zinc-900"
          >
            <DownloadSimple weight="bold" className="h-3.5 w-3.5" aria-hidden />
            HTML
          </a>
          <a
            href={reportUrl(runId!, "txt")}
            target="_blank"
            rel="noreferrer"
            className="flex items-center gap-1.5 rounded-md border border-zinc-300 px-3 py-1.5 text-xs font-medium text-zinc-700 hover:bg-zinc-50 dark:border-zinc-700 dark:text-zinc-300 dark:hover:bg-zinc-900"
          >
            <DownloadSimple weight="bold" className="h-3.5 w-3.5" aria-hidden />
            TXT
          </a>
        </div>
      </div>

      <div className="mt-4">
        <VerdictBanner verdict={data.verdict} fusionModeLabel={data.fusion_mode_label ?? ""} />
      </div>

      <div className="mt-6">
        <h2 className="mb-2 text-sm font-semibold text-zinc-900 dark:text-zinc-100">
          Behavioral narrative
        </h2>
        <NarrativePanel narrative={data.narrative ?? null} />
      </div>

      <div className="mt-6">
        <h2 className="mb-2 text-sm font-semibold text-zinc-900 dark:text-zinc-100">
          Per-tool analysis
        </h2>
        <div className="grid gap-2.5 sm:grid-cols-2">
          {data.tools.map((entry) => (
            <ToolCard key={entry.tool} entry={entry} />
          ))}
        </div>
      </div>

      <div className="mt-6">
        <h2 className="mb-2 text-sm font-semibold text-zinc-900 dark:text-zinc-100">
          Evidence
        </h2>
        <EvidencePanel verdict={data.verdict} />
      </div>
    </div>
  );
}
