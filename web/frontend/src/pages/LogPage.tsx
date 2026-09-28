import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { MagnifyingGlass } from "@phosphor-icons/react";
import { listRuns } from "../lib/api";
import type { RunSummary, VerdictLabel } from "../lib/types";
import { FUSION, formatLabel, shortHash, when } from "../lib/vocab";
import { Notice, Panel, VerdictWord } from "../components/ui";

const FILTERS: { v: VerdictLabel | "all" | "running"; label: string }[] = [
  { v: "all", label: "All" },
  { v: "malicious", label: "Malicious" },
  { v: "suspicious", label: "Suspicious" },
  { v: "undetermined", label: "Undetermined" },
  { v: "benign", label: "Benign" },
  { v: "running", label: "In progress" },
];

export function LogPage() {
  const navigate = useNavigate();
  const [runs, setRuns] = useState<RunSummary[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<(typeof FILTERS)[number]["v"]>("all");
  const [q, setQ] = useState("");

  useEffect(() => {
    let cancelled = false;
    const load = () =>
      listRuns()
        .then((r) => !cancelled && setRuns(r))
        .catch((e) => !cancelled && setError(e.message));
    load();
    const t = setInterval(load, 5000);
    return () => {
      cancelled = true;
      clearInterval(t);
    };
  }, []);

  const shown = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return (runs ?? []).filter((r) => {
      if (filter === "running" && !(r.status === "queued" || r.status === "running")) return false;
      if (filter !== "all" && filter !== "running" && r.verdict !== filter) return false;
      if (!needle) return true;
      return [r.filename, r.sha256, r.format].some((f) => f?.toLowerCase().includes(needle));
    });
  }, [runs, filter, q]);

  return (
    <div className="mx-auto max-w-[1180px] px-5 py-8 lg:px-10 lg:py-10">
      <div className="mb-5 flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="font-sign text-3xl font-bold tracking-wide text-ink">Run log</h1>
          <p className="text-ink-2">Every file screened on this machine, newest first.</p>
        </div>
        <label className="flex w-full items-center gap-2 rounded-md border border-rule bg-panel px-3 focus-within:border-tool sm:w-72">
          <MagnifyingGlass weight="bold" className="h-4 w-4 text-ink-3" aria-hidden />
          <span className="sr-only">Search runs</span>
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="File name, hash or format"
            className="w-full bg-transparent py-2 text-ink outline-none placeholder:text-ink-3"
          />
        </label>
      </div>

      <div role="radiogroup" aria-label="Filter by verdict" className="mb-4 flex flex-wrap gap-1.5">
        {FILTERS.map((f) => (
          <button
            key={f.v}
            role="radio"
            aria-checked={filter === f.v}
            onClick={() => setFilter(f.v)}
            className={`rounded-md px-3 py-1.5 font-sign text-sm font-semibold uppercase tracking-wide ${
              filter === f.v ? "bg-ink text-ground" : "bg-panel text-ink-2 hover:bg-panel-2"
            }`}
          >
            {f.label}
          </button>
        ))}
      </div>

      {error && <Notice tone="alarm">{error}</Notice>}

      <Panel className="overflow-x-auto">
        <table className="w-full min-w-[760px] text-left">
          <thead>
            <tr className="border-b border-rule font-sign text-[13px] uppercase tracking-wide text-ink-3">
              <th className="px-4 py-2.5 font-semibold">Verdict</th>
              <th className="px-4 py-2.5 font-semibold">File</th>
              <th className="px-4 py-2.5 font-semibold">Format</th>
              <th className="px-4 py-2.5 font-semibold">SHA-256</th>
              <th className="px-4 py-2.5 font-semibold">Decided by</th>
              <th className="px-4 py-2.5 font-semibold">When</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-rule">
            {runs === null && (
              <tr>
                <td colSpan={6} className="px-4 py-8 text-ink-3">
                  Loading…
                </td>
              </tr>
            )}
            {runs !== null && shown.length === 0 && (
              <tr>
                <td colSpan={6} className="px-4 py-8 text-ink-3">
                  {runs.length === 0 ? (
                    <>
                      Nothing screened yet.{" "}
                      <Link to="/" className="text-tool hover:underline">
                        Screen a file
                      </Link>
                    </>
                  ) : (
                    "No runs match this filter."
                  )}
                </td>
              </tr>
            )}
            {shown.map((r) => (
              <tr
                key={r.run_id}
                onClick={() => navigate(`/runs/${r.run_id}`)}
                className="cursor-pointer hover:bg-panel-2"
              >
                <td className="px-4 py-3">
                  {r.status === "complete" ? (
                    <span className="flex items-baseline gap-2">
                      <VerdictWord verdict={r.verdict} />
                      {r.confidence != null && <span className="text-sm text-ink-3">{r.confidence.toFixed(2)}</span>}
                    </span>
                  ) : r.status === "error" ? (
                    <span className="text-alarm">Failed</span>
                  ) : (
                    <span className="text-inspect">In progress</span>
                  )}
                </td>
                <td className="max-w-[260px] px-4 py-3">
                  <Link to={`/runs/${r.run_id}`} className="block truncate text-ink hover:underline">
                    {r.filename ?? "unnamed sample"}
                  </Link>
                </td>
                <td className="px-4 py-3 text-ink-2">{formatLabel(r.format)}</td>
                <td className="data px-4 py-3 text-ink-3">{shortHash(r.sha256)}</td>
                <td className="px-4 py-3 text-ink-2">{FUSION[r.fusion_mode]?.short ?? r.fusion_mode}</td>
                <td className="whitespace-nowrap px-4 py-3 text-ink-3">{when(r.created_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Panel>
    </div>
  );
}
