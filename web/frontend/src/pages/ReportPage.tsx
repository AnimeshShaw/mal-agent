import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ArrowLeft, ArrowSquareOut, DownloadSimple, Spinner, Warning } from "@phosphor-icons/react";
import { fetchReportUrl, getRun, subscribeToProgress } from "../lib/api";
import type { RunDetail } from "../lib/types";
import { FUSION, bytes, formatLabel, when } from "../lib/vocab";
import { LaneStrip } from "../components/LaneStrip";
import { EvidenceScan, FindingsList } from "../components/EvidenceScan";
import { Stations } from "../components/Stations";
import { CopyText, Notice, Panel, SectionHead } from "../components/ui";

function useElapsed(since?: string | null, running = true) {
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    if (!running) return;
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, [running]);
  if (!since) return "";
  const s = Math.max(0, Math.round((now - new Date(since).getTime()) / 1000));
  return s < 60 ? `${s}s` : `${Math.floor(s / 60)}m ${String(s % 60).padStart(2, "0")}s`;
}

const TOOL_LINE = /^\[(triage|static)\] \((\d+)\/(\d+)\) ([\w-]+): (\w+)/;

/** Live view while the belt is moving: each station as it reports in. */
function LiveBelt({ run, lines }: { run: RunDetail; lines: string[] }) {
  const elapsed = useElapsed(run.created_at, true);
  const endRef = useRef<HTMLLIElement>(null);
  useEffect(() => endRef.current?.scrollIntoView({ block: "nearest" }), [lines.length]);
  const latest = [...lines].reverse().find((l) => l.startsWith("[pipeline]"));
  const done = lines.filter((l) => TOOL_LINE.test(l));
  const last = done.length ? done[done.length - 1].match(TOOL_LINE) : null;
  return (
    <div className="mx-auto max-w-[960px] px-5 py-10 lg:px-10">
      <div className="flex items-center gap-3">
        <Spinner weight="bold" className="h-5 w-5 animate-spin text-tool" aria-hidden />
        <h1 className="font-sign text-2xl font-bold tracking-wide text-ink">
          {run.status === "queued" ? "Waiting for a free lane" : "Screening in progress"}
        </h1>
        <span className="data ml-auto text-ink-3">{elapsed}</span>
      </div>
      <p className="mt-1 text-ink-2">
        {run.filename ?? "Sample"} · {FUSION[run.fusion_mode]?.label ?? run.fusion_mode}. Decompiling with Ghidra can
        take several minutes; this page updates on its own.
      </p>
      {last && (
        <div className="mt-5">
          <div className="mb-1.5 flex justify-between text-sm text-ink-3">
            <span>
              {last[1]} station {last[2]} of {last[3]}
            </span>
            <span>{latest?.replace("[pipeline] ", "")}</span>
          </div>
          <div className="h-1.5 overflow-hidden rounded-sm bg-panel-2" aria-hidden>
            <div
              className="h-full bg-tool transition-[width] duration-500 ease-out"
              style={{ width: `${(Number(last[2]) / Number(last[3])) * 100}%` }}
            />
          </div>
        </div>
      )}
      <Panel className="mt-5">
        <ul className="data max-h-[60vh] overflow-y-auto px-4 py-3 text-[13px] leading-6 text-ink-2">
          {lines.length === 0 && <li className="text-ink-3">Waiting for the first station to report…</li>}
          {lines.map((l, i) => {
            const m = l.match(TOOL_LINE);
            const tone = m
              ? m[5] === "ok"
                ? "text-ink-2"
                : m[5] === "error"
                  ? "text-alarm"
                  : "text-ink-3"
              : l.startsWith("[pipeline]")
                ? "text-ink font-medium"
                : "text-ink-3";
            return (
              <li key={i} className={tone}>
                {l}
              </li>
            );
          })}
          <li ref={endRef} />
        </ul>
      </Panel>
    </div>
  );
}

/**
 * Fetches the report with the real auth header and opens/downloads it as a
 * blob URL, so a bearer token never has to travel in a plain <a href>
 * (which can't set headers) or end up in browser history.
 */
function ReportLink({
  run,
  format,
  icon: Icon,
  label,
  openInNewTab,
  download,
}: {
  run: RunDetail;
  format: "html" | "txt";
  icon: typeof ArrowSquareOut;
  label: string;
  openInNewTab?: boolean;
  download?: boolean;
}) {
  const [busy, setBusy] = useState(false);
  return (
    <button
      type="button"
      disabled={busy}
      onClick={async () => {
        setBusy(true);
        try {
          const url = await fetchReportUrl(run.run_id, format);
          if (download) {
            const a = document.createElement("a");
            a.href = url;
            a.download = `${run.filename ?? run.run_id}.${format}`;
            a.click();
          } else if (openInNewTab) {
            window.open(url, "_blank", "noopener,noreferrer");
          }
          setTimeout(() => URL.revokeObjectURL(url), 60_000);
        } finally {
          setBusy(false);
        }
      }}
      className="inline-flex items-center gap-1.5 rounded-md border border-rule bg-panel px-3 py-1.5 text-sm text-ink-2 hover:text-ink disabled:opacity-50"
    >
      {busy ? <Spinner weight="bold" className="h-3.5 w-3.5 animate-spin" aria-hidden /> : <Icon weight="bold" className="h-3.5 w-3.5" aria-hidden />}
      {label}
    </button>
  );
}

function Report({ run }: { run: RunDetail }) {
  const [focus, setFocus] = useState<Set<string>>(new Set());
  const evRef = useRef<HTMLDivElement>(null);
  // Setup notices (a tool not configured/installed) belong with tool coverage;
  // what the analysis itself could not settle is shown first.
  const [unresolved, setupGaps] = useMemo(() => {
    const all = Array.from(new Set(run.unresolved ?? []));
    const setup = /not configured|not installed|not on PATH|No model configured|not set\b|set [A-Z_]{6,}|not found \(set/i;
    return [all.filter((u) => !setup.test(u)), all.filter((u) => setup.test(u))];
  }, [run.unresolved]);

  function focusEvidence(ids: string[]) {
    setFocus(new Set(ids));
    const first = document.getElementById(`ev-${ids[0]}`);
    (first ?? evRef.current)?.scrollIntoView({ behavior: "smooth", block: "center" });
  }

  return (
    <div className="mx-auto max-w-[1440px] px-5 py-6 lg:px-8">
      <div className="mb-5 flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <Link to="/runs" className="mb-1 inline-flex items-center gap-1 text-sm text-ink-3 hover:text-ink">
            <ArrowLeft weight="bold" className="h-3.5 w-3.5" aria-hidden />
            Run log
          </Link>
          <h1 className="truncate font-sign text-3xl font-bold tracking-wide text-ink">{run.filename ?? "Sample"}</h1>
          <div className="mt-1 flex flex-wrap items-center gap-x-4 gap-y-1 text-sm text-ink-3">
            {run.sample && (
              <CopyText text={run.sample.sha256} display={`sha256 ${run.sample.sha256.slice(0, 24)}…`} />
            )}
            <span>{formatLabel(run.sample?.format)}</span>
            <span>{bytes(run.sample?.size)}</span>
            <span>{when(run.created_at)}</span>
          </div>
        </div>
        <div className="flex flex-wrap gap-2">
          <ReportLink run={run} format="html" icon={ArrowSquareOut} label="HTML report" openInNewTab />
          <ReportLink run={run} format="txt" icon={DownloadSimple} label="Full text report" download />
        </div>
      </div>

      <LaneStrip run={run} />

      <div className="mt-6 grid gap-6 xl:grid-cols-[minmax(0,1fr)_380px]">
        <div className="min-w-0 space-y-6">
          {run.narrative && (
            <div>
              <SectionHead
                title="Behaviour narrative"
                aside={run.narrative_grounded ? "Fact-checked against its evidence" : "Did not pass the fact-check"}
              />
              <Panel className="px-5 py-4">
                {!run.narrative_grounded && (
                  <div className="mb-3">
                    <Notice tone="inspect">
                      The independent fact-check did not confirm every sentence below. Read it as a draft, and rely on
                      the evidence.
                    </Notice>
                  </div>
                )}
                <p className="max-w-[75ch] whitespace-pre-wrap text-ink-2">{run.narrative}</p>
                <p className="mt-3 text-sm text-ink-3">Written by a language model. It never changes the verdict.</p>
              </Panel>
            </div>
          )}

          <div>
            <SectionHead
              title="Findings"
              aside={
                run.gate
                  ? `Corroboration: ${run.gate.categories.length} of ${run.gate.required} categories needed to convict on evidence alone`
                  : "Which way each one points"
              }
            />
            <Panel>
              <FindingsList findings={run.findings ?? []} onFocus={focusEvidence} />
            </Panel>
          </div>

          <div ref={evRef}>
            <SectionHead title="Evidence" aside="What the tools actually saw" />
            <Panel>
              <EvidenceScan evidence={run.evidence ?? []} highlight={focus} />
            </Panel>
          </div>
        </div>

        <div className="min-w-0 space-y-6">
          <div>
            <SectionHead title="Tool coverage" />
            <Panel>
              <Stations tools={run.tools ?? []} />
            </Panel>
          </div>

          {(unresolved.length > 0 || setupGaps.length > 0) && (
            <div>
              <SectionHead title="Could not determine" />
              <Panel className="px-4 py-3">
                {unresolved.length > 0 ? (
                  <ul className="space-y-2 text-sm text-ink-2">
                    {unresolved.slice(0, 30).map((u, i) => (
                      <li key={i}>{u}</li>
                    ))}
                  </ul>
                ) : (
                  <p className="text-sm text-ink-3">Nothing the analysis itself left open.</p>
                )}
                {setupGaps.length > 0 && (
                  <details className="mt-3 border-t border-rule pt-2 text-sm">
                    <summary className="cursor-pointer text-ink-3 hover:text-ink-2">
                      {setupGaps.length} tools not set up on this machine
                    </summary>
                    <ul className="mt-2 space-y-2 text-ink-3">
                      {setupGaps.map((u, i) => (
                        <li key={i}>{u}</li>
                      ))}
                    </ul>
                  </details>
                )}
              </Panel>
            </div>
          )}

          {!!run.iocs?.length && (
            <div>
              <SectionHead title="Indicators" aside={`${run.iocs.length} extracted`} />
              <Panel>
                <ul className="max-h-[320px] divide-y divide-rule overflow-y-auto">
                  {run.iocs.map((i, k) => (
                    <li key={k} className="flex items-center gap-3 px-4 py-2">
                      <span className="w-14 shrink-0 font-sign text-[13px] font-semibold uppercase text-ink-3">{i.type}</span>
                      <CopyText text={i.value} className="min-w-0 text-sample" />
                    </li>
                  ))}
                </ul>
                <p className="border-t border-rule px-4 py-2 text-xs text-ink-3">
                  Copied out of the sample: defang before sharing.
                </p>
              </Panel>
            </div>
          )}

          {!!run.attack?.length && (
            <div>
              <SectionHead title="ATT&CK techniques" />
              <Panel>
                <ul className="divide-y divide-rule">
                  {run.attack.map((t) => (
                    <li key={t.id} className="px-4 py-2">
                      <a
                        href={`https://attack.mitre.org/techniques/${t.id.replace(".", "/")}/`}
                        target="_blank"
                        rel="noreferrer"
                        className="data text-tool hover:underline"
                      >
                        {t.id}
                      </a>{" "}
                      <span className="text-ink">{t.name}</span>
                      {t.tactics.length > 0 && <div className="text-sm text-ink-3">{t.tactics.join(" · ")}</div>}
                    </li>
                  ))}
                </ul>
              </Panel>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export function ReportPage() {
  const { runId } = useParams<{ runId: string }>();
  const [run, setRun] = useState<RunDetail | null>(null);
  const [lines, setLines] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!runId) return;
    let cancelled = false;
    let unsubscribe: (() => void) | null = null;
    setLines([]);
    const load = () =>
      getRun(runId)
        .then((r) => {
          if (cancelled) return;
          setRun(r);
          if ((r.status === "queued" || r.status === "running") && !unsubscribe) {
            unsubscribe = subscribeToProgress(
              runId,
              (l) => setLines((prev) => [...prev, l]),
              () => !cancelled && load(),
            );
          }
        })
        .catch((e) => !cancelled && setError(e.message));
    load();
    return () => {
      cancelled = true;
      unsubscribe?.();
    };
  }, [runId]);

  if (error) {
    return (
      <div className="mx-auto max-w-[760px] px-5 py-10">
        <Notice tone="alarm">
          <span className="inline-flex items-center gap-2">
            <Warning weight="bold" className="h-4 w-4" aria-hidden /> {error}
          </span>
        </Notice>
        <Link to="/runs" className="mt-4 inline-block text-tool hover:underline">
          Back to the run log
        </Link>
      </div>
    );
  }
  if (!run) {
    return <div className="px-10 py-10 text-ink-3">Loading…</div>;
  }
  if (run.status === "queued" || run.status === "running") {
    return <LiveBelt run={run} lines={lines} />;
  }
  if (run.status === "error") {
    return (
      <div className="mx-auto max-w-[760px] px-5 py-10">
        <h1 className="font-sign text-2xl font-bold tracking-wide text-ink">The analysis failed</h1>
        <p className="mt-2 text-ink-2">
          Nothing was concluded about this file. The error below is what the pipeline reported.
        </p>
        <pre className="data mt-4 whitespace-pre-wrap rounded-md bg-alarm-bg px-4 py-3 text-alarm">{run.error}</pre>
        <Link to="/" className="mt-4 inline-block text-tool hover:underline">
          Screen another file
        </Link>
      </div>
    );
  }
  if (!run.verdict) {
    return <div className="px-10 py-10 text-ink-3">This run finished without a report.</div>;
  }
  return <Report run={run} />;
}
