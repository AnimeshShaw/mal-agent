import { useEffect, useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ArrowRight, FileArrowUp, FolderOpen, Spinner, X } from "@phosphor-icons/react";
import { createAnalysis, getConfig, listRuns } from "../lib/api";
import type { AppConfig, FusionMode, RunSummary } from "../lib/types";
import { FUSION, bytes, formatLabel, when } from "../lib/vocab";
import { Notice, Panel, SectionHead, VerdictWord } from "../components/ui";

function readLocal<T>(key: string, fallback: T): T {
  try {
    const v = localStorage.getItem(key);
    return v == null ? fallback : (JSON.parse(v) as T);
  } catch {
    return fallback;
  }
}

function writeLocal(key: string, v: unknown) {
  try {
    localStorage.setItem(key, JSON.stringify(v));
  } catch {
    /* not persisted in private mode */
  }
}

export function IntakePage() {
  const navigate = useNavigate();
  const [config, setConfig] = useState<AppConfig | null>(null);
  const [recent, setRecent] = useState<RunSummary[] | null>(null);
  const [source, setSource] = useState<"upload" | "path">("upload");
  const [file, setFile] = useState<File | null>(null);
  const [path, setPath] = useState("");
  const [mode, setMode] = useState<FusionMode>(() => readLocal("malagent.mode", "simple"));
  const [judgeModel, setJudgeModel] = useState<string>(() => readLocal("malagent.judge", ""));
  const [narrative, setNarrative] = useState<boolean>(() => readLocal("malagent.narrative", false));
  const [localOnly, setLocalOnly] = useState<boolean>(() => readLocal("malagent.localOnly", true));
  const [dragging, setDragging] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    getConfig()
      .then((c) => {
        setConfig(c);
        if (!judgeModel && c.judge_models.length) setJudgeModel(c.judge_models[0]);
      })
      .catch((e) => setError(e.message));
    listRuns()
      .then((r) => setRecent(r.slice(0, 8)))
      .catch(() => setRecent([]));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => writeLocal("malagent.mode", mode), [mode]);
  useEffect(() => writeLocal("malagent.judge", judgeModel), [judgeModel]);
  useEffect(() => writeLocal("malagent.narrative", narrative), [narrative]);
  useEffect(() => writeLocal("malagent.localOnly", localOnly), [localOnly]);

  const judgeIsCloud = mode === "judge" && judgeModel && !judgeModel.startsWith("ollama:");
  const ready = source === "upload" ? !!file : path.trim().length > 0;

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      const { run_id } = await createAnalysis({
        file: source === "upload" ? file ?? undefined : undefined,
        path: source === "path" ? path.trim() : undefined,
        fusionMode: mode,
        judgeModel: mode === "judge" ? judgeModel : undefined,
        enableModels: narrative,
        noCloud: localOnly,
      });
      navigate(`/runs/${run_id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "The analysis could not be started.");
      setSubmitting(false);
    }
  }

  return (
    <div className="mx-auto grid max-w-[1180px] gap-8 px-5 py-8 lg:grid-cols-[minmax(0,1fr)_340px] lg:px-10 lg:py-10">
      <form onSubmit={submit} className="min-w-0 space-y-7">
        <div>
          <h1 className="font-sign text-3xl font-bold tracking-wide text-ink">Screen a file</h1>
          <p className="mt-1 max-w-[62ch] text-ink-2">
            Nothing is executed. The file is copied into quarantine, every static tool looks at it, and
            the report shows what each tool found, what it could not check, and which way each finding
            points.
          </p>
        </div>

        {config?.allow_server_paths && (
          <div role="tablist" aria-label="Sample source" className="flex gap-1 border-b border-rule">
            {(
              [
                ["upload", "Upload"],
                ["path", "Path on this machine"],
              ] as const
            ).map(([v, label]) => (
              <button
                key={v}
                type="button"
                role="tab"
                aria-selected={source === v}
                onClick={() => setSource(v)}
                className={`-mb-px border-b-2 px-3 pb-2 font-sign text-[15px] font-semibold uppercase tracking-wide ${
                  source === v ? "border-tool text-ink" : "border-transparent text-ink-3 hover:text-ink-2"
                }`}
              >
                {label}
              </button>
            ))}
          </div>
        )}

        {source === "upload" ? (
          <div
            onDragOver={(e) => {
              e.preventDefault();
              setDragging(true);
            }}
            onDragLeave={() => setDragging(false)}
            onDrop={(e) => {
              e.preventDefault();
              setDragging(false);
              const f = e.dataTransfer.files?.[0];
              if (f) setFile(f);
            }}
            className={`relative rounded-lg border-2 border-dashed transition-colors ${
              dragging ? "border-tool bg-tool-bg" : "border-rule bg-panel hover:border-ink-3"
            }`}
          >
            <input
              ref={inputRef}
              id="sample"
              type="file"
              className="sr-only"
              onChange={(e) => setFile(e.target.files?.[0] ?? null)}
            />
            {file ? (
              <div className="flex items-center gap-4 px-5 py-6">
                <div className="grid h-12 w-12 shrink-0 place-items-center rounded-md bg-sample-bg text-sample">
                  <FileArrowUp weight="bold" className="h-6 w-6" aria-hidden />
                </div>
                <div className="min-w-0 flex-1">
                  <div className="truncate font-medium text-ink">{file.name}</div>
                  <div className="text-sm text-ink-3">
                    {bytes(file.size)} · will be stored as a neutral, non-executable file
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => {
                    setFile(null);
                    if (inputRef.current) inputRef.current.value = "";
                  }}
                  className="rounded p-1.5 text-ink-3 hover:bg-panel-2 hover:text-ink"
                  title="Remove file"
                >
                  <X weight="bold" className="h-4 w-4" aria-hidden />
                  <span className="sr-only">Remove file</span>
                </button>
              </div>
            ) : (
              <label htmlFor="sample" className="flex cursor-pointer flex-col items-center gap-2 px-5 py-12 text-center">
                <FileArrowUp weight="bold" className="h-8 w-8 text-ink-3" aria-hidden />
                <span className="font-medium text-ink">Drop a sample here, or choose a file</span>
                <span className="text-sm text-ink-3">
                  Any format: executables, scripts, shortcuts, documents, archives
                  {config ? ` · up to ${config.max_upload_mb} MB` : ""}
                </span>
              </label>
            )}
          </div>
        ) : (
          <div>
            <label htmlFor="path" className="mb-1.5 block text-sm font-medium text-ink-2">
              Path on the machine running mal-agent
            </label>
            <div className="flex items-center gap-2 rounded-md border border-rule bg-panel px-3 focus-within:border-tool">
              <FolderOpen weight="bold" className="h-4 w-4 text-ink-3" aria-hidden />
              <input
                id="path"
                value={path}
                onChange={(e) => setPath(e.target.value)}
                placeholder="/path/to/sample.bin"
                className="data w-full bg-transparent py-2.5 text-ink outline-none placeholder:text-ink-3"
              />
            </div>
          </div>
        )}

        <fieldset>
          <legend className="mb-2 font-sign text-lg font-bold uppercase tracking-wide text-ink">Who decides</legend>
          <div className="divide-y divide-rule overflow-hidden rounded-lg border border-rule bg-panel">
            {(config?.fusion_modes ?? (["simple", "cgef", "judge"] as FusionMode[])).map((m) => (
              <label
                key={m}
                className={`flex cursor-pointer items-start gap-3 px-4 py-3 ${mode === m ? "bg-panel-2" : "hover:bg-panel-2/60"}`}
              >
                <input
                  type="radio"
                  name="mode"
                  value={m}
                  checked={mode === m}
                  onChange={() => setMode(m)}
                  className="mt-1 accent-[var(--tool)]"
                />
                <span className="min-w-0">
                  <span className="block font-medium text-ink">
                    {FUSION[m].label}
                    {m === "simple" && <span className="ml-2 text-sm font-normal text-ink-3">default</span>}
                    {m === "judge" && <span className="ml-2 text-sm font-normal text-ink-3">research</span>}
                  </span>
                  <span className="block text-sm text-ink-2">{FUSION[m].detail}</span>
                </span>
              </label>
            ))}
          </div>
          {mode === "judge" && (
            <div className="mt-3">
              <label htmlFor="judge" className="mb-1.5 block text-sm font-medium text-ink-2">
                Adjudicator model
              </label>
              <select
                id="judge"
                value={judgeModel}
                onChange={(e) => setJudgeModel(e.target.value)}
                className="data w-full rounded-md border border-rule bg-panel px-3 py-2.5 text-ink outline-none focus:border-tool"
              >
                {(config?.judge_models ?? []).map((m) => (
                  <option key={m} value={m}>
                    {m}
                  </option>
                ))}
              </select>
              {judgeIsCloud && localOnly && (
                <div className="mt-2">
                  <Notice tone="inspect">
                    This is a cloud model and “Keep everything local” is on, so hard cases will be reported
                    as not adjudicated. Turn it off to allow derived evidence (never the file) to leave this
                    machine.
                  </Notice>
                </div>
              )}
            </div>
          )}
        </fieldset>

        <fieldset className="space-y-2.5">
          <legend className="mb-2 font-sign text-lg font-bold uppercase tracking-wide text-ink">Language model</legend>
          <label className="flex items-start gap-3 text-ink">
            <input
              type="checkbox"
              checked={narrative}
              onChange={(e) => setNarrative(e.target.checked)}
              className="mt-1 accent-[var(--tool)]"
            />
            <span>
              Write a behaviour narrative
              <span className="block text-sm text-ink-3">
                Explains the evidence in prose. Never changes the verdict. Needs Ollama or an API key.
              </span>
            </span>
          </label>
          <label className="flex items-start gap-3 text-ink">
            <input
              type="checkbox"
              checked={localOnly}
              onChange={(e) => setLocalOnly(e.target.checked)}
              className="mt-1 accent-[var(--tool)]"
            />
            <span>
              Keep everything local
              <span className="block text-sm text-ink-3">No cloud model is called, even when one is configured.</span>
            </span>
          </label>
        </fieldset>

        {error && <Notice tone="alarm">{error}</Notice>}

        <button
          type="submit"
          disabled={!ready || submitting}
          className="inline-flex items-center gap-2 rounded-md bg-tool px-5 py-3 font-sign text-base font-bold uppercase tracking-wide text-ground transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-40"
        >
          {submitting ? (
            <Spinner weight="bold" className="h-4 w-4 animate-spin" aria-hidden />
          ) : (
            <ArrowRight weight="bold" className="h-4 w-4" aria-hidden />
          )}
          {submitting ? "Sending to screening" : "Send to screening"}
        </button>
      </form>

      <aside className="min-w-0">
        <SectionHead
          title="Recent"
          aside={
            <Link to="/runs" className="text-tool hover:underline">
              Full log
            </Link>
          }
        />
        <Panel>
          {recent === null ? (
            <div className="px-4 py-6 text-sm text-ink-3">Loading…</div>
          ) : recent.length === 0 ? (
            <div className="px-4 py-6 text-sm text-ink-3">
              No files screened yet. Your runs are kept here across restarts.
            </div>
          ) : (
            <ul className="divide-y divide-rule">
              {recent.map((r) => (
                <li key={r.run_id}>
                  <Link to={`/runs/${r.run_id}`} className="block px-4 py-3 hover:bg-panel-2">
                    <div className="flex items-baseline justify-between gap-3">
                      <span className="truncate text-ink">{r.filename ?? "unnamed sample"}</span>
                      {r.status === "complete" ? (
                        <VerdictWord verdict={r.verdict} className="shrink-0 text-sm" />
                      ) : (
                        <span className={`shrink-0 text-sm ${r.status === "error" ? "text-alarm" : "text-inspect"}`}>
                          {r.status === "error" ? "Failed" : "In progress"}
                        </span>
                      )}
                    </div>
                    <div className="text-sm text-ink-3">
                      {formatLabel(r.format)} · {when(r.created_at)}
                    </div>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      </aside>
    </div>
  );
}
