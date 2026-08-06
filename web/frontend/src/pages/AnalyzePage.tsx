import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { ArrowRight, FileArrowUp, Spinner } from "@phosphor-icons/react";
import { createAnalysis, subscribeToProgress } from "../lib/api";

type Mode = "path" | "upload";

export function AnalyzePage() {
  const navigate = useNavigate();
  const [mode, setMode] = useState<Mode>("path");
  const [path, setPath] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [fusionMode, setFusionMode] = useState<"simple" | "cgef">("simple");
  const [enableModels, setEnableModels] = useState(false);
  const [noCloud, setNoCloud] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [progress, setProgress] = useState<string[]>([]);
  const unsubscribeRef = useRef<(() => void) | null>(null);

  useEffect(() => () => unsubscribeRef.current?.(), []);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setProgress([]);
    setSubmitting(true);
    try {
      const created = await createAnalysis({
        path: mode === "path" ? path : undefined,
        file: mode === "upload" ? (file ?? undefined) : undefined,
        fusionMode,
        enableModels,
        noCloud,
      });
      unsubscribeRef.current = subscribeToProgress(
        created.run_id,
        (line) => setProgress((prev) => [...prev, line]),
        () => navigate(`/report/${created.run_id}`),
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to start analysis.");
      setSubmitting(false);
    }
  }

  const canSubmit = mode === "path" ? path.trim().length > 0 : file !== null;

  return (
    <div className="mx-auto max-w-2xl px-6 py-10">
      <h1 className="text-xl font-semibold text-zinc-900 dark:text-zinc-100">Analyze a sample</h1>
      <p className="mt-1 text-sm text-zinc-600 dark:text-zinc-400">
        Runs the full mal-agent pipeline: triage, static analysis, ATT&amp;CK aggregation, and the
        EMBER classifier decision. Ghidra-backed runs can take several minutes.
      </p>

      <form onSubmit={handleSubmit} className="mt-6 space-y-5">
        <div className="flex gap-1 rounded-lg border border-zinc-200 p-1 dark:border-zinc-800">
          {(["path", "upload"] as const).map((m) => (
            <button
              key={m}
              type="button"
              onClick={() => setMode(m)}
              className={`flex-1 rounded-md px-3 py-1.5 text-sm font-medium transition-colors ${
                mode === m
                  ? "bg-zinc-900 text-white dark:bg-zinc-100 dark:text-zinc-900"
                  : "text-zinc-600 hover:bg-zinc-100 dark:text-zinc-400 dark:hover:bg-zinc-900"
              }`}
            >
              {m === "path" ? "Server-local path" : "Upload a file"}
            </button>
          ))}
        </div>

        {mode === "path" ? (
          <div>
            <label htmlFor="path" className="block text-sm font-medium text-zinc-700 dark:text-zinc-300">
              Sample path
            </label>
            <input
              id="path"
              type="text"
              value={path}
              onChange={(e) => setPath(e.target.value)}
              placeholder="D:\samples\suspicious.bin"
              className="mt-1.5 w-full rounded-md border border-zinc-300 bg-white px-3 py-2 text-sm text-zinc-900 placeholder:text-zinc-400 focus:border-accent focus:outline-none focus:ring-1 focus:ring-accent dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-100"
            />
            <p className="mt-1 text-xs text-zinc-500 dark:text-zinc-500">
              A path on the machine running the backend, not your browser.
            </p>
          </div>
        ) : (
          <div>
            <label htmlFor="file" className="block text-sm font-medium text-zinc-700 dark:text-zinc-300">
              Sample file
            </label>
            <label
              htmlFor="file"
              className="mt-1.5 flex cursor-pointer items-center justify-center gap-2 rounded-md border border-dashed border-zinc-300 px-3 py-6 text-sm text-zinc-500 hover:border-accent hover:text-accent dark:border-zinc-700 dark:text-zinc-500"
            >
              <FileArrowUp weight="regular" className="h-5 w-5" aria-hidden />
              {file ? file.name : "Choose a file"}
            </label>
            <input
              id="file"
              type="file"
              className="sr-only"
              onChange={(e) => setFile(e.target.files?.[0] ?? null)}
            />
          </div>
        )}

        <div>
          <span className="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Fusion mode</span>
          <div className="mt-1.5 flex gap-1 rounded-lg border border-zinc-200 p-1 dark:border-zinc-800">
            {(
              [
                ["simple", "Simple (default)"],
                ["cgef", "CGEF (opt-in)"],
              ] as const
            ).map(([value, label]) => (
              <button
                key={value}
                type="button"
                onClick={() => setFusionMode(value)}
                className={`flex-1 rounded-md px-3 py-1.5 text-sm font-medium transition-colors ${
                  fusionMode === value
                    ? "bg-zinc-900 text-white dark:bg-zinc-100 dark:text-zinc-900"
                    : "text-zinc-600 hover:bg-zinc-100 dark:text-zinc-400 dark:hover:bg-zinc-900"
                }`}
              >
                {label}
              </button>
            ))}
          </div>
        </div>

        <div className="space-y-2">
          <label className="flex items-center gap-2 text-sm text-zinc-700 dark:text-zinc-300">
            <input
              type="checkbox"
              checked={enableModels}
              onChange={(e) => setEnableModels(e.target.checked)}
              className="h-4 w-4 rounded border-zinc-300 text-accent focus:ring-accent dark:border-zinc-700"
            />
            Enable local/cloud model narrative (needs Ollama or API keys)
          </label>
          <label className="flex items-center gap-2 text-sm text-zinc-700 dark:text-zinc-300">
            <input
              type="checkbox"
              checked={noCloud}
              onChange={(e) => setNoCloud(e.target.checked)}
              className="h-4 w-4 rounded border-zinc-300 text-accent focus:ring-accent dark:border-zinc-700"
            />
            Disable cloud escalation (local only)
          </label>
        </div>

        {error && (
          <p className="rounded-md bg-red-50 px-3 py-2 text-sm text-red-800 dark:bg-red-950/50 dark:text-red-300">
            {error}
          </p>
        )}

        <button
          type="submit"
          disabled={!canSubmit || submitting}
          className="flex w-full items-center justify-center gap-2 rounded-md bg-accent px-4 py-2.5 text-sm font-semibold text-white transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-40"
        >
          {submitting ? (
            <Spinner weight="bold" className="h-4 w-4 animate-spin" aria-hidden />
          ) : (
            <ArrowRight weight="bold" className="h-4 w-4" aria-hidden />
          )}
          {submitting ? "Analyzing" : "Run analysis"}
        </button>
      </form>

      {progress.length > 0 && (
        <div className="mt-6 rounded-lg border border-zinc-200 bg-zinc-50 p-4 dark:border-zinc-800 dark:bg-zinc-950">
          <h2 className="text-sm font-medium text-zinc-700 dark:text-zinc-300">Progress</h2>
          <ul className="mt-2 max-h-64 space-y-1 overflow-y-auto font-mono text-xs text-zinc-600 dark:text-zinc-400">
            {progress.map((line, i) => (
              <li key={i}>{line}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
