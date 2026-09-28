import type { AnalyzeOptions, AppConfig, RunDetail, RunSummary } from "./types";

// Relative paths: vite.config.ts proxies /api in dev; in production the
// backend serves this build from the same origin.
const API = "/api";

function tokenHeaders(): HeadersInit {
  try {
    const t = localStorage.getItem("malagent.token");
    return t ? { "X-Mal-Agent-Token": t } : {};
  } catch {
    return {};
  }
}

function tokenQuery(): string {
  try {
    const t = localStorage.getItem("malagent.token");
    return t ? `?token=${encodeURIComponent(t)}` : "";
  } catch {
    return "";
  }
}

async function json<T>(resp: Response, what: string): Promise<T> {
  if (!resp.ok) {
    const body = await resp.json().catch(() => ({}));
    throw new Error(body.detail ?? `${what} failed (HTTP ${resp.status})`);
  }
  return resp.json();
}

export async function getConfig(): Promise<AppConfig> {
  return json(await fetch(`${API}/config`, { headers: tokenHeaders() }), "Loading settings");
}

export async function listRuns(): Promise<RunSummary[]> {
  const body = await json<{ runs: RunSummary[] }>(
    await fetch(`${API}/analyses`, { headers: tokenHeaders() }),
    "Loading the run log",
  );
  return body.runs;
}

export async function getRun(runId: string): Promise<RunDetail> {
  return json(await fetch(`${API}/analyses/${runId}`, { headers: tokenHeaders() }), "Loading the run");
}

export async function createAnalysis(opts: AnalyzeOptions): Promise<{ run_id: string }> {
  const form = new FormData();
  if (opts.file) form.set("file", opts.file);
  else if (opts.path) form.set("path", opts.path);
  else throw new Error("Choose a file or enter a server path first.");
  form.set("fusion_mode", opts.fusionMode);
  if (opts.fusionMode === "judge" && opts.judgeModel) form.set("judge_model", opts.judgeModel);
  form.set("enable_models", String(opts.enableModels));
  form.set("no_cloud", String(opts.noCloud));
  return json(
    await fetch(`${API}/analyses`, { method: "POST", body: form, headers: tokenHeaders() }),
    "Starting the analysis",
  );
}

export function reportUrl(runId: string, format: "txt" | "html" | "md"): string {
  return `${API}/analyses/${runId}/report.${format}${tokenQuery()}`;
}

/** Live progress lines over SSE. Returns an unsubscribe function. */
export function subscribeToProgress(
  runId: string,
  onLine: (line: string) => void,
  onDone: (status: string) => void,
): () => void {
  const source = new EventSource(`${API}/analyses/${runId}/events${tokenQuery()}`);
  source.onmessage = (e) => onLine(e.data);
  source.addEventListener("done", (e) => {
    onDone((e as MessageEvent).data);
    source.close();
  });
  source.onerror = () => {
    source.close();
    onDone("disconnected");
  };
  return () => source.close();
}
