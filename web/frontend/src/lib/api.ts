import type { AnalysisStatusResponse, AnalyzeOptions, CreateAnalysisResponse } from "./types";

// vite.config.ts proxies /api -> the FastAPI backend (127.0.0.1:8765) in
// dev; in production the frontend build is served by the same backend, so
// relative paths work unmodified either way.
const API_BASE = "/api";

export async function createAnalysis(opts: AnalyzeOptions): Promise<CreateAnalysisResponse> {
  const form = new FormData();
  if (opts.file) {
    form.set("file", opts.file);
  } else if (opts.path) {
    form.set("path", opts.path);
  } else {
    throw new Error("either a file or a path is required");
  }
  form.set("fusion_mode", opts.fusionMode);
  form.set("enable_models", String(opts.enableModels));
  form.set("no_cloud", String(opts.noCloud));

  const resp = await fetch(`${API_BASE}/analyses`, { method: "POST", body: form });
  if (!resp.ok) {
    const body = await resp.json().catch(() => ({}));
    throw new Error(body.detail ?? `analysis request failed (${resp.status})`);
  }
  return resp.json();
}

export async function getAnalysis(runId: string): Promise<AnalysisStatusResponse> {
  const resp = await fetch(`${API_BASE}/analyses/${runId}`);
  if (!resp.ok) {
    throw new Error(`failed to fetch run status (${resp.status})`);
  }
  return resp.json();
}

export function reportUrl(runId: string, format: "txt" | "html" | "md"): string {
  return `${API_BASE}/analyses/${runId}/report.${format}`;
}

/** Subscribes to the SSE progress stream. Returns an unsubscribe function. */
export function subscribeToProgress(
  runId: string,
  onLine: (line: string) => void,
  onDone: () => void,
): () => void {
  const source = new EventSource(`${API_BASE}/analyses/${runId}/events`);
  source.onmessage = (event) => onLine(event.data);
  source.addEventListener("done", () => {
    onDone();
    source.close();
  });
  source.onerror = () => {
    // The backend closes the stream itself once the run reaches a terminal
    // state (see the "done" event above); a connection error here means
    // the server/network genuinely dropped, not normal completion.
    source.close();
    onDone();
  };
  return () => source.close();
}
