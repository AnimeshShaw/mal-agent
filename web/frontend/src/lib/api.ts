import type { AnalyzeOptions, AppConfig, RunDetail, RunSummary } from "./types";

// Relative paths: vite.config.ts proxies /api in dev; in production the
// backend serves this build from the same origin.
const API = "/api";

function token(): string | null {
  try {
    return localStorage.getItem("malagent.token");
  } catch {
    return null;
  }
}

function tokenHeaders(): HeadersInit {
  const t = token();
  return t ? { "X-Mal-Agent-Token": t } : {};
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

/**
 * Fetches a rendered report with the real auth header (a plain <a href>
 * can't set one) and hands back a same-origin object URL to open or
 * download it from — the bearer token itself never appears in a URL, so it
 * can't land in browser history or a proxy's access log.
 * Caller owns the URL and should revokeObjectURL it when done with it.
 */
export async function fetchReportUrl(runId: string, format: "txt" | "html" | "md"): Promise<string> {
  const resp = await fetch(`${API}/analyses/${runId}/report.${format}`, { headers: tokenHeaders() });
  if (!resp.ok) throw new Error(`could not load the ${format} report (HTTP ${resp.status})`);
  return URL.createObjectURL(await resp.blob());
}

/**
 * Returns a URL for the HTML report meant to be *navigated to* (window.open
 * / location), not fetched into a blob. A blob: URL carries no HTTP headers,
 * which was silently discarding the backend's Content-Security-Policy
 * header -- a defense-in-depth backstop against an escaping bug in
 * reporter._e, since this report embeds strings extracted straight out of
 * the analyzed sample. Mints a short-lived, single-use, run-scoped ticket
 * (same pattern as subscribeToProgress above) so a real navigation, which
 * can't set a custom header, doesn't need the long-lived real token either.
 */
export async function reportHtmlUrl(runId: string): Promise<string> {
  const t = token();
  if (!t) return `${API}/analyses/${runId}/report.html`;
  const resp = await fetch(`${API}/analyses/${runId}/report/ticket`, {
    method: "POST",
    headers: tokenHeaders(),
  });
  if (!resp.ok) throw new Error(`could not open the report (HTTP ${resp.status})`);
  const { ticket } = await resp.json();
  return `${API}/analyses/${runId}/report.html?ticket=${encodeURIComponent(ticket)}`;
}

/**
 * Live progress lines over SSE. EventSource can't send a custom header, so
 * when a token is configured this first exchanges it (via a normal,
 * header-authenticated POST) for a short-lived, single-use, run-scoped
 * ticket and connects with that instead — see the backend's tickets.py.
 * Returns an unsubscribe function.
 */
export function subscribeToProgress(
  runId: string,
  onLine: (line: string) => void,
  onDone: (status: string) => void,
): () => void {
  let source: EventSource | null = null;
  let cancelled = false;

  async function connect() {
    let qs = "";
    const t = token();
    if (t) {
      const resp = await fetch(`${API}/analyses/${runId}/events/ticket`, {
        method: "POST",
        headers: tokenHeaders(),
      });
      if (!resp.ok) {
        onDone("disconnected");
        return;
      }
      const { ticket } = await resp.json();
      qs = `?ticket=${encodeURIComponent(ticket)}`;
    }
    if (cancelled) return;
    source = new EventSource(`${API}/analyses/${runId}/events${qs}`);
    source.onmessage = (e) => onLine(e.data);
    source.addEventListener("done", (e) => {
      onDone((e as MessageEvent).data);
      source?.close();
    });
    source.onerror = () => {
      source?.close();
      onDone("disconnected");
    };
  }
  connect();

  return () => {
    cancelled = true;
    source?.close();
  };
}
