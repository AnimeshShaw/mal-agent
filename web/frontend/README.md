# mal-agent web frontend

React + Vite + TypeScript + Tailwind v4 frontend for mal-agent's local web
UI (see `docs/TODO.md` Phase 8, and the top-level `README.md`'s "Web UI"
section for the full picture). Talks to the FastAPI backend in
`web/backend/malagent_web/` via `src/lib/api.ts`.

## Develop

```bash
npm install
npm run dev
```

`vite.config.ts` proxies `/api` to `http://127.0.0.1:8765` in dev, so run
the backend separately (`mal-agent web`) alongside `npm run dev` for a
hot-reloading frontend against a live backend.

## Build

```bash
npm run build
```

Outputs to `dist/`, which `mal-agent web` serves directly (see
`web/backend/malagent_web/app.py`) — no separate frontend server needed
in production use.

## Layout

- `src/pages/` — `AnalyzePage` (submission form + live SSE progress),
  `ReportPage` (verdict, per-tool cards, narrative, evidence)
- `src/components/` — `VerdictBanner`, `ToolCard`, `NarrativePanel`,
  `EvidencePanel`
- `src/lib/` — typed API client (`api.ts`) and response shapes (`types.ts`)
  mirroring `malagent.reporter.build_tool_report()`'s JSON output
