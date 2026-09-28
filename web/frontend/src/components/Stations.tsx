import { useState } from "react";
import { CaretDown } from "@phosphor-icons/react";
import type { ToolReportEntry, ToolStatus } from "../lib/types";
import { DIRECTION, toolName } from "../lib/vocab";
import { Swatch } from "./ui";

const STATUS: Record<ToolStatus, { label: string; dot: string; text: string }> = {
  ok: { label: "Ran", dot: "bg-clear", text: "text-clear" },
  partial: { label: "Partial", dot: "bg-inspect", text: "text-inspect" },
  skipped: { label: "Skipped", dot: "bg-idle", text: "text-ink-3" },
  error: { label: "Error", dot: "bg-alarm", text: "text-alarm" },
};

function StationRow({ t }: { t: ToolReportEntry }) {
  const [open, setOpen] = useState(false);
  const s = STATUS[t.status];
  const hasBody = !!(t.reason || t.notes || t.unresolved.length || t.findings.length || t.purpose);
  return (
    <li>
      <button
        type="button"
        onClick={() => hasBody && setOpen(!open)}
        aria-expanded={open}
        className="flex w-full items-center gap-3 px-4 py-2 text-left hover:bg-panel-2"
      >
        <span aria-hidden className={`h-2 w-2 shrink-0 rounded-full ${s.dot}`} />
        <span className="min-w-0 flex-1 truncate text-ink">{toolName(t.tool)}</span>
        {t.findings.length > 0 && <span className="text-sm text-ink-3">{t.findings.length}</span>}
        <span className={`w-16 text-right font-sign text-[13px] font-semibold uppercase tracking-wide ${s.text}`}>{s.label}</span>
        <CaretDown
          weight="bold"
          className={`h-3.5 w-3.5 text-ink-3 transition-transform ${open ? "rotate-180" : ""} ${hasBody ? "" : "invisible"}`}
          aria-hidden
        />
      </button>
      {open && (
        <div className="space-y-2 px-4 pb-3 pl-9 text-sm">
          {t.purpose && <p className="text-ink-3">{t.purpose}</p>}
          {t.reason && <p className="text-ink-2">{t.reason}</p>}
          {t.notes && <p className="data text-ink-3">{t.notes}</p>}
          {t.unresolved.map((u, i) => (
            <p key={i} className="text-inspect">
              {u}
            </p>
          ))}
          {t.findings.length > 0 && (
            <ul className="space-y-1">
              {t.findings.map((f, i) => (
                <li key={i} className="flex gap-2">
                  <Swatch tone={DIRECTION[f.direction].tone} className="mt-[6px]" />
                  <span className="text-ink-2">{f.claim}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </li>
  );
}

/** Every tool, whether it ran, was skipped or failed: never hidden. */
export function Stations({ tools }: { tools: ToolReportEntry[] }) {
  const ran = tools.filter((t) => t.status === "ok").length;
  const failed = tools.filter((t) => t.status === "error").length;
  return (
    <div>
      <div className="flex gap-4 border-b border-rule px-4 py-3 text-sm text-ink-2">
        <span>
          <span className="text-clear">{ran}</span> ran
        </span>
        <span>
          <span className="text-ink-3">{tools.length - ran - failed}</span> skipped
        </span>
        <span>
          <span className={failed ? "text-alarm" : "text-ink-3"}>{failed}</span> failed
        </span>
      </div>
      <ul className="divide-y divide-rule">
        {tools.map((t) => (
          <StationRow key={t.tool} t={t} />
        ))}
      </ul>
    </div>
  );
}
