import { useState } from "react";
import { CaretDown } from "@phosphor-icons/react";
import type { IOC, Verdict } from "../lib/types";

function Collapsible({ title, count, children }: { title: string; count: number; children: React.ReactNode }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="rounded-lg border border-zinc-200 bg-white dark:border-zinc-800 dark:bg-zinc-900">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center justify-between px-4 py-3 text-left"
        aria-expanded={open}
      >
        <span className="font-medium text-zinc-900 dark:text-zinc-100">
          {title} <span className="text-zinc-400 dark:text-zinc-500">({count})</span>
        </span>
        <CaretDown
          weight="bold"
          className={`h-4 w-4 text-zinc-400 transition-transform ${open ? "rotate-180" : ""}`}
          aria-hidden
        />
      </button>
      {open && <div className="border-t border-zinc-200 px-4 py-3 dark:border-zinc-800">{children}</div>}
    </div>
  );
}

function IocTable({ iocs }: { iocs: IOC[] }) {
  if (iocs.length === 0) {
    return <p className="text-sm text-zinc-500 dark:text-zinc-500">No IOCs extracted.</p>;
  }
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-sm">
        <thead>
          <tr className="border-b border-zinc-200 text-xs uppercase tracking-wide text-zinc-500 dark:border-zinc-800 dark:text-zinc-500">
            <th className="py-1.5 pr-4 font-medium">Type</th>
            <th className="py-1.5 font-medium">Value</th>
          </tr>
        </thead>
        <tbody>
          {iocs.map((ioc, i) => (
            <tr key={i} className="border-b border-zinc-100 last:border-0 dark:border-zinc-900">
              <td className="py-1.5 pr-4 text-zinc-500 dark:text-zinc-500">{ioc.type}</td>
              <td className="py-1.5 font-mono text-xs text-zinc-800 dark:text-zinc-200 break-all">
                {ioc.value}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function EvidencePanel({ verdict }: { verdict: Verdict }) {
  return (
    <div className="space-y-3">
      <Collapsible title="IOCs" count={verdict.iocs.length}>
        <IocTable iocs={verdict.iocs} />
      </Collapsible>

      <Collapsible title="Generated YARA rules" count={verdict.yara_rules.length}>
        {verdict.yara_rules.length === 0 ? (
          <p className="text-sm text-zinc-500 dark:text-zinc-500">No rules generated for this sample.</p>
        ) : (
          <div className="space-y-3">
            {verdict.yara_rules.map((rule, i) => (
              <pre
                key={i}
                className="overflow-x-auto rounded bg-zinc-100 p-3 font-mono text-xs text-zinc-800 dark:bg-zinc-950 dark:text-zinc-300"
              >
                {rule}
              </pre>
            ))}
          </div>
        )}
      </Collapsible>

      {verdict.unresolved.length > 0 && (
        <Collapsible title="What this analysis could not determine" count={verdict.unresolved.length}>
          <ul className="space-y-1.5">
            {verdict.unresolved.map((u, i) => (
              <li key={i} className="text-sm text-zinc-600 dark:text-zinc-400">
                {u}
              </li>
            ))}
          </ul>
        </Collapsible>
      )}
    </div>
  );
}
