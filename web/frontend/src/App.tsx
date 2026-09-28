import { useEffect, useState } from "react";
import { BrowserRouter, Navigate, NavLink, Route, Routes, useParams } from "react-router-dom";
import { Desktop, Moon, Sun, Tray, ListBullets } from "@phosphor-icons/react";
import { IntakePage } from "./pages/IntakePage";
import { LogPage } from "./pages/LogPage";
import { ReportPage } from "./pages/ReportPage";

type Theme = "system" | "dark" | "light";

function readTheme(): Theme {
  try {
    const t = localStorage.getItem("malagent.theme");
    return t === "dark" || t === "light" ? t : "system";
  } catch {
    return "system";
  }
}

function useTheme(): [Theme, (t: Theme) => void] {
  const [theme, setTheme] = useState<Theme>(readTheme);
  useEffect(() => {
    const root = document.documentElement;
    const apply = () => {
      const dark =
        theme === "dark" ||
        (theme === "system" && !window.matchMedia("(prefers-color-scheme: light)").matches);
      root.dataset.theme = dark ? "dark" : "light";
    };
    apply();
    try {
      localStorage.setItem("malagent.theme", theme);
    } catch {
      /* private mode: theme just won't persist */
    }
    const mq = window.matchMedia("(prefers-color-scheme: light)");
    mq.addEventListener("change", apply);
    return () => mq.removeEventListener("change", apply);
  }, [theme]);
  return [theme, setTheme];
}

/** The lane mark: a bag on a belt passing under the scanner arch. */
function Mark({ className = "" }: { className?: string }) {
  return (
    <svg viewBox="0 0 32 32" className={className} aria-hidden="true">
      <path d="M6 22V11a10 10 0 0 1 20 0v11" fill="none" stroke="currentColor" strokeWidth="2.4" />
      <rect x="11" y="15" width="10" height="7" rx="1.5" fill="var(--sample)" />
      <path d="M3 25h26" stroke="var(--tool)" strokeWidth="2.4" strokeLinecap="round" />
      <path d="M16 6v4" stroke="var(--tool)" strokeWidth="2" strokeLinecap="round" />
    </svg>
  );
}

function NavItem({ to, icon: Icon, label }: { to: string; icon: typeof Tray; label: string }) {
  return (
    <NavLink
      to={to}
      end={to === "/"}
      className={({ isActive }) =>
        `flex items-center gap-2.5 rounded-md px-3 py-2 font-sign text-[15px] font-semibold uppercase tracking-wide transition-colors ${
          isActive ? "bg-panel-2 text-ink" : "text-ink-3 hover:bg-panel-2 hover:text-ink-2"
        }`
      }
    >
      <Icon weight="bold" className="h-4 w-4" aria-hidden />
      {label}
    </NavLink>
  );
}

function ThemeSwitch({ theme, setTheme }: { theme: Theme; setTheme: (t: Theme) => void }) {
  const opts: { v: Theme; icon: typeof Sun; label: string }[] = [
    { v: "dark", icon: Moon, label: "Console (dark)" },
    { v: "light", icon: Sun, label: "Slip (light)" },
    { v: "system", icon: Desktop, label: "Follow system" },
  ];
  return (
    <div role="radiogroup" aria-label="Theme" className="flex gap-1 rounded-md bg-panel-2 p-1">
      {opts.map(({ v, icon: Icon, label }) => (
        <button
          key={v}
          role="radio"
          aria-checked={theme === v}
          title={label}
          onClick={() => setTheme(v)}
          className={`grid h-7 flex-1 place-items-center rounded ${
            theme === v ? "bg-panel text-ink shadow-[0_1px_2px_rgb(0_0_0/0.25)]" : "text-ink-3 hover:text-ink-2"
          }`}
        >
          <Icon weight="bold" className="h-3.5 w-3.5" aria-hidden />
          <span className="sr-only">{label}</span>
        </button>
      ))}
    </div>
  );
}

function LegacyReportRedirect() {
  const { runId } = useParams();
  return <Navigate to={`/runs/${runId}`} replace />;
}

export default function App() {
  const [theme, setTheme] = useTheme();
  return (
    <BrowserRouter>
      <div className="min-h-dvh lg:grid lg:grid-cols-[220px_1fr]">
        <aside className="flex items-center justify-between gap-4 border-b border-rule bg-panel px-4 py-3 lg:sticky lg:top-0 lg:h-dvh lg:flex-col lg:items-stretch lg:justify-start lg:border-r lg:border-b-0 lg:px-4 lg:py-5">
          <div className="flex items-center gap-2.5 lg:mb-8 lg:px-2">
            <Mark className="h-7 w-7 text-ink" />
            <div className="leading-tight">
              <div className="font-sign text-xl font-bold tracking-wide text-ink">mal-agent</div>
              <div className="hidden text-xs text-ink-3 lg:block">Static triage, evidence first</div>
            </div>
          </div>
          <nav className="flex gap-1 lg:flex-col" aria-label="Main">
            <NavItem to="/" icon={Tray} label="Intake" />
            <NavItem to="/runs" icon={ListBullets} label="Run log" />
          </nav>
          <div className="hidden lg:mt-auto lg:block">
            <ThemeSwitch theme={theme} setTheme={setTheme} />
          </div>
        </aside>
        <main className="min-w-0">
          <Routes>
            <Route path="/" element={<IntakePage />} />
            <Route path="/runs" element={<LogPage />} />
            <Route path="/runs/:runId" element={<ReportPage />} />
            <Route path="/report/:runId" element={<LegacyReportRedirect />} />
          </Routes>
          <div className="border-t border-rule px-6 py-4 lg:hidden">
            <ThemeSwitch theme={theme} setTheme={setTheme} />
          </div>
        </main>
      </div>
    </BrowserRouter>
  );
}
