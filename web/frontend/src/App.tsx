import { BrowserRouter, Link, Route, Routes } from "react-router-dom";
import { ShieldCheck } from "@phosphor-icons/react";
import { AnalyzePage } from "./pages/AnalyzePage";
import { ReportPage } from "./pages/ReportPage";

function Header() {
  return (
    <header className="border-b border-zinc-200 dark:border-zinc-800">
      <div className="mx-auto flex max-w-4xl items-center gap-2 px-6 py-3">
        <Link to="/" className="flex items-center gap-2">
          <ShieldCheck weight="fill" className="h-5 w-5 text-accent" aria-hidden />
          <span className="text-sm font-semibold tracking-tight text-zinc-900 dark:text-zinc-100">
            mal-agent
          </span>
        </Link>
      </div>
    </header>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <div className="min-h-dvh">
        <Header />
        <Routes>
          <Route path="/" element={<AnalyzePage />} />
          <Route path="/report/:runId" element={<ReportPage />} />
        </Routes>
      </div>
    </BrowserRouter>
  );
}
