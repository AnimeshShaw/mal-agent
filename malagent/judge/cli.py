"""`mal-agent research build-bundles | judge-run | judge-report`."""
from __future__ import annotations
import argparse
import os
import sys
from pathlib import Path

JUDGE_CMDS = {"build-bundles", "judge-run", "judge-report", "judge-claims"}


def _model_slug(spec: str) -> str:
    return spec.replace(":", "_").replace("/", "_")


def main(argv: list[str]) -> int:
    cmd, rest = argv[0], argv[1:]
    if cmd == "build-bundles":
        from .collect import build_bundles
        p = argparse.ArgumentParser(prog="mal-agent research build-bundles")
        p.add_argument("manifest")
        p.add_argument("--out", default="bundles/v2")
        p.add_argument("--workers", type=int, default=4)
        p.add_argument("--limit", type=int, default=None)
        p.add_argument("--capa-timeout", type=int, default=180,
                       help="per-sample capa timeout in seconds (default 180)")
        p.add_argument("--max-pool-restarts", type=int, default=3,
                       help="how many times to restart the worker pool after a crash "
                            "(e.g. out-of-memory) before giving up on remaining samples "
                            "(default 3; each restart resumes only what's left)")
        a = p.parse_args(rest)
        os.environ["MAL_AGENT_CAPA_TIMEOUT"] = str(a.capa_timeout)
        os.environ.pop("KNOWN_GOOD_HASHES_PATH", None)  # never let the allowlist decide
        result = build_bundles(a.manifest, a.out, workers=a.workers, limit=a.limit,
                               max_pool_restarts=a.max_pool_restarts)
        print(result)
        if result["not_built"]:
            print(f"[build-bundles] {result['not_built']} sample(s) not built -- re-run this "
                  f"same command to resume (a non-zero exit here is deliberate: a caller "
                  f"chaining judge-run after this must not silently score a partial dataset).",
                  file=sys.stderr)
            return 1
        return 0

    if cmd == "judge-run":
        from .bundle import load_bundles
        from .cache import CachedProvider
        from .experiments import (adversarial_jobs, main_jobs, reliability_jobs, run_jobs, select)
        from .providers import make_provider
        p = argparse.ArgumentParser(prog="mal-agent research judge-run")
        p.add_argument("--bundles", default="bundles/v2")
        p.add_argument("--model", required=True, help="e.g. ollama:qwen3:8b, anthropic:claude-sonnet-4-6")
        p.add_argument("--exp", required=True, choices=["main", "adversarial", "reliability"])
        p.add_argument("--split", default="test", help="dev | test | all")
        p.add_argument("--limit", type=int, default=None)
        p.add_argument("--routed-only", action="store_true")
        p.add_argument("--out", default="research_out")
        p.add_argument("--repeats", type=int, default=5)
        p.add_argument("--orders", type=int, default=3)
        a = p.parse_args(rest)
        bundles = load_bundles(a.bundles)
        sel = select(bundles, split=None if a.split == "all" else a.split,
                     routed_only=a.routed_only, limit=a.limit)
        prov = CachedProvider(make_provider(a.model), Path(a.out) / "llm_cache")
        jobs = {"main": lambda: main_jobs(sel),
                "adversarial": lambda: adversarial_jobs(sel),
                "reliability": lambda: reliability_jobs(sel, a.repeats, a.orders)}[a.exp]()
        out = Path(a.out) / a.exp / f"{_model_slug(a.model)}.jsonl"
        print(f"[judge-run] {a.exp} on {len(sel)} bundle(s), {len(jobs)} job(s) -> {out}")
        run_jobs(jobs, prov, out, a.exp)
        return 0

    if cmd == "judge-claims":
        from .bundle import load_bundles
        from .cache import CachedProvider
        from .claims import annotation_rows, export_annotation_csv, run_claims
        from .experiments import load_results, select
        from .providers import make_provider
        p = argparse.ArgumentParser(prog="mal-agent research judge-claims")
        p.add_argument("--bundles", default="bundles/v2")
        p.add_argument("--narrator", required=True, help="model writing the narratives")
        p.add_argument("--judge", required=True, help="model verifying each claim")
        p.add_argument("--split", default="test")
        p.add_argument("--limit", type=int, default=60)
        p.add_argument("--out", default="research_out")
        p.add_argument("--annotate", type=int, default=300,
                       help="also export this many random claims for human labelling")
        a = p.parse_args(rest)
        bundles = load_bundles(a.bundles)
        sel = select(bundles, split=None if a.split == "all" else a.split, limit=a.limit)
        cache = Path(a.out) / "llm_cache"
        narrator = CachedProvider(make_provider(a.narrator), cache)
        judge = CachedProvider(make_provider(a.judge), cache)
        out = Path(a.out) / "claims" / f"{_model_slug(a.narrator)}__{_model_slug(a.judge)}.jsonl"
        run_claims(sel, narrator, judge, out)
        rows = annotation_rows(load_results(out), {b["sha256"]: b for b in bundles}, k=a.annotate)
        ann = export_annotation_csv(rows, out.with_suffix(".annotate.csv"))
        print(f"[judge-claims] wrote {out} and {ann}")
        return 0

    if cmd == "judge-report":
        from .analysis import build_report, write_report
        from .bundle import load_bundles
        from .experiments import load_results
        p = argparse.ArgumentParser(prog="mal-agent research judge-report")
        p.add_argument("--bundles", default="bundles/v2")
        p.add_argument("--results", default="research_out")
        p.add_argument("--split", default="test")
        p.add_argument("--out", default="research_out/report")
        a = p.parse_args(rest)
        bundles = load_bundles(a.bundles)
        by_model: dict[str, list] = {}
        for exp in ("main", "adversarial", "reliability"):
            for f in sorted((Path(a.results) / exp).glob("*.jsonl")):
                by_model.setdefault(f.stem, []).extend(load_results(f))
        rep = build_report(bundles, by_model, split=None if a.split == "all" else a.split)
        from .analysis import claims_summary
        rep["claims"] = {f.stem: claims_summary(load_results(f))
                         for f in sorted((Path(a.results) / "claims").glob("*.jsonl"))}
        path = write_report(rep, a.out)
        print(f"[judge-report] wrote {path}")
        return 0

    print(f"unknown judge command {cmd!r}", file=sys.stderr)
    return 2
