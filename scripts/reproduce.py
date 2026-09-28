#!/usr/bin/env python3
"""One entry point for reproducing mal-agent's results, on any OS.

Three modes, cheapest first:

    python scripts/reproduce.py check
        Prints what's installed/configured on this machine and what each
        missing piece would cost you (nothing is run).

    python scripts/reproduce.py smoke
        ~10 seconds. Synthesizes a handful of SAFE, synthetic multi-format
        files (no network, no real malware, no Ollama needed) and runs the
        actual `mal-agent` pipeline on each one end to end. This proves the
        tool itself works on your machine -- it does not reproduce the
        paper's numbers (those need the private dataset + local LLMs below).

    python scripts/reproduce.py paper
        Hours, real hardware, real local LLMs. Reproduces the four
        experimental axes behind paper/paper_draft.md from a manifest you
        provide (§3 "Dataset" in docs/RESEARCH.md explains how the
        project's own manifest was built and why it isn't shipped in the
        repo: it's real, if inert, malware). Thin, cross-platform wrapper
        around the exact same `mal-agent research <subcommand>` calls
        scripts/run_research_jobs.ps1 uses on the Windows machine the paper's
        numbers were measured on -- read that file's comments for the
        original run's real timings and the two resilience incidents that
        shaped how this wrapper behaves (never proceed past a failed
        critical step; never touch a path a live worker owns).

Every step below prints what it's doing and why *before* running it -- this
is meant to be readable by someone who has never seen this repo before, not
just executable.
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _banner(title: str) -> None:
    print(f"\n{'=' * 70}\n{title}\n{'=' * 70}")


def _run(cmd: list[str], *, critical: bool = False, cwd: Path = REPO_ROOT) -> int:
    """Run a subprocess, streaming its output live, exactly like a human
    watching a terminal would -- no captured/buffered surprises."""
    print(f"$ {' '.join(cmd)}")
    t0 = time.time()
    proc = subprocess.run(cmd, cwd=cwd)
    dt = time.time() - t0
    status = "ok" if proc.returncode == 0 else f"FAILED (exit {proc.returncode})"
    print(f"  -> {status} in {dt:.1f}s")
    if critical and proc.returncode != 0:
        print(
            f"\nSTOPPING: '{' '.join(cmd)}' is a critical step and did not succeed.\n"
            "Refusing to proceed to the next phase against data that was never\n"
            "confirmed complete -- this is not a style choice, it is the direct fix\n"
            "for a real incident (see docs/RESEARCH.md §6): an earlier version of\n"
            "this pipeline silently scored experiments against 267 of 1,504 intended\n"
            "samples after an unchecked worker-pool crash. Fix the error above and\n"
            "re-run this same command; every step here is idempotent/resumable.",
            file=sys.stderr,
        )
        sys.exit(proc.returncode)
    return proc.returncode


# --------------------------------------------------------------------------- check
def cmd_check(_args: argparse.Namespace) -> int:
    _banner("mal-agent doctor -- deterministic tool availability")
    _run([sys.executable, "-m", "malagent.cli", "doctor"])

    _banner("Extra checks for reproducing the *paper's* numbers specifically")
    checks = []

    ember = os.environ.get("EMBER_MODEL_PATH")
    checks.append((
        "EMBER_MODEL_PATH set and file exists",
        bool(ember and Path(ember).is_file()),
        "export/set EMBER_MODEL_PATH=<path to EMBER2024_all.model> "
        "(see docs/SETUP.md; the model file itself is downloaded separately, "
        "it's ~100s of MB and not part of this repo).",
    ))

    manifest = REPO_ROOT / "dataset" / "manifest_v2.csv"
    checks.append((
        f"dataset manifest exists ({manifest.relative_to(REPO_ROOT)})",
        manifest.is_file(),
        "you need your own labeled sample set -- see docs/RESEARCH.md §3 "
        "'Dataset' for the exact scripts used to build the project's own "
        "manifest (scripts/fetch_malwarebazaar.py, scripts/collect_benign.py, "
        "scripts/select_mb_daily.py, scripts/make_manifest_v2.py). This repo "
        "deliberately does not ship real malware.",
    ))

    ollama_ok = shutil.which("ollama") is not None
    checks.append((
        "ollama on PATH",
        ollama_ok,
        "install from https://ollama.com and `ollama pull qwen3:8b` (and "
        "`ollama pull gemma4:12b` for the second local-model arm).",
    ))

    ok_count = 0
    for label, ok, fix in checks:
        mark = "[PASS]" if ok else "[MISSING]"
        print(f"{mark:10} {label}")
        if not ok:
            print(f"           -> {fix}")
        else:
            ok_count += 1
    print(f"\n{ok_count}/{len(checks)} paper-reproduction prerequisites satisfied.")
    print("(the smoke test below needs none of these)")
    return 0


# --------------------------------------------------------------------------- smoke
_SMOKE_SAMPLES: dict[str, bytes] = {
    # A synthetic file that *looks* like a Windows PE just enough to exercise
    # the format-ID/PE-header/strings tools -- the same technique
    # tests/test_cli.py uses (tests/fixtures/README.md: "never commit live
    # malware here", so the fixture is a harmless byte pattern, not a file).
    "demo_app.exe": (
        b"MZ" + b"\x00" * 64
        + b"This program cannot be run in DOS mode.\n"
        + b"CreateRemoteThread VirtualAlloc WriteProcessMemory\n"
        + b"\x00" * 256
    ),
    # A plain PowerShell script -- exercises ScriptTool / format detection
    # for a non-PE format EMBER was never trained on.
    "setup.ps1": (
        b"# demo script, not malware\n"
        b"$path = 'C:\\Windows\\Temp\\demo.txt'\n"
        b"Set-Content -Path $path -Value 'hello from mal-agent smoke test'\n"
    ),
    # A benign text file with no suspicious content at all.
    "notes.txt": b"This is an ordinary text file with nothing suspicious in it.\n",
}


def _make_smoke_samples(tmp: Path) -> list[Path]:
    paths = []
    for name, body in _SMOKE_SAMPLES.items():
        p = tmp / name
        p.write_bytes(body)
        paths.append(p)
    return paths


def cmd_smoke(args: argparse.Namespace) -> int:
    _banner("Smoke test: synthesize safe multi-format samples, run the real pipeline")
    print(
        "Nothing here is malware, and nothing is downloaded. This exercises the\n"
        "same code path 'mal-agent <path>' uses in production, on a handful of\n"
        "harmless synthetic files spanning PE / script / plain-text formats, and\n"
        "confirms the tool runs end to end on this machine."
    )
    with tempfile.TemporaryDirectory(prefix="mal-agent-smoke-") as tmpdir:
        tmp = Path(tmpdir)
        out_dir = tmp / "reports"
        samples = _make_smoke_samples(tmp)

        results = []
        for sample in samples:
            cmd = [sys.executable, "-m", "malagent.cli", str(sample), "--out", str(out_dir)]
            if args.fusion_mode:
                cmd += ["--fusion-mode", args.fusion_mode]
            print(f"\n-- {sample.name} --")
            code = _run(cmd)
            results.append((sample.name, code))

        _banner("Smoke test summary")
        failed = [name for name, code in results if code != 0]
        for name, code in results:
            print(f"  {'OK  ' if code == 0 else 'FAIL'}  {name}")
        if failed:
            print(f"\n{len(failed)}/{len(results)} samples FAILED. This means the pipeline itself "
                  "errored (not just 'produced an abstain verdict', which is expected and fine "
                  "for the .ps1/.txt samples in --fusion-mode simple since EMBER only decides "
                  "PE files). Run `python scripts/reproduce.py check` first.")
            return 1
        print(f"\nAll {len(results)} samples completed. Reports were written under a temp dir "
              "and discarded; pass --keep-reports to inspect them, or just run "
              "`mal-agent <your file>` directly for a real one.")
        if args.keep_reports:
            dest = REPO_ROOT / "mal-agent-reports" / "smoke-test"
            shutil.copytree(out_dir, dest, dirs_exist_ok=True)
            print(f"Reports kept at {dest}")
    return 0


# --------------------------------------------------------------------------- paper
def cmd_paper(args: argparse.Namespace) -> int:
    _banner("Paper reproduction: the four experimental axes, end to end")
    print(
        "This is the long path -- see scripts/run_research_jobs.ps1's header comment\n"
        "for this project's own real measured timings on a 16GB Windows machine:\n"
        "bundles ~1h56m for 1,504 samples at 4 workers; qwen3:8b's main-experiment\n"
        "arm ~1h32m; adversarial ~1h34m; reliability (1,100 jobs) ~2h14m. Budget a\n"
        "full day if you're running both local-model arms end to end.\n"
    )
    manifest = REPO_ROOT / args.manifest
    if not manifest.is_file():
        print(
            f"error: {manifest} not found.\n"
            "Run `python scripts/reproduce.py check` for exactly what's missing, or see\n"
            "docs/RESEARCH.md §3 'Dataset' for how to build your own manifest from\n"
            "your own (legally held, inert) malware/benign corpus. This script never\n"
            "fabricates or downloads samples on your behalf.",
            file=sys.stderr,
        )
        return 2

    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    log_path = REPO_ROOT / "research_out" / "logs" / "jobs.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)

    def step(name: str, cmd: list[str], critical: bool = False) -> None:
        stamp = time.strftime("%Y-%m-%dT%H:%M:%S")
        with log_path.open("a", encoding="utf-8") as fh:
            fh.write(f"[{stamp}] START {name}\n")
        code = _run(cmd)
        stamp = time.strftime("%Y-%m-%dT%H:%M:%S")
        with log_path.open("a", encoding="utf-8") as fh:
            fh.write(f"[{stamp}] END   {name} (exit {code})\n")
        if critical and code != 0:
            sys.exit(code)

    py = sys.executable
    bundles_dir = REPO_ROOT / "bundles" / "v2"
    step(
        "bundles",
        [py, "-m", "malagent.cli", "research", "build-bundles", str(manifest),
         "--out", str(bundles_dir), "--workers", str(args.workers), "--capa-timeout", "150"],
        critical=True,
    )

    models = [m.strip() for m in args.models.split(",") if m.strip()]
    for model in models:
        step(f"main {model}", [py, "-m", "malagent.cli", "research", "judge-run",
                                "--model", model, "--exp", "main", "--split", "test"])

    first = models[0]
    if not args.skip_adversarial:
        step(f"adversarial {first}", [py, "-m", "malagent.cli", "research", "judge-run",
                                       "--model", first, "--exp", "adversarial", "--split", "test",
                                       "--routed-only", "--limit", "160"])
    if not args.skip_reliability:
        step(f"reliability {first}", [py, "-m", "malagent.cli", "research", "judge-run",
                                       "--model", first, "--exp", "reliability", "--split", "test",
                                       "--routed-only", "--limit", "100"])
    if len(models) > 1 and not args.skip_claims:
        step("claims", [py, "-m", "malagent.cli", "research", "judge-claims",
                         "--narrator", models[1], "--judge", first, "--split", "test", "--limit", "60"])

    step("report", [py, "-m", "malagent.cli", "research", "judge-report",
                     "--split", "test", "--out", "research_out/report"])
    _banner("Done -- research_out/report/report.md")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="reproduce.py", description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = p.add_subparsers(dest="mode", required=True)

    sub.add_parser("check", help="report what's installed/configured, run nothing")

    sp = sub.add_parser("smoke", help="~10s end-to-end run on safe synthetic samples")
    sp.add_argument("--fusion-mode", choices=["simple", "cgef", "judge"], default=None)
    sp.add_argument("--keep-reports", action="store_true")

    pp = sub.add_parser("paper", help="reproduce the paper's four experimental axes (hours)")
    pp.add_argument("--manifest", default="dataset/manifest_v2.csv")
    pp.add_argument("--models", default="ollama:qwen3:8b,ollama:gemma4:12b")
    pp.add_argument("--workers", type=int, default=4,
                     help="bundle-building parallelism; see scripts/run_research_jobs.ps1's "
                          "header comment for why the default is 4, not higher")
    pp.add_argument("--skip-adversarial", action="store_true")
    pp.add_argument("--skip-reliability", action="store_true")
    pp.add_argument("--skip-claims", action="store_true")

    args = p.parse_args(argv)
    return {"check": cmd_check, "smoke": cmd_smoke, "paper": cmd_paper}[args.mode](args)


if __name__ == "__main__":
    raise SystemExit(main())
