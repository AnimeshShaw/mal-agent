"""CLI entry point."""
from __future__ import annotations
import argparse
import sys
from pathlib import Path
from .contracts import EgressPolicy, Provenance
from .pipeline import analyze


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == "doctor":
        from .doctor import exit_code, format_report, run_checks
        results = run_checks()
        print(format_report(results))
        return exit_code(results)

    p = argparse.ArgumentParser(prog="mal-agent", description="Evidence-grounded static malware analysis")
    p.add_argument("path", help="path to the sample")
    p.add_argument("--source", default="manual", choices=["soc", "cdc", "manual", "dataset"])
    p.add_argument("--ticket", default=None)
    p.add_argument("--enable-models", action="store_true",
                   help="enable local/cloud model stage (needs Ollama or API keys)")
    p.add_argument("--no-cloud", action="store_true", help="disable cloud escalation (local only)")
    p.add_argument("--allow-pseudocode-egress", action="store_true")
    p.add_argument("--escalation-provider", default="anthropic",
                   choices=["openai", "anthropic", "gemini", "xai"])
    p.add_argument("--out", default="./mal-agent-reports",
                   help="dir to write report.md + verdict.json + the mandatory report.txt "
                        "(default: ./mal-agent-reports; always written, files are namespaced "
                        "by sample hash)")
    args = p.parse_args(argv)

    if not Path(args.path).exists():
        print(f"error: {args.path} not found", file=sys.stderr)
        return 2

    policy = EgressPolicy(allow_cloud=not args.no_cloud,
                          allow_pseudocode_egress=args.allow_pseudocode_egress)
    prov = Provenance(source=args.source, ticket_id=args.ticket)

    state, verdict, report_md, report_txt, audit = analyze(
        args.path, provenance=prov, policy=policy, enable_models=args.enable_models,
        escalation_provider=args.escalation_provider)

    print(report_md)
    print(f"\n[audit] chain intact: {audit.verify()}  records: {len(audit.records)}")

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    prefix = state.sample.sha256[:16]
    (out / f"{prefix}_report.md").write_text(report_md)
    (out / f"{prefix}_verdict.json").write_text(verdict.model_dump_json(indent=2))
    (out / f"{prefix}_report.txt").write_text(report_txt)
    print(f"[out] wrote {out}/{prefix}_report.md, {prefix}_verdict.json, {prefix}_report.txt")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
