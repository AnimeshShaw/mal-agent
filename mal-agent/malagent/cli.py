"""CLI entry point."""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path
from .contracts import EgressPolicy, Provenance
from .pipeline import analyze


def main(argv=None):
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
    p.add_argument("--out", default=None, help="dir to write report.md + verdict.json")
    args = p.parse_args(argv)

    if not Path(args.path).exists():
        print(f"error: {args.path} not found", file=sys.stderr)
        return 2

    policy = EgressPolicy(allow_cloud=not args.no_cloud,
                          allow_pseudocode_egress=args.allow_pseudocode_egress)
    prov = Provenance(source=args.source, ticket_id=args.ticket)

    state, verdict, report_md, audit = analyze(
        args.path, provenance=prov, policy=policy, enable_models=args.enable_models,
        escalation_provider=args.escalation_provider)

    print(report_md)
    print(f"\n[audit] chain intact: {audit.verify()}  records: {len(audit.records)}")

    if args.out:
        out = Path(args.out); out.mkdir(parents=True, exist_ok=True)
        (out / "report.md").write_text(report_md)
        (out / "verdict.json").write_text(verdict.model_dump_json(indent=2))
        print(f"[out] wrote {out}/report.md and verdict.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
