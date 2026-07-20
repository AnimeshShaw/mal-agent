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

    if argv and argv[0] == "evaluate":
        from . import evaluation
        ep = argparse.ArgumentParser(prog="mal-agent evaluate",
                                     description="Score verdicts against a labeled benign/malicious sample set")
        ep.add_argument("manifest", help="CSV manifest: path,label[,notes] (label: benign|malicious)")
        ep.add_argument("--enable-models", action="store_true")
        ep.add_argument("--no-cloud", action="store_true")
        ep.add_argument("--escalation-provider", default="anthropic",
                        choices=["openai", "anthropic", "gemini", "xai"])
        ep.add_argument("--out", default=None, help="also write the report text to this path")
        eargs = ep.parse_args(argv[1:])

        if not Path(eargs.manifest).exists():
            print(f"error: {eargs.manifest} not found", file=sys.stderr)
            return 2

        samples = evaluation.load_labeled_samples(eargs.manifest)
        policy = EgressPolicy(allow_cloud=not eargs.no_cloud)
        report = evaluation.evaluate(samples, enable_models=eargs.enable_models, policy=policy,
                                     escalation_provider=eargs.escalation_provider)
        text = evaluation.format_report(report)
        print(text)
        if eargs.out:
            Path(eargs.out).write_text(text)
            print(f"[out] wrote {eargs.out}")
        return 0

    if argv and argv[0] == "make-manifest":
        from . import manifest_gen
        mp = argparse.ArgumentParser(prog="mal-agent make-manifest",
                                     description="Scan <dir>/benign and <dir>/malicious, write "
                                                 "the manifest CSV 'mal-agent evaluate' needs")
        mp.add_argument("dataset_dir")
        mp.add_argument("--out", default=None, help="default: <dataset_dir>/manifest.csv")
        margs = mp.parse_args(argv[1:])

        out = margs.out or str(Path(margs.dataset_dir) / "manifest.csv")
        try:
            pairs = manifest_gen.scan_dataset_dir(margs.dataset_dir)
        except ValueError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
        manifest_gen.write_manifest(pairs, out)
        counts: dict[str, int] = {}
        for _, label in pairs:
            counts[label] = counts.get(label, 0) + 1
        print(f"[manifest] wrote {out}: {len(pairs)} samples "
              f"({counts.get('benign', 0)} benign, {counts.get('malicious', 0)} malicious)")
        return 0

    if argv and argv[0] == "ablate-critic":
        from . import critic_ablation
        ap = argparse.ArgumentParser(prog="mal-agent ablate-critic",
                                     description="Measure whether verifier_critic catches "
                                                 "overclaiming, against a bundled synthetic "
                                                 "fixture set (no real malware needed)")
        ap.add_argument("--enable-models", action="store_true",
                        help="without this, no model is configured and every case is "
                             "conservatively flagged as unverified (honest, but degenerate)")
        ap.add_argument("--no-cloud", action="store_true")
        ap.add_argument("--escalation-provider", default="anthropic",
                        choices=["openai", "anthropic", "gemini", "xai"])
        ap.add_argument("--out", default=None, help="also write the report text to this path")
        aargs = ap.parse_args(argv[1:])

        router = None
        if aargs.enable_models:
            from .contracts import AnalysisState, Sample, StepBudget
            from .models import ModelRouter, build_provider
            policy = EgressPolicy(allow_cloud=not aargs.no_cloud)
            dummy_sample = Sample(sha256="0" * 64, md5="0" * 32, path="/synthetic/ablation.bin",
                                  file_type="PE", size=1)
            state = AnalysisState(run_id="ablate-critic", sample=dummy_sample,
                                  policy=policy, budget=StepBudget())
            local = build_provider("ollama", "qwen2.5-coder:7b")
            esc = build_provider(aargs.escalation_provider) if aargs.escalation_provider else None
            router = ModelRouter(state, local=local, escalation=esc)

        report = critic_ablation.run_ablation(critic_ablation.DEFAULT_CASES, router=router)
        text = critic_ablation.format_report(report)
        print(text)
        if aargs.out:
            Path(aargs.out).write_text(text)
            print(f"[out] wrote {aargs.out}")
        return 0

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
