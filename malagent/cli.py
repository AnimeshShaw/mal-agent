"""CLI entry point."""
from __future__ import annotations
import argparse
import sys
from pathlib import Path
from .contracts import EgressPolicy, Provenance
from .pipeline import analyze


_RESEARCH_CMDS = {"evaluate", "make-manifest", "suggest-verdict",
                  "ablate-critic", "family-attribution", "ablate-llm"}


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv

    # Documented top-level surface: `analyze` (single sample) and `web`
    # (local UI) are primary; `research <subcommand>` groups the six
    # measurement/ablation tools below (still needed for the paper's
    # methodology section, just out of the way of everyday use). Old flat
    # invocations (`mal-agent evaluate ...`, bare `mal-agent <path>`) must
    # keep working unmodified -- ~30 existing tests call them directly,
    # and test_normal_analyze_invocation_still_works_unaffected documents
    # a prior CLI-shadowing bug this must not reintroduce. Stripping the
    # `research`/`analyze` wrapper and falling through to the exact same
    # unmodified per-command blocks below (rather than a parallel
    # subparser tree) guarantees zero behavioral drift between the old
    # and new invocation forms -- there is only one code path per command.
    if argv and argv[0] == "research":
        if len(argv) < 2 or argv[1] not in _RESEARCH_CMDS:
            print("usage: mal-agent research <subcommand> [args...]", file=sys.stderr)
            print(f"subcommands: {', '.join(sorted(_RESEARCH_CMDS))}", file=sys.stderr)
            return 2
        argv = argv[1:]
    elif argv and argv[0] == "analyze":
        argv = argv[1:]

    if argv and argv[0] == "doctor":
        from .doctor import exit_code, format_report, run_checks
        results = run_checks()
        print(format_report(results))
        return exit_code(results)

    if argv and argv[0] == "web":
        try:
            from .web_cli import run as run_web
        except ImportError as e:
            print(f"error: the local web UI isn't available: {e}", file=sys.stderr)
            print("install its extra dependencies with: pip install -e \".[web]\"",
                 file=sys.stderr)
            return 3
        wp = argparse.ArgumentParser(prog="mal-agent web", description="Launch the local web UI")
        wp.add_argument("--host", default="127.0.0.1")
        wp.add_argument("--port", type=int, default=8765)
        wargs = wp.parse_args(argv[1:])
        run_web(host=wargs.host, port=wargs.port)
        return 0

    if argv and argv[0] == "evaluate":
        from . import evaluation
        ep = argparse.ArgumentParser(prog="mal-agent evaluate",
                                     description="Score verdicts against a labeled benign/malicious sample set")
        ep.add_argument("manifest", help="CSV manifest: path,label[,notes] (label: benign|malicious)")
        ep.add_argument("--enable-models", action="store_true")
        ep.add_argument("--no-cloud", action="store_true")
        ep.add_argument("--local-model", default="qwen2.5-coder:7b",
                        help="Ollama model tag to use locally (default: qwen2.5-coder:7b)")
        ep.add_argument("--escalation-provider", default="anthropic",
                        choices=["openai", "anthropic", "gemini", "xai"])
        ep.add_argument("--fusion-mode", default="simple", choices=["simple", "cgef"],
                        help="verdict decision method when EMBER is configured "
                             "(see docs/ML_CLASSIFIER_PLAN.md S10/S11)")
        ep.add_argument("--out", default=None, help="also write the report text to this path")
        eargs = ep.parse_args(argv[1:])

        if not Path(eargs.manifest).exists():
            print(f"error: {eargs.manifest} not found", file=sys.stderr)
            return 2

        samples = evaluation.load_labeled_samples(eargs.manifest)
        policy = EgressPolicy(allow_cloud=not eargs.no_cloud)
        report = evaluation.evaluate(samples, enable_models=eargs.enable_models, policy=policy,
                                     local_model=eargs.local_model,
                                     escalation_provider=eargs.escalation_provider,
                                     fusion_mode=eargs.fusion_mode)
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

    if argv and argv[0] == "suggest-verdict":
        from . import evaluation, verdict_suggestion
        vp = argparse.ArgumentParser(prog="mal-agent suggest-verdict",
                                     description="Non-binding: ask an LLM to holistically judge "
                                                 "malicious/benign from all gathered evidence, "
                                                 "measured against ground truth for comparison "
                                                 "with the deterministic verdict -- never used "
                                                 "to influence the real verdict")
        vp.add_argument("manifest", help="CSV manifest: path,label[,notes] (label: benign|malicious)")
        vp.add_argument("--no-cloud", action="store_true")
        vp.add_argument("--local-model", default="qwen2.5-coder:7b",
                        help="Ollama model tag to ask for the verdict suggestion "
                             "(default: qwen2.5-coder:7b)")
        vp.add_argument("--escalation-provider", default="anthropic",
                        choices=["openai", "anthropic", "gemini", "xai"])
        vp.add_argument("--out", default=None, help="also write the report text to this path")
        vargs = vp.parse_args(argv[1:])

        if not Path(vargs.manifest).exists():
            print(f"error: {vargs.manifest} not found", file=sys.stderr)
            return 2

        from .contracts import AnalysisState, Sample, StepBudget
        from .models import ModelRouter, build_provider
        policy = EgressPolicy(allow_cloud=not vargs.no_cloud)
        dummy_sample = Sample(sha256="0" * 64, md5="0" * 32, path="/synthetic/suggest.bin",
                              file_type="PE", size=1)
        dummy_state = AnalysisState(run_id="suggest-verdict", sample=dummy_sample,
                                    policy=policy, budget=StepBudget())
        local = build_provider("ollama", vargs.local_model)
        esc = (build_provider(vargs.escalation_provider)
              if vargs.escalation_provider and policy.allow_cloud else None)
        router = ModelRouter(dummy_state, local=local, escalation=esc)

        samples = evaluation.load_labeled_samples(vargs.manifest)
        report = verdict_suggestion.evaluate_llm_suggestions(samples, router=router)
        text = verdict_suggestion.format_report(report)
        print(text)
        if vargs.out:
            Path(vargs.out).write_text(text)
            print(f"[out] wrote {vargs.out}")
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
        ap.add_argument("--local-model", default="qwen2.5-coder:7b",
                       help="Ollama model tag to use locally (default: qwen2.5-coder:7b)")
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
            local = build_provider("ollama", aargs.local_model)
            esc = (build_provider(aargs.escalation_provider)
                  if aargs.escalation_provider and policy.allow_cloud else None)
            router = ModelRouter(state, local=local, escalation=esc)

        report = critic_ablation.run_ablation(critic_ablation.DEFAULT_CASES, router=router)
        text = critic_ablation.format_report(report)
        print(text)
        if aargs.out:
            Path(aargs.out).write_text(text)
            print(f"[out] wrote {aargs.out}")
        return 0

    if argv and argv[0] == "family-attribution":
        from . import family_attribution as fam
        fp = argparse.ArgumentParser(
            prog="mal-agent family-attribution",
            description="Predict malware family via leave-one-out imphash clustering "
                        "(+ real capa malware-family rule hits when present) and score "
                        "macro-F1 against real MalwareBazaar ground truth")
        fp.add_argument("--dataset-dir", default="dataset/malicious",
                        help="dir of <sha256>.bin samples (default dataset/malicious)")
        fp.add_argument("--ground-truth", default="dataset/family_ground_truth.csv",
                        help="CSV from scripts/fetch_family_ground_truth.py "
                             "(default dataset/family_ground_truth.csv)")
        fp.add_argument("--use-capa", action="store_true",
                        help="also run real capa per sample for malware-family namespace hits. "
                             "Slow, and empirically contributes nothing for AgentTesla/"
                             "RedLineStealer/Emotet/Lokibot/Formbook/Remcos/AsyncRAT/njRAT -- "
                             "capa-rules-9.4.0's malware-family namespace only covers "
                             "donut-loader/plugx. Off by default.")
        fp.add_argument("--out", default=None, help="also write the report text to this path")
        fargs = fp.parse_args(argv[1:])

        if not Path(fargs.dataset_dir).is_dir():
            print(f"error: {fargs.dataset_dir} not found", file=sys.stderr)
            return 2
        if not Path(fargs.ground_truth).exists():
            print(f"error: {fargs.ground_truth} not found -- run "
                  f"scripts/fetch_family_ground_truth.py first", file=sys.stderr)
            return 2

        capa_family_hits_by_hash = None
        if fargs.use_capa:
            capa_family_hits_by_hash = {
                p.stem: fam.compute_capa_family_hits(str(p))
                for p in sorted(Path(fargs.dataset_dir).glob("*.bin"))
            }

        report = fam.run_family_attribution(fargs.dataset_dir, fargs.ground_truth,
                                            capa_family_hits_by_hash=capa_family_hits_by_hash)
        text = fam.format_family_report(report)
        print(text)
        if fargs.out:
            Path(fargs.out).write_text(text)
            print(f"[out] wrote {fargs.out}")
        return 0

    if argv and argv[0] == "ablate-llm":
        from . import llm_ablation
        lp = argparse.ArgumentParser(prog="mal-agent ablate-llm",
                                     description="Deterministic-only vs. +LLM ablation: runs each "
                                                 "sample through the full pipeline twice and checks "
                                                 "whether the verdict label/score ever differs "
                                                 "(it should not -- LLMs narrate, never judge)")
        lp.add_argument("manifest", help="CSV manifest: path,label[,notes] (label: benign|malicious)")
        lp.add_argument("--no-cloud", action="store_true")
        lp.add_argument("--local-model", default="qwen2.5-coder:7b",
                        help="Ollama model tag to use for the +LLM condition "
                             "(default: qwen2.5-coder:7b)")
        lp.add_argument("--escalation-provider", default=None,
                        choices=[None, "openai", "anthropic", "gemini", "xai"],
                        help="cloud escalation provider for the +LLM condition "
                             "(default: none -- local Ollama only, fully reproducible)")
        lp.add_argument("--out", default=None, help="also write the report text to this path")
        largs = lp.parse_args(argv[1:])

        if not Path(largs.manifest).exists():
            print(f"error: {largs.manifest} not found", file=sys.stderr)
            return 2

        from . import evaluation as evaluation_module
        samples = evaluation_module.load_labeled_samples(largs.manifest)
        report = llm_ablation.run_llm_ablation(
            samples, local_model=largs.local_model,
            escalation_provider=largs.escalation_provider, no_cloud=largs.no_cloud)
        text = llm_ablation.format_report(report)
        print(text)
        if largs.out:
            Path(largs.out).write_text(text)
            print(f"[out] wrote {largs.out}")
        return 0

    p = argparse.ArgumentParser(prog="mal-agent", description="Evidence-grounded static malware analysis")
    p.add_argument("path", help="path to the sample")
    p.add_argument("--source", default="manual", choices=["soc", "cdc", "manual", "dataset"])
    p.add_argument("--ticket", default=None)
    p.add_argument("--enable-models", action="store_true",
                   help="enable local/cloud model stage (needs Ollama or API keys)")
    p.add_argument("--no-cloud", action="store_true", help="disable cloud escalation (local only)")
    p.add_argument("--allow-pseudocode-egress", action="store_true")
    p.add_argument("--local-model", default="qwen2.5-coder:7b",
                   help="Ollama model tag to use locally (default: qwen2.5-coder:7b)")
    p.add_argument("--escalation-provider", default="anthropic",
                   choices=["openai", "anthropic", "gemini", "xai"])
    p.add_argument("--fusion-mode", default="simple", choices=["simple", "cgef"],
                   help="verdict decision method when EMBER is configured: 'simple' "
                        "(default) lets the EMBER classifier alone decide malicious/"
                        "benign; 'cgef' opts into the deterministic corroboration "
                        "gate voting in the gray zone (see docs/ML_CLASSIFIER_PLAN.md "
                        "S10/S11)")
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

    state, verdict, report_md, report_txt, report_html, audit = analyze(
        args.path, provenance=prov, policy=policy, enable_models=args.enable_models,
        local_model=args.local_model, escalation_provider=args.escalation_provider,
        fusion_mode=args.fusion_mode)

    print(report_md)
    print(f"\n[audit] chain intact: {audit.verify()}  records: {len(audit.records)}")

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    prefix = state.sample.sha256[:16]
    (out / f"{prefix}_report.md").write_text(report_md)
    (out / f"{prefix}_verdict.json").write_text(verdict.model_dump_json(indent=2))
    (out / f"{prefix}_report.txt").write_text(report_txt)
    (out / f"{prefix}_report.html").write_text(report_html, encoding="utf-8")
    print(f"[out] wrote {out}/{prefix}_report.md, {prefix}_verdict.json, "
         f"{prefix}_report.txt, {prefix}_report.html")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
