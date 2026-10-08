"""Turn bundles + experiment JSONL into the paper's tables (markdown +
JSON) and figures. Pure functions over records; nothing here calls a model.

Arms (all on the same bundles):
  EMBER-alone   production default ('simple' fusion)
  CGEF          confidence-gated evidence fusion (opt-in mode)
  Gate          deterministic corroboration gate, EMBER removed
  LLM-alone[m]  judge m's verdict on every sample
  Hybrid[m]     EMBER-alone, except routed hard cases take judge m's verdict
"""
from __future__ import annotations
import json
import statistics
from collections import Counter, defaultdict
from pathlib import Path
from typing import Optional

from .adversarial import attack_target
from .metrics import (aurc, bootstrap_ci, confusion, ece, fleiss_kappa, mcnemar, normalize_verdict,
                      risk_coverage_curve)
from .routing import hybrid_verdict, route

_GROUPS = {"pe": "PE", "elf": "ELF", "macho": "ELF/Mach-O", "lnk": "LNK",
           "ole": "Office/PDF", "ooxml": "Office/PDF", "rtf": "Office/PDF", "pdf": "Office/PDF",
           "onenote": "Office/PDF", "zip": "Archive/ISO", "archive": "Archive/ISO",
           "iso": "Archive/ISO"}


def format_group(fmt: Optional[str]) -> str:
    if fmt and fmt.startswith("script_") or fmt == "text":
        return "Script"
    return _GROUPS.get(fmt or "", "Other")


def _fmt(x, pct=False, nd=3):
    if x is None:
        return "–"
    return f"{100 * x:.1f}%" if pct else f"{x:.{nd}f}"


# ---------------------------------------------------------------- arms
def main_verdicts(results: list[dict], variant: str = "main:provenance") -> dict:
    return {r["sha256"]: r["result"] for r in results if r.get("variant") == variant}


def arm_predictions(bundles: list[dict], judge_results: dict[str, list[dict]]) -> dict:
    arms = {"EMBER-alone": {}, "CGEF": {}, "Gate": {}}
    for b in bundles:
        bl = b["baselines"]
        arms["EMBER-alone"][b["sha256"]] = bl["simple"]["verdict"]
        arms["CGEF"][b["sha256"]] = bl["cgef"]["verdict"]
        arms["Gate"][b["sha256"]] = bl["gate"]["verdict"]
    for model, results in judge_results.items():
        mv = main_verdicts(results)
        if not mv:
            continue
        la, hy = {}, {}
        for b in bundles:
            j = mv.get(b["sha256"])
            if j is None:
                continue
            la[b["sha256"]] = j["verdict"]
            hy[b["sha256"]] = hybrid_verdict(b, j["verdict"])
        arms[f"LLM-alone[{model}]"] = la
        arms[f"Hybrid[{model}]"] = hy
    return arms


def _metrics_with_ci(bundles, preds, seed=0) -> dict:
    pairs = [(b["label"], preds[b["sha256"]]) for b in bundles if b["sha256"] in preds]
    m = confusion(pairs)
    if pairs:
        for key in ("f1", "fpr", "recall", "coverage"):
            m[f"{key}_ci"] = bootstrap_ci(pairs, lambda xs, k=key: confusion(xs)[k], n=500, seed=seed)
    return m


def main_table(bundles: list[dict], arms: dict, subset_name: str = "all") -> dict:
    return {arm: _metrics_with_ci(bundles, preds) for arm, preds in arms.items()}


def subsets(bundles: list[dict]) -> dict[str, list[dict]]:
    return {
        "all": bundles,
        "PE": [b for b in bundles if b.get("format") == "pe"],
        "non-PE": [b for b in bundles if b.get("format") != "pe"],
        "routed (hard)": [b for b in bundles if route(b).routed],
        "not routed": [b for b in bundles if not route(b).routed],
    }


def per_group_table(bundles, arms) -> dict:
    groups = defaultdict(list)
    for b in bundles:
        groups[format_group(b.get("format"))].append(b)
    return {g: {arm: confusion([(b["label"], preds[b["sha256"]]) for b in bs if b["sha256"] in preds])
                for arm, preds in arms.items()} for g, bs in sorted(groups.items())}


def paired_tests(bundles, arms, reference="EMBER-alone") -> dict:
    ref = arms[reference]
    out = {}
    for arm, preds in arms.items():
        if arm == reference:
            continue
        common = [b for b in bundles if b["sha256"] in preds and b["sha256"] in ref]
        a = [normalize_verdict(ref[b["sha256"]]) == b["label"] for b in common]
        c = [normalize_verdict(preds[b["sha256"]]) == b["label"] for b in common]
        out[arm] = mcnemar(a, c)
    return out


# ---------------------------------------------------------------- routing / dataset
def dataset_table(bundles) -> dict:
    t = defaultdict(Counter)
    for b in bundles:
        t[format_group(b.get("format"))][f"{(b.get('meta') or {}).get('split', '?')}:{b['label']}"] += 1
    return {g: dict(c) for g, c in sorted(t.items())}


def routing_table(bundles) -> dict:
    reasons = Counter()
    routed = 0
    by_label = Counter()
    for b in bundles:
        r = route(b)
        if r.routed:
            routed += 1
            by_label[b["label"]] += 1
            reasons.update(r.reasons)
    return {"n": len(bundles), "routed": routed, "routed_frac": routed / len(bundles) if bundles else None,
            "routed_by_label": dict(by_label), "reasons": dict(reasons)}


# ---------------------------------------------------------------- adversarial
def adversarial_table(results: list[dict]) -> dict:
    """Per (attack, mode): attack success rate = fraction of attacked samples
    whose verdict equals the attacker's target, among samples whose clean
    verdict in the same mode was NOT already the target."""
    clean = {(r["sha256"], r["variant"].split(":")[1]): r["result"]["verdict"]
             for r in results if r["variant"].startswith("clean:")}
    agg = defaultdict(lambda: {"n": 0, "success": 0, "changed": 0, "gated": 0, "invalid": 0})
    for r in results:
        name, _, mode = r["variant"].partition(":")
        if name in ("clean", "main") or not mode:
            continue
        base = clean.get((r["sha256"], mode))
        if base is None:
            continue
        target = attack_target(name)
        if base == target:
            continue
        a = agg[(name, mode)]
        v = r["result"]["verdict"]
        a["n"] += 1
        a["success"] += v == target
        a["changed"] += v != base
        a["gated"] += bool(r["result"].get("gated"))
        a["invalid"] += not r["result"].get("valid", False)
    return {f"{k[0]}|{k[1]}": {**v, "asr": v["success"] / v["n"] if v["n"] else None}
            for k, v in sorted(agg.items())}


# ---------------------------------------------------------------- reliability
def reliability_table(results: list[dict], bundles_by_sha: dict) -> dict:
    by_sha = defaultdict(dict)
    for r in results:
        by_sha[r["sha256"]][r["variant"]] = r["result"]["verdict"]
    main = {s: v.get("main:provenance") for s, v in by_sha.items()}
    repeats, order_flip, ablate_flip = [], Counter(), Counter()
    order_n, ablate_n = Counter(), Counter()
    for sha, vs in by_sha.items():
        reps = [vs[k] for k in sorted(vs) if k.startswith("repeat:")]
        if len(reps) >= 2:
            repeats.append(reps)
        ref = main.get(sha)
        if ref is None:
            continue
        for k, v in vs.items():
            if k.startswith("order:"):
                order_n["all"] += 1
                order_flip["all"] += v != ref
            elif k.startswith("ablate:"):
                name = k.split(":", 1)[1]
                ablate_n[name] += 1
                ablate_flip[name] += v != ref
    k = min((len(r) for r in repeats), default=0)
    reps = [r[:k] for r in repeats] if k >= 2 else []
    return {
        "repeat_items": len(reps), "repeats_per_item": k,
        "repeat_fleiss_kappa": fleiss_kappa(reps) if reps else None,
        "repeat_unanimous_frac": (sum(len(set(r)) == 1 for r in reps) / len(reps)) if reps else None,
        "order_flip_rate": (order_flip["all"] / order_n["all"]) if order_n["all"] else None,
        "ablation_flip_rate": {n: ablate_flip[n] / ablate_n[n] for n in ablate_n},
    }


def calibration(results: list[dict], bundles_by_sha: dict) -> dict:
    conf, correct = [], []
    for r in results:
        if r.get("variant") != "main:provenance":
            continue
        v = r["result"]["verdict"]
        if v not in ("malicious", "benign"):
            continue
        conf.append(float(r["result"].get("confidence") or 0))
        correct.append(v == r["label"])
    return {"n_committed": len(conf), "ece": ece(conf, correct), "aurc": aurc(conf, correct),
            "curve": risk_coverage_curve(conf, correct)}


def cost_table(results: list[dict]) -> dict:
    rs = [r["result"] for r in results]
    if not rs:
        return {}
    lat = sorted(x["latency_ms"] for x in rs if not x.get("cached") and x["latency_ms"])
    return {"calls": len(rs), "invalid_rate": sum(not x["valid"] for x in rs) / len(rs),
            "gated_rate": sum(bool(x.get("gated")) for x in rs) / len(rs),
            "mean_input_tokens": statistics.mean(x["input_tokens"] for x in rs),
            "mean_output_tokens": statistics.mean(x["output_tokens"] for x in rs),
            "latency_p50_ms": lat[len(lat) // 2] if lat else None,
            "latency_p95_ms": lat[int(len(lat) * 0.95)] if lat else None}


# ---------------------------------------------------------------- claims
def claims_summary(records: list[dict]) -> dict:
    claims = [c for r in records for c in r.get("claims", [])]
    if not claims:
        return {"narratives": len(records), "claims": 0}
    judged = [c for c in claims if (c.get("judge") or {}).get("label") in
              ("SUPPORTED", "NOT_SUPPORTED", "CONTRADICTED")]
    det = [c["deterministic"] for c in claims]
    lab = Counter(c["judge"]["label"] for c in judged)
    return {
        "narratives": len(records), "claims": len(claims),
        "claims_per_narrative": len(claims) / max(1, len(records)),
        "uncited_rate": sum(d["uncited"] for d in det) / len(det),
        "invalid_citation_rate": sum(not d["citations_valid"] for d in det) / len(det),
        "ungrounded_entity_rate": sum(not d["entities_grounded"] for d in det) / len(det),
        "attack_not_observed_rate": sum(bool(d["attack_not_observed"]) for d in det) / len(det),
        "judge_labels": dict(lab),
        "judge_unsupported_rate": (sum(v for k, v in lab.items() if k != "SUPPORTED") / len(judged))
        if judged else None,
        "judge_unparseable": len(claims) - len(judged),
    }


# ---------------------------------------------------------------- report
def _confusion_md(title, table) -> list[str]:
    L = [f"### {title}", "",
         "| Arm | n | TP | FP | TN | FN | Undet (mal/ben) | Precision | Recall | F1 [95% CI] | FPR [95% CI] | Coverage |",
         "|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for arm, m in table.items():
        f1ci, fprci = m.get("f1_ci", (None, None)), m.get("fpr_ci", (None, None))
        L.append(f"| {arm} | {m['n']} | {m['tp']} | {m['fp']} | {m['tn']} | {m['fn']} | "
                 f"{m['undet_mal']}/{m['undet_ben']} | {_fmt(m['precision'])} | {_fmt(m['recall'])} | "
                 f"{_fmt(m['f1'])} [{_fmt(f1ci[0])}, {_fmt(f1ci[1])}] | "
                 f"{_fmt(m['fpr'], True)} [{_fmt(fprci[0], True)}, {_fmt(fprci[1], True)}] | "
                 f"{_fmt(m['coverage'], True)} |")
    return L + [""]


def build_report(bundles: list[dict], results_by_model: dict[str, list[dict]],
                 split: Optional[str] = "test") -> dict:
    sel = [b for b in bundles if split is None or (b.get("meta") or {}).get("split") == split]
    by_sha = {b["sha256"]: b for b in bundles}
    arms = arm_predictions(sel, results_by_model)
    rep = {"split": split, "dataset": dataset_table(bundles), "routing": routing_table(sel),
           "main": {name: main_table(bs, arms) for name, bs in subsets(sel).items()},
           "per_group": per_group_table(sel, arms), "paired_vs_ember": paired_tests(sel, arms),
           "models": {}}
    for model, results in results_by_model.items():
        rs = [r for r in results if split is None or r.get("split") == split]
        rep["models"][model] = {
            "adversarial": adversarial_table([r for r in rs if r["exp"] == "adversarial"]),
            "reliability": reliability_table(
                [r for r in rs if r["exp"] in ("reliability", "main")], by_sha),
            "calibration": {k: v for k, v in calibration(rs, by_sha).items() if k != "curve"},
            "cost": cost_table(rs)}
    return rep


def report_markdown(rep: dict) -> str:
    L = [f"# Judge experiments — split: {rep['split']}", "", "## Dataset (all splits)", "",
         "| Format group | counts |", "|---|---|"]
    for g, c in rep["dataset"].items():
        L.append(f"| {g} | {', '.join(f'{k}={v}' for k, v in sorted(c.items()))} |")
    rt = rep["routing"]
    L += ["", "## Routing", "", f"{rt['routed']}/{rt['n']} routed ({_fmt(rt['routed_frac'], True)}); "
          f"by label {rt['routed_by_label']}; reasons {rt['reasons']}", ""]
    L += ["## Main results", ""]
    for name, table in rep["main"].items():
        L += _confusion_md(f"Subset: {name}", table)
    L += ["## Per format group (F1 / FPR / coverage)", ""]
    arms = list(next(iter(rep["per_group"].values()), {}).keys())
    L += ["| Group | " + " | ".join(arms) + " |", "|---" * (len(arms) + 1) + "|"]
    for g, t in rep["per_group"].items():
        L.append(f"| {g} (n={next(iter(t.values()))['n']}) | " + " | ".join(
            f"{_fmt(t[a]['f1'])} / {_fmt(t[a]['fpr'], True)} / {_fmt(t[a]['coverage'], True)}"
            for a in arms) + " |")
    L += ["", "## Paired test vs EMBER-alone (McNemar, correctness incl. abstention as wrong)", "",
          "| Arm | EMBER right, arm wrong | arm right, EMBER wrong | p |", "|---|---|---|---|"]
    for arm, t in rep["paired_vs_ember"].items():
        L.append(f"| {arm} | {t['b01']} | {t['b10']} | {_fmt(t['p'], nd=4)} |")
    for model, m in rep["models"].items():
        L += ["", f"## Model: {model}", "", "### Adversarial (attack success rate)", "",
              "| Attack | Mode | n | ASR | changed | gated | invalid |", "|---|---|---|---|---|---|---|"]
        for k, v in m["adversarial"].items():
            a, mode = k.split("|")
            L.append(f"| {a} | {mode} | {v['n']} | {_fmt(v['asr'], True)} | {v['changed']} | "
                     f"{v['gated']} | {v['invalid']} |")
        rl = m["reliability"]
        L += ["", "### Reliability", "",
              f"- repeats: {rl['repeat_items']} items x {rl['repeats_per_item']}; Fleiss kappa "
              f"{_fmt(rl['repeat_fleiss_kappa'])}; unanimous {_fmt(rl['repeat_unanimous_frac'], True)}",
              f"- evidence-order flip rate: {_fmt(rl['order_flip_rate'], True)}",
              f"- ablation flip rates: " + ", ".join(f"{k} {_fmt(v, True)}"
                                                     for k, v in rl['ablation_flip_rate'].items()),
              f"- calibration: ECE {_fmt(m['calibration']['ece'])}, AURC {_fmt(m['calibration']['aurc'])} "
              f"over {m['calibration']['n_committed']} committed verdicts",
              f"- cost: {json.dumps({k: (round(v, 3) if isinstance(v, float) else v) for k, v in m['cost'].items()})}"]
    if rep.get("claims"):
        L += ["", "## Claim-level verification of narratives", "",
              "| Narrator__Judge | narratives | claims | uncited | invalid cite | ungrounded entity | "
              "ATT&CK not observed | judge unsupported |", "|---|---|---|---|---|---|---|---|"]
        for k, c in rep["claims"].items():
            if not c.get("claims"):
                continue
            L.append(f"| {k} | {c['narratives']} | {c['claims']} | {_fmt(c['uncited_rate'], True)} | "
                     f"{_fmt(c['invalid_citation_rate'], True)} | {_fmt(c['ungrounded_entity_rate'], True)} | "
                     f"{_fmt(c['attack_not_observed_rate'], True)} | {_fmt(c['judge_unsupported_rate'], True)} |")
    return "\n".join(L) + "\n"


def write_report(rep: dict, out_dir) -> Path:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.json").write_text(json.dumps(rep, indent=1, default=str), encoding="utf-8")
    p = out / "report.md"
    p.write_text(report_markdown(rep), encoding="utf-8")
    return p
