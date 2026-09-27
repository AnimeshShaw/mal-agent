"""Experiment runners. Every run appends one JSON record per (sample,
variant) to a JSONL file and is resumable: records already present are
skipped, and generations are disk-cached, so an interrupted multi-hour
local run -- or a later re-run for the paper -- costs nothing twice.

Experiments
  main         judge every bundle once (temperature 0), provenance mode.
               The LLM-alone arm is these verdicts on all samples; the
               hybrid arm uses them only on routed samples (routing.py), so
               both arms come from the same calls.
  adversarial  clean + each attack, in flat and provenance modes.
               benign-target attacks on malicious samples, 'alarm' on benign.
  reliability  on a fixed subset: repeated sampling (temperature 0.7,
               seeds 1..k), evidence-order permutations (temperature 0),
               single-source ablations (drop EMBER / Authenticode / capa+gate).
"""
from __future__ import annotations
import json
import random
from pathlib import Path
from typing import Callable, Iterable, Optional

from .adversarial import ATTACKS, apply_attack, attack_target
from .judge import PROMPT_VERSION, adjudicate
from .routing import route

RELIABILITY_DROPS = {"no_ember": {"ember"}, "no_authenticode": {"authenticode"},
                     "no_capa_gate": {"capa", "gate"}}


def select(bundles: list[dict], split: Optional[str] = None, routed_only: bool = False,
           limit: Optional[int] = None, seed: int = 7) -> list[dict]:
    out = [b for b in bundles if split is None or (b.get("meta") or {}).get("split") == split]
    if routed_only:
        out = [b for b in out if route(b).routed]
    if limit is not None and len(out) > limit:
        # stratified-ish: keep label balance when subsampling
        rng = random.Random(seed)
        mal = [b for b in out if b["label"] == "malicious"]
        ben = [b for b in out if b["label"] == "benign"]
        rng.shuffle(mal)
        rng.shuffle(ben)
        half = limit // 2
        n_m = min(len(mal), half)
        n_b = min(len(ben), limit - n_m)
        n_m = min(len(mal), limit - n_b)
        out = mal[:n_m] + ben[:n_b]
    return out


def _done_keys(path: Path) -> set:
    keys = set()
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                r = json.loads(line)
                keys.add((r["sha256"], r["variant"]))
            except (json.JSONDecodeError, KeyError):
                continue
    return keys


def _record(b: dict, exp: str, variant: str, res, extra: dict) -> dict:
    rt = route(b)
    return {"sha256": b["sha256"], "label": b["label"], "format": b.get("format"),
            "split": (b.get("meta") or {}).get("split"), "routed": rt.routed,
            "reasons": rt.reasons, "exp": exp, "variant": variant,
            "prompt_version": PROMPT_VERSION, **extra, "result": res.to_dict()}


def run_jobs(jobs: Iterable[tuple[dict, str, dict, Optional[Callable]]], provider, out_path,
             exp: str, progress: bool = True) -> int:
    """jobs: (bundle, variant, adjudicate_kwargs, transform-or-None)."""
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    done = _done_keys(out)
    jobs = [j for j in jobs if (j[0]["sha256"], j[1]) not in done]
    n = 0
    with open(out, "a", encoding="utf-8") as fh:
        for b, variant, kw, transform in jobs:
            src = transform(b) if transform else b
            res = adjudicate(src, provider, **kw)
            extra = {k: (sorted(v) if isinstance(v, (set, frozenset)) else v) for k, v in kw.items()}
            fh.write(json.dumps(_record(b, exp, variant, res, extra)) + "\n")
            fh.flush()
            n += 1
            if progress:
                print(f"[{exp}] {n}/{len(jobs)} {b['sha256'][:12]} {variant}: {res.verdict}"
                      f"{' (gated)' if res.gated else ''}{'' if res.valid else ' INVALID'}",
                      flush=True)
    return n


def main_jobs(bundles, mode="provenance"):
    return [(b, f"main:{mode}", {"mode": mode}, None) for b in bundles]


def adversarial_jobs(bundles, modes=("flat", "provenance"), attacks=tuple(ATTACKS)):
    jobs = []
    for b in bundles:
        for mode in modes:
            jobs.append((b, f"clean:{mode}", {"mode": mode}, None))
            for a in attacks:
                if (attack_target(a) == "benign") != (b["label"] == "malicious"):
                    continue  # benign-target attacks only on malware; 'alarm' only on benign
                jobs.append((b, f"{a}:{mode}", {"mode": mode},
                             (lambda bb, a=a: apply_attack(bb, a))))
    return jobs


def reliability_jobs(bundles, repeats=5, orders=3):
    jobs = []
    for b in bundles:
        for s in range(1, repeats + 1):
            jobs.append((b, f"repeat:{s}", {"mode": "provenance", "temperature": 0.7, "seed": s}, None))
        for o in range(1, orders + 1):
            jobs.append((b, f"order:{o}", {"mode": "provenance", "order_seed": o}, None))
        for name, drop in RELIABILITY_DROPS.items():
            jobs.append((b, f"ablate:{name}", {"mode": "provenance", "drop": frozenset(drop)}, None))
    return jobs


def load_results(path) -> list[dict]:
    p = Path(path)
    if not p.exists():
        return []
    out = []
    for line in p.read_text(encoding="utf-8").splitlines():
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out
