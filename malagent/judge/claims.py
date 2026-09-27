"""Claim-level verification of LLM-written analyst narratives.

A narrative is split deterministically into sentence-level claims, each
carrying the [E#] evidence aliases it cites. Every claim then gets:

  deterministic checks  citations point at real evidence items; cited-or-
                        not; ATT&CK IDs exist in the MITRE reference table
                        and were actually observed in this sample's
                        findings; named identifiers (API names, URLs, IPs,
                        file names, registry paths) appear somewhere in the
                        evidence text.
  an LLM entailment     SUPPORTED / NOT_SUPPORTED / CONTRADICTED given only
  judgement             the evidence the claim cites (uncited claims are
                        judged against nothing, i.e. NOT_SUPPORTED unless
                        they are pure hedging).

Human labels are collected through an annotation CSV; import_annotations()
reports judge-vs-human agreement (Cohen's kappa) and how well the judge
detects unsupported claims.
"""
from __future__ import annotations
import csv
import json
import re
from pathlib import Path

from ..attck_reference import technique_name
from .judge import parse_judge_output
from .metrics import cohen_kappa
from .render import Rendered, render_evidence

CLAIM_LABELS = ("SUPPORTED", "NOT_SUPPORTED", "CONTRADICTED")

_CITE_RX = re.compile(r"\[(E\d+(?:\s*,\s*E\d+)*)\]")
_SENT_RX = re.compile(r"(?<=[.!?])\s+(?=[A-Z0-9\"'(])")
_ATTACK_RX = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_ENTITY_RXS = [
    re.compile(r"https?://[^\s\]\)\"']+"),
    re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    re.compile(r"\b[\w-]+\.(?:exe|dll|ps1|vbs|js|bat|cmd|lnk|hta|dat|tmp|scr|sys)\b", re.I),
    re.compile(r"\bHK(?:LM|CU|EY_[A-Z_]+)\\[^\s,;)\]]+"),
    # Win32/.NET-API-shaped identifiers: CamelCase with >= 3 capitals, e.g. CreateRemoteThread
    re.compile(r"\b(?:[A-Z][a-z0-9]+){3,}(?:Ex|A|W)?\b"),
]
_ENTITY_STOP = {"PowerShell", "JavaScript", "VirusTotal", "OneNote", "WindowsPowerShell",
                "MalwareBazaar", "GitHub", "OpenAction", "EmbeddedFile", "RichMedia"}

NARRATIVE_SYSTEM = """You are a senior malware analyst writing the behavioural analysis section of a
report for ONE file. Using only the evidence provided, describe what the file does and why it is
or is not concerning. After every factual sentence, cite the evidence it rests on with its alias,
e.g. [E3] or [E3, E7]. Do not state facts that no evidence item shows. Write 5-10 sentences of
plain prose (no lists, no headings)."""

CLAIM_SYSTEM = """You verify ONE sentence from a malware analysis report against the evidence it
cites. Answer SUPPORTED if the cited evidence shows what the sentence asserts, NOT_SUPPORTED if the
evidence does not show it (including when nothing is cited), CONTRADICTED if the evidence shows the
opposite. Hedged statements ("may", "could") still need the evidence to show the underlying fact.
Respond with ONLY: {"label": "SUPPORTED" | "NOT_SUPPORTED" | "CONTRADICTED", "reason": "<one sentence>"}"""


def split_claims(narrative: str) -> list[dict]:
    claims = []
    for s in _SENT_RX.split(narrative.strip()):
        s = s.strip()
        if len(s) < 8:
            continue
        cited = []
        for grp in _CITE_RX.findall(s):
            cited += [a.strip() for a in grp.split(",")]
        claims.append({"text": s, "cited": cited})
    return claims


def _evidence_text(bundle: dict) -> str:
    parts = [e.get("excerpt", "") + " " + e.get("locator", "") for e in bundle.get("evidence", [])]
    parts += [f.get("claim", "") for f in bundle.get("findings", [])]
    return "\n".join(parts).lower()


def check_claim_deterministic(claim: dict, bundle: dict, rendered: Rendered) -> dict:
    text = _CITE_RX.sub("", claim["text"])
    unknown = [a for a in claim["cited"] if a not in rendered.id_map]
    observed_attack = {t for f in bundle.get("findings", []) for t in f.get("attack", [])}
    attack_ids = sorted(set(_ATTACK_RX.findall(text)))
    ev_text = _evidence_text(bundle)
    entities = set()
    for rx in _ENTITY_RXS:
        entities |= {m for m in rx.findall(text) if m not in _ENTITY_STOP}
    ungrounded = sorted(e for e in entities if e.lower().rstrip(".") not in ev_text)
    return {
        "citations_valid": not unknown,
        "unknown_citations": unknown,
        "uncited": not claim["cited"],
        "attack_ids": attack_ids,
        "attack_unknown": [t for t in attack_ids if not technique_name(t)],
        "attack_not_observed": [t for t in attack_ids if t not in observed_attack
                                and t.split(".")[0] not in {o.split(".")[0] for o in observed_attack}],
        "entities": sorted(entities),
        "ungrounded_entities": ungrounded,
        "entities_grounded": not ungrounded,
    }


def judge_claim(claim: dict, bundle: dict, rendered: Rendered, provider, *, seed: int = 0) -> dict:
    by_id = {e["id"]: e for e in bundle.get("evidence", [])}
    cited = [by_id[rendered.id_map[a]] for a in claim["cited"] if a in rendered.id_map]
    ev = "\n".join(f"[{a}] ({e['locator'][:100]}) {e['excerpt'][:600]}"
                   for a, e in zip([a for a in claim["cited"] if a in rendered.id_map], cited))
    prompt = (f"SENTENCE:\n{claim['text']}\n\nCITED EVIDENCE:\n{ev or '(nothing cited)'}\n\n"
              f"Reply with the JSON object only.")
    try:
        g = provider.generate(CLAIM_SYSTEM, prompt, temperature=0.0, seed=seed, json_mode=True,
                              max_tokens=200)
    except Exception as e:
        return {"label": "ERROR", "reason": f"{type(e).__name__}: {str(e)[:120]}"}
    obj = parse_judge_output(g.text) or {}
    label = str(obj.get("label", "")).strip().upper()
    if label not in CLAIM_LABELS:
        return {"label": "UNPARSEABLE", "reason": (g.text or "")[:200]}
    return {"label": label, "reason": str(obj.get("reason", ""))[:300]}


def narrate(bundle: dict, provider, *, seed: int = 0) -> str:
    r = render_evidence(bundle, mode="provenance")
    g = provider.generate(NARRATIVE_SYSTEM, r.text, temperature=0.0, seed=seed, json_mode=False,
                          max_tokens=700)
    return g.text.strip()


def verify_narrative(narrative: str, bundle: dict, judge_provider=None) -> dict:
    rendered = render_evidence(bundle, mode="provenance")
    claims = []
    for i, c in enumerate(split_claims(narrative)):
        det = check_claim_deterministic(c, bundle, rendered)
        lj = judge_claim(c, bundle, rendered, judge_provider) if judge_provider else None
        claims.append({"idx": i, **c, "deterministic": det, "judge": lj})
    n = len(claims)
    judged = [c for c in claims if c["judge"] and c["judge"]["label"] in CLAIM_LABELS]
    summary = {
        "uncited": sum(c["deterministic"]["uncited"] for c in claims),
        "invalid_citations": sum(not c["deterministic"]["citations_valid"] for c in claims),
        "ungrounded_entities": sum(not c["deterministic"]["entities_grounded"] for c in claims),
        "attack_not_observed": sum(bool(c["deterministic"]["attack_not_observed"]) for c in claims),
        "judge_supported": sum(c["judge"]["label"] == "SUPPORTED" for c in judged),
        "judge_unsupported": sum(c["judge"]["label"] != "SUPPORTED" for c in judged),
    }
    summary["supported_rate"] = summary["judge_supported"] / len(judged) if judged else None
    return {"n_claims": n, "claims": claims, "summary": summary}


def deterministic_flags(det: dict) -> str:
    flags = []
    if det["uncited"]:
        flags.append("uncited")
    if not det["citations_valid"]:
        flags.append("invalid_citation")
    if det["ungrounded_entities"]:
        flags.append("ungrounded:" + "|".join(det["ungrounded_entities"][:5]))
    if det["attack_not_observed"]:
        flags.append("attack_not_observed:" + "|".join(det["attack_not_observed"]))
    return ";".join(flags)


_ANN_FIELDS = ["claim_id", "sha256", "claim", "evidence", "judge_label", "deterministic_flags",
               "human_label", "human_note"]


def export_annotation_csv(rows: list[dict], path) -> Path:
    """Blind-ish annotation sheet: annotators fill human_label with
    SUPPORTED / NOT_SUPPORTED / CONTRADICTED. (Hide the judge_label column
    when annotating if you want fully blind labels.)"""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=_ANN_FIELDS)
        w.writeheader()
        for r in rows:
            w.writerow({k: _csv_safe(r.get(k, "")) for k in _ANN_FIELDS})
    return p


def _csv_safe(value) -> str:
    """Claims and evidence quote attacker-controlled sample text: neutralise
    spreadsheet formula injection (a leading = + - @ tab or CR is executed
    by Excel/LibreOffice) by prefixing a single quote."""
    s = "" if value is None else str(value)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def import_annotations(path) -> dict:
    rows = [{k: (v[1:] if isinstance(v, str) and v.startswith("'") else v) for k, v in r.items()}
            for r in csv.DictReader(open(path, encoding="utf-8"))]
    rows = [r for r in rows
            if (r.get("human_label") or "").strip().upper() in CLAIM_LABELS
            and (r.get("judge_label") or "").strip().upper() in CLAIM_LABELS]
    h = [r["human_label"].strip().upper() for r in rows]
    j = [r["judge_label"].strip().upper() for r in rows]
    if not rows:
        return {"n": 0}
    hb = [x != "SUPPORTED" for x in h]
    jb = [x != "SUPPORTED" for x in j]
    tp = sum(a and b for a, b in zip(hb, jb))
    return {"n": len(rows), "agreement": sum(a == b for a, b in zip(h, j)) / len(rows),
            "kappa_3class": cohen_kappa(h, j), "kappa_binary": cohen_kappa(hb, jb),
            "human_unsupported_rate": sum(hb) / len(rows),
            "judge_unsupported_precision": tp / sum(jb) if sum(jb) else None,
            "judge_unsupported_recall": tp / sum(hb) if sum(hb) else None}


def run_claims(bundles: list[dict], narrator, judge, out_path, progress: bool = True) -> int:
    """One JSONL record per bundle: the narrator's narrative and its claim-level
    verification by the judge. Resumable by sha256."""
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    done = set()
    if out.exists():
        for line in out.read_text(encoding="utf-8").splitlines():
            try:
                done.add(json.loads(line)["sha256"])
            except (json.JSONDecodeError, KeyError):
                pass
    n = 0
    with open(out, "a", encoding="utf-8") as fh:
        for b in bundles:
            if b["sha256"] in done:
                continue
            try:
                narrative = narrate(b, narrator)
            except Exception as e:
                narrative = ""
                err = f"{type(e).__name__}: {str(e)[:200]}"
            else:
                err = None
            ver = verify_narrative(narrative, b, judge) if narrative else {"n_claims": 0, "claims": [],
                                                                           "summary": {}}
            fh.write(json.dumps({"sha256": b["sha256"], "label": b["label"], "format": b.get("format"),
                                 "split": (b.get("meta") or {}).get("split"),
                                 "narrator": f"{narrator.name}:{narrator.model}",
                                 "judge": f"{judge.name}:{judge.model}", "error": err,
                                 "narrative": narrative, **ver}) + "\n")
            fh.flush()
            n += 1
            if progress:
                print(f"[claims] {n} {b['sha256'][:12]} claims={ver['n_claims']} "
                      f"supported_rate={ver.get('summary', {}).get('supported_rate')}", flush=True)
    return n


def annotation_rows(records: list[dict], bundles_by_sha: dict, k: int = 300, seed: int = 7) -> list[dict]:
    import random
    rows = []
    for r in records:
        b = bundles_by_sha.get(r["sha256"])
        if not b:
            continue
        rendered = render_evidence(b, mode="provenance")
        by_id = {e["id"]: e for e in b["evidence"]}
        for c in r.get("claims", []):
            ev = "\n".join(f"[{a}] {by_id[rendered.id_map[a]]['excerpt'][:400]}"
                           for a in c["cited"] if a in rendered.id_map)
            rows.append({"claim_id": f"{r['sha256'][:12]}:{c['idx']}", "sha256": r["sha256"],
                         "claim": c["text"], "evidence": ev,
                         "judge_label": (c.get("judge") or {}).get("label", ""),
                         "deterministic_flags": deterministic_flags(c["deterministic"])})
    random.Random(seed).shuffle(rows)
    return rows[:k]
