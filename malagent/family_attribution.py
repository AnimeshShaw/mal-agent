"""Family attribution + macro-F1 scoring (M6).

WHY THIS EXISTS: dataset/malicious/ was fetched across several
scripts/fetch_malwarebazaar.py batches (AgentTesla, RedLineStealer, Emotet;
later Lokibot, Formbook, Remcos, AsyncRAT, njRAT), but that script never
persisted which hash came from which --tags query -- files are saved named
only by sha256. There is therefore no locally-recorded ground truth. Real
ground truth is fetched fresh and honestly from MalwareBazaar's own
get_info API (scripts/fetch_family_ground_truth.py) into
dataset/family_ground_truth.csv. If a lookup fails or returns no family,
it is recorded "unknown" -- never guessed, never silently dropped.

TWO REAL SIGNALS, BOTH HONESTLY WEAK FOR THIS DATASET:

1. capa's own 'malware-family' namespace rules. Checked against the real
   capa-rules-9.4.0 corpus: this namespace contains exactly two rule
   families -- donut-loader and plugx. Neither applies to this project's
   fetched families. Confirmed empirically: a live capa run against a real
   AsyncRAT .NET sample from dataset/malicious/ matched 52 rules across
   anti-analysis/communication/data-manipulation/executable/host-interaction/
   internal/load-code/persistence/runtime -- zero under malware-family. This
   signal is implemented and tested because it is real and free to check
   when present (and capa's rule corpus does grow over time), but expect it
   to contribute nothing for AgentTesla/RedLineStealer/Emotet/Lokibot/
   Formbook/Remcos/AsyncRAT/njRAT specifically.

2. imphash nearest-neighbor. Samples built by the same builder/packer often
   share an identical PE import table (a standard, cheap clustering signal
   -- VT and threat-intel platforms track known-bad imphashes the same
   way). Evaluated here via LEAVE-ONE-OUT against this project's own
   fetched dataset: for each sample, every OTHER sample's ground-truth
   label is used as the reference set, and the target's family is
   predicted by majority vote among same-imphash neighbors. This is the
   only honest evaluation methodology available -- there is no external
   imphash-to-family reference database in this project -- but it means
   the resulting macro-F1 measures "does this dataset's own imphash
   clustering agree with MalwareBazaar's real labels", not real-world
   generalization to a sample built with a different imphash. It is also
   fundamentally blind to non-PE samples (scripts, installers wrapping a
   script, ISO droppers) -- a real, material chunk of this dataset -- since
   imphash requires a PE import table pefile can parse.

Both signals are combined deterministically (attribute_family): a capa
malware-family hit wins if present, else the imphash cluster vote, else
"unknown". No LLM is involved in this module at all -- reporter.build_verdict
remains the only thing that decides malicious/benign, and this module does
not touch it.

MEASURED RESULT (live, `mal-agent family-attribution`, 2026-07-27, against
this project's real 45-sample dataset/malicious/ and real MalwareBazaar
ground truth): macro-F1 = 0.0952 across 11 families, 44 scored samples (1
excluded as ground-truth "unknown"). This is genuinely weak, and the
dominant reason is diagnosable, not mysterious: many .NET-built samples
across DIFFERENT families (AgentTesla, AsyncRAT, RedLineStealer, Formbook,
njRAT, ...) share the exact same imphash (observed live:
f34d5f2d4577ed6d9ceec516c1f5a744) because .NET assemblies typically only
import mscoree.dll's CLR entry point natively -- the real dispatch happens
in managed IL, invisible to a native import-table hash. That collapses the
leave-one-out neighbor vote into noise for every family sharing it.
RedLineStealer (native, not .NET, in these samples) got imphash precision
1.0 / recall 0.4 off one genuinely distinctive shared imphash
(70d2e884fa127843c5bcbb53da86b6c8) -- proof the signal *can* work, just
rarely does across this dataset's mostly-.NET commodity malware. Singleton
families (LockBit, Phorpiex, Lokibot: 1 sample each) can never be predicted
correctly under leave-one-out almost by construction -- there is no "other"
sample of that family to vote from. capa's malware-family signal
contributed nothing (confirmed live, 0/0 hits across 3 real samples of
different types: a .NET AsyncRAT PE, a native Formbook PE, and an NSIS
AsyncRAT installer)."""
from __future__ import annotations
import csv
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

UNKNOWN = "unknown"


# ---------- capa 'malware-family' namespace ----------

def extract_capa_malware_family_hits(capa_doc: Optional[dict]) -> list[str]:
    """Rule names whose top-level namespace is 'malware-family', mapped to
    the family label (the namespace's second segment, e.g.
    'malware-family/plugx' -> 'plugx'; falls back to the raw rule name if
    the namespace has no second segment)."""
    if not capa_doc:
        return []
    rules = capa_doc.get("rules", {}) or {}
    hits: list[str] = []
    for rule_name, rule in rules.items():
        namespace = ((rule or {}).get("meta", {}) or {}).get("namespace", "") or ""
        parts = namespace.split("/")
        if parts and parts[0] == "malware-family":
            hits.append(parts[1] if len(parts) > 1 and parts[1] else rule_name)
    return hits


def compute_capa_family_hits(sample_path: str, size: Optional[int] = None) -> list[str]:
    """Runs real capa (same command construction as CapaTool) and extracts
    only the malware-family namespace hits. Degrades to [] on any failure
    (capa missing, oversized sample, crash, timeout) -- this is a bonus
    signal, never a hard dependency."""
    import os
    import shutil
    import subprocess
    import json as _json
    from .tools import _capa_command, _CAPA_MAX_SIZE_BYTES

    if not shutil.which("capa"):
        return []
    if size is None:
        try:
            size = os.path.getsize(sample_path)
        except OSError:
            return []
    if size > _CAPA_MAX_SIZE_BYTES:
        return []
    try:
        out = subprocess.run(_capa_command(sample_path), capture_output=True, timeout=300)
        doc = _json.loads(out.stdout.decode("utf-8", "ignore"))
    except Exception:
        return []
    return extract_capa_malware_family_hits(doc)


# ---------- imphash ----------

def compute_imphash(sample_path: str) -> Optional[str]:
    """Thin pefile wrapper, mirroring PEHeaderTool's own imphash computation
    (malagent/tools.py) but standalone -- this module runs outside the main
    analyze() pipeline as a batch/evaluation heuristic. Degrades to None on
    any failure (not a PE, no import table, pefile error)."""
    try:
        import pefile  # type: ignore
        pe = pefile.PE(sample_path, fast_load=True)
        # fast_load skips the import-table directory entirely -- without
        # this, get_imphash() silently returns "" instead of raising,
        # which looks like "no imports" instead of "we never looked".
        # Same gotcha PEHeaderTool (malagent/tools.py) already works
        # around; confirmed live against a real dataset sample.
        pe.parse_data_directories()
        imphash = pe.get_imphash()
    except Exception:
        return None
    return imphash or None


def predict_family_by_imphash(target_hash: str, target_imphash: Optional[str],
                              imphash_by_hash: dict, family_by_hash: dict) -> Optional[str]:
    """Majority vote among OTHER hashes sharing target_imphash, using only
    entries in family_by_hash with a known (non-'unknown') label. Ties are
    broken alphabetically for determinism. Returns None when there is no
    usable neighbor."""
    if not target_imphash:
        return None
    votes: dict[str, int] = {}
    for h, imphash in imphash_by_hash.items():
        if h == target_hash or imphash != target_imphash:
            continue
        fam = family_by_hash.get(h)
        if not fam or fam == UNKNOWN:
            continue
        votes[fam] = votes.get(fam, 0) + 1
    if not votes:
        return None
    max_votes = max(votes.values())
    winners = sorted(f for f, v in votes.items() if v == max_votes)
    return winners[0]


# ---------- combining signals ----------

@dataclass(frozen=True)
class FamilyAttribution:
    sha256: str
    predicted_family: str
    method: str  # "capa_malware_family" | "imphash_cluster" | "none"


def attribute_family(sha256: str, *, capa_family_hits: Optional[list[str]] = None,
                     imphash: Optional[str] = None,
                     imphash_by_hash: Optional[dict] = None,
                     family_by_hash: Optional[dict] = None) -> FamilyAttribution:
    """Deterministic priority: a real capa malware-family hit wins (it's
    the more specific signal when present); otherwise fall back to the
    imphash cluster vote; otherwise honestly 'unknown'."""
    if capa_family_hits:
        return FamilyAttribution(sha256=sha256, predicted_family=sorted(capa_family_hits)[0],
                                 method="capa_malware_family")
    predicted = predict_family_by_imphash(sha256, imphash, imphash_by_hash or {},
                                          family_by_hash or {})
    if predicted:
        return FamilyAttribution(sha256=sha256, predicted_family=predicted, method="imphash_cluster")
    return FamilyAttribution(sha256=sha256, predicted_family=UNKNOWN, method="none")


def predict_all_leave_one_out(imphash_by_hash: dict, ground_truth: dict,
                              capa_family_hits_by_hash: Optional[dict] = None
                              ) -> dict[str, FamilyAttribution]:
    """Predicts every hash's family using every OTHER hash's ground-truth
    label as the reference set (leave-one-out) -- see module docstring for
    why this is the only honest evaluation available without an external
    imphash reference database."""
    capa_family_hits_by_hash = capa_family_hits_by_hash or {}
    predictions: dict[str, FamilyAttribution] = {}
    for h, imphash in imphash_by_hash.items():
        family_by_hash = {k: v for k, v in ground_truth.items() if k != h}
        predictions[h] = attribute_family(
            h, capa_family_hits=capa_family_hits_by_hash.get(h), imphash=imphash,
            imphash_by_hash=imphash_by_hash, family_by_hash=family_by_hash)
    return predictions


# ---------- ground truth ----------

def load_family_ground_truth(csv_path: str) -> dict[str, str]:
    """CSV as written by scripts/fetch_family_ground_truth.py: hash,family,...
    Empty/missing family is treated as 'unknown', matching that script's own
    honest-abstention convention -- never a guess."""
    gt: dict[str, str] = {}
    with open(csv_path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            gt[row["hash"].strip()] = (row.get("family") or UNKNOWN).strip() or UNKNOWN
    return gt


# ---------- macro-F1 ----------

@dataclass
class ClassScore:
    precision: float
    recall: float
    f1: float
    support: int


@dataclass
class FamilyMacroF1Report:
    classes: list = field(default_factory=list)
    per_class: dict = field(default_factory=dict)
    macro_f1: Optional[float] = None
    scored_samples: int = 0
    excluded_unknown_ground_truth: int = 0
    unscored_missing_predictions: int = 0
    predictions: dict = field(default_factory=dict)


def compute_macro_f1(predictions: dict, ground_truth: dict) -> FamilyMacroF1Report:
    """Standard macro-F1 across family classes. Ground-truth rows labeled
    'unknown' (MalwareBazaar itself couldn't tell) are excluded entirely --
    there is no true label to score against, and scoring 'unknown' as a
    class would let a heuristic farm points by also guessing 'unknown'. A
    hash with a real label but no prediction at all still counts as a
    recall miss for its true class (tracked, never silently dropped)."""
    excluded_unknown = sum(1 for fam in ground_truth.values() if fam == UNKNOWN)
    labeled_hashes = [h for h, fam in ground_truth.items() if fam != UNKNOWN]
    scored_hashes = [h for h in labeled_hashes if h in predictions]
    missing = len(labeled_hashes) - len(scored_hashes)
    classes = sorted({ground_truth[h] for h in labeled_hashes})

    per_class: dict[str, ClassScore] = {}
    for cls in classes:
        tp = sum(1 for h in scored_hashes if predictions[h] == cls and ground_truth[h] == cls)
        fp = sum(1 for h in scored_hashes if predictions[h] == cls and ground_truth[h] != cls)
        fn_scored = sum(1 for h in scored_hashes if predictions[h] != cls and ground_truth[h] == cls)
        fn_missing = sum(1 for h in labeled_hashes if h not in predictions and ground_truth[h] == cls)
        fn = fn_scored + fn_missing
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
        per_class[cls] = ClassScore(precision=precision, recall=recall, f1=f1, support=tp + fn)

    macro_f1 = (sum(c.f1 for c in per_class.values()) / len(classes)) if classes else None
    return FamilyMacroF1Report(classes=classes, per_class=per_class, macro_f1=macro_f1,
                               scored_samples=len(scored_hashes),
                               excluded_unknown_ground_truth=excluded_unknown,
                               unscored_missing_predictions=missing)


def format_family_report(report: FamilyMacroF1Report) -> str:
    lines = [
        "FAMILY ATTRIBUTION MACRO-F1 REPORT",
        "=" * 40,
        f"Scored samples: {report.scored_samples}  "
        f"(excluded unknown ground truth: {report.excluded_unknown_ground_truth}, "
        f"missing predictions: {report.unscored_missing_predictions})",
        f"Families scored: {len(report.classes)}",
        "-" * 40,
    ]
    for cls in report.classes:
        cs = report.per_class[cls]
        lines.append(f"{cls:20s} precision={cs.precision:.3f} recall={cs.recall:.3f} "
                     f"f1={cs.f1:.3f} support={cs.support}")
    lines.append("-" * 40)
    lines.append(f"macro-F1: {report.macro_f1:.4f}" if report.macro_f1 is not None else "macro-F1: n/a")
    return "\n".join(lines)


# ---------- end-to-end orchestration ----------

def run_family_attribution(dataset_malicious_dir: str, ground_truth_csv: str, *,
                           imphash_fn: Callable[[str], Optional[str]] = compute_imphash,
                           capa_family_hits_by_hash: Optional[dict] = None
                           ) -> FamilyMacroF1Report:
    """Real end-to-end run: computes imphash for every <sha256>.bin under
    dataset_malicious_dir, loads real ground truth from ground_truth_csv,
    predicts every sample's family via leave-one-out imphash clustering
    (plus any supplied real capa malware-family hits, which take priority
    when present), and scores macro-F1. imphash_fn is injectable so tests
    don't need a real pefile-parseable binary on disk."""
    ground_truth = load_family_ground_truth(ground_truth_csv)
    sample_dir = Path(dataset_malicious_dir)
    hashes = sorted(p.stem for p in sample_dir.iterdir() if p.is_file() and p.suffix == ".bin")
    imphash_by_hash = {h: imphash_fn(str(sample_dir / f"{h}.bin")) for h in hashes}
    predictions = predict_all_leave_one_out(imphash_by_hash, ground_truth, capa_family_hits_by_hash)
    predicted_family = {h: r.predicted_family for h, r in predictions.items()}
    report = compute_macro_f1(predicted_family, ground_truth)
    report.predictions = predictions
    return report
