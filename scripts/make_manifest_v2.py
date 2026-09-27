#!/usr/bin/env python3
"""Assemble dataset/manifest_v2.csv from the v1 sets and the v2 collections.

Columns: path,label,file_type,source,first_seen,split

Split protocol (fixed before any judge experiment is run):
  - malicious: TEMPORAL. first_seen < 2026-09-05 -> 'dev', else 'test'.
    The v1 sets (first seen 2025 - 2026-08) are all 'dev'.
  - benign: no first-seen date exists, so a seeded 40/60 random split,
    stratified by file_type. v1 benign (Windows System32 + the 12 third-party
    held-out executables) is 'dev'.
'dev' is the only data used to develop prompts, routing thresholds and the
judge protocol; every headline number is reported on 'test'.
"""
from __future__ import annotations
import csv
import random
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DS = REPO / "dataset"
CUTOFF = "2026-09-05"


def _rel(p: Path) -> str:
    return str(p.relative_to(REPO)).replace("\\", "/")


def main() -> int:
    rng = random.Random(7)
    rows = []
    # v1
    first_seen = {}
    ov = DS / "ember_overlap_check.csv"
    if ov.exists():
        for r in csv.DictReader(open(ov, encoding="utf-8")):
            first_seen[r["hash"].lower()] = r["first_seen"][:10]
    for sub, label in (("malicious", "malicious"), ("malicious_heldout", "malicious"),
                       ("benign", "benign"), ("benign_heldout", "benign")):
        for f in sorted((DS / sub).glob("*")):
            if f.is_file():
                rows.append(dict(path=_rel(f), label=label, file_type="v1", source="v1:" + sub,
                                 first_seen=first_seen.get(f.stem.lower(), ""), split="dev"))
    # v2 malicious
    mal_meta = {}
    if (DS / "malicious_v2_meta.csv").exists():
        for r in csv.DictReader(open(DS / "malicious_v2_meta.csv", encoding="utf-8")):
            mal_meta[r["sha256"].lower()] = r
    mal_files = sorted((DS / "malicious_v2").rglob("*.bin")) + sorted((DS / "malicious_v2_tags").rglob("*.bin"))
    for f in mal_files:
        m = mal_meta.get(f.stem.lower(), {})
        fs = (m.get("first_seen") or "")[:10]
        rows.append(dict(path=_rel(f), label="malicious", file_type=f.parent.name,
                         source="malwarebazaar", first_seen=fs,
                         split="test" if fs and fs >= CUTOFF else "dev"))
    # v2 benign, stratified seeded split
    by_type = defaultdict(list)
    for f in sorted((DS / "benign_v2").rglob("*.bin")):
        by_type[f.parent.name].append(f)
    for t, files in sorted(by_type.items()):
        rng.shuffle(files)
        n_dev = round(len(files) * 0.4)
        for i, f in enumerate(files):
            rows.append(dict(path=_rel(f), label="benign", file_type=t, source="benign_v2",
                             first_seen="", split="dev" if i < n_dev else "test"))
    out = DS / "manifest_v2.csv"
    with open(out, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["path", "label", "file_type", "source", "first_seen", "split"])
        w.writeheader()
        w.writerows(rows)
    c = defaultdict(int)
    for r in rows:
        c[(r["split"], r["label"])] += 1
    print(f"wrote {len(rows)} rows -> {out}")
    for k in sorted(c):
        print(f"  {k[0]:5s} {k[1]:10s} {c[k]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
