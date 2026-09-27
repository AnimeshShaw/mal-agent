#!/usr/bin/env python3
"""Build the dataset-v2 malicious set from MalwareBazaar daily batches.

Reads dataset/_sources/mb_daily_<date>.zip (AES, password 'infected') entry
by entry IN MEMORY, identifies each sample's real format from its content
(malagent.format_triage.detect_format -- never the file extension), and
writes a stratified selection to dataset/malicious_v2/<format>/<sha256>.bin.
Nothing is executed. first_seen is the batch date, which is what the
temporal split uses. Hashes already present anywhere under dataset/ are
skipped (no overlap with the v1 calibration/held-out sets).

PE and ELF dominate the feed, so they are capped; every other format is
taken up to its cap, spread evenly across the batches.

Usage: python scripts/select_mb_daily.py [--seed 7]
"""
from __future__ import annotations
import argparse
import csv
import hashlib
import random
import sys
from collections import defaultdict
from pathlib import Path

import pyzipper

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
from malagent.format_triage import detect_format  # noqa: E402

SRC = REPO / "dataset" / "_sources"
OUT = REPO / "dataset" / "malicious_v2"
META = REPO / "dataset" / "malicious_v2_meta.csv"
CAPS = {"pe": 220, "elf": 50, "macho": 10, "script_js": 60, "script_vbs": 60, "script_ps1": 60,
        "script_bat": 60, "script_hta": 60, "text": 30, "lnk": 60, "ole": 60, "ooxml": 60,
        "rtf": 60, "pdf": 60, "onenote": 40, "zip": 50, "archive": 40, "iso": 30, "unknown": 20}
MAX_BYTES = 40_000_000


def _existing() -> set[str]:
    return {f.stem.lower() for f in (REPO / "dataset").rglob("*.bin") if len(f.stem) == 64}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()
    rng = random.Random(args.seed)
    existing = _existing()
    batches = sorted(SRC.glob("mb_daily_*.zip"))
    per_fmt_per_batch = defaultdict(lambda: defaultdict(list))  # fmt -> batch -> [(name)]

    # pass 1: classify every entry (reads each file once, keeps only names)
    for b in batches:
        with pyzipper.AESZipFile(b) as zf:
            zf.pwd = b"infected"
            for info in zf.infolist():
                if info.is_dir() or info.file_size > MAX_BYTES:
                    continue
                sha = Path(info.filename).stem.lower()
                if len(sha) != 64 or sha in existing:
                    continue
                with zf.open(info) as fh:
                    head = fh.read(70000)
                per_fmt_per_batch[detect_format(head)][b.name].append(info.filename)
        print(f"classified {b.name}", flush=True)

    # pass 2: round-robin across batches up to each format's cap
    chosen = defaultdict(list)  # batch -> [(fmt, name)]
    for fmt, by_batch in per_fmt_per_batch.items():
        cap = CAPS.get(fmt, 20)
        pools = {bn: rng.sample(names, len(names)) for bn, names in by_batch.items()}
        picked = 0
        while picked < cap and any(pools.values()):
            for bn in sorted(pools):
                if pools[bn] and picked < cap:
                    chosen[bn].append((fmt, pools[bn].pop()))
                    picked += 1
        print(f"{fmt:12s} available={sum(len(v) for v in by_batch.values()):5d} chosen={picked}")

    new_meta = not META.exists() or META.stat().st_size == 0
    with open(META, "a", newline="", encoding="utf-8") as mfh:
        w = csv.writer(mfh)
        if new_meta:
            w.writerow(["sha256", "file_type", "first_seen", "signature", "tags"])
        total = 0
        for b in batches:
            date = b.stem.replace("mb_daily_", "")
            with pyzipper.AESZipFile(b) as zf:
                zf.pwd = b"infected"
                for fmt, name in chosen.get(b.name, []):
                    data = zf.read(name)
                    sha = hashlib.sha256(data).hexdigest()
                    d = OUT / fmt
                    d.mkdir(parents=True, exist_ok=True)
                    (d / f"{sha}.bin").write_bytes(data)
                    w.writerow([sha, fmt, date, "", Path(name).suffix.lstrip(".")])
                    total += 1
    print(f"wrote {total} samples to {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
