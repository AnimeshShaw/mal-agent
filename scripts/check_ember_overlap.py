#!/usr/bin/env python3
"""Checks the open Phase 1 caveat (docs/ML_CLASSIFIER_PLAN.md): could any
of the original 45 malicious samples used to design CGEF's thresholds
overlap with EMBER2024's training window (VT submissions Sep 24 2023 -
Dec 14 2024)? We can't check EMBER's training set directly (no access to
its 3.2M-file manifest), but MalwareBazaar's own get_info API returns a
real first_seen timestamp per hash -- if a sample's first_seen falls
inside EMBER's training window, it's a REAL, honest overlap risk (not
proof of inclusion, since EMBER's set is a sample of that window, not
all of it -- but a first_seen date OUTSIDE the window is proof of
non-overlap for that sample)."""
from __future__ import annotations
import csv
import sys
import time
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fetch_malwarebazaar import API_URL, _api_key

EMBER_TRAIN_START = datetime(2023, 9, 24)
EMBER_TRAIN_END = datetime(2024, 12, 14)


def main():
    import requests
    key = _api_key()
    session = requests.Session()
    hashes = sorted(p.stem for p in Path("dataset/malicious").iterdir()
                    if p.is_file() and p.suffix == ".bin")

    rows = []
    in_window = 0
    for i, h in enumerate(hashes, start=1):
        resp = session.post(API_URL, data={"query": "get_info", "hash": h},
                            headers={"Auth-Key": key}, timeout=30)
        result = resp.json()
        first_seen = None
        if result.get("query_status") == "ok" and result.get("data"):
            first_seen = result["data"][0].get("first_seen")
        overlap = "?"
        if first_seen:
            try:
                dt = datetime.strptime(first_seen.split(" ")[0], "%Y-%m-%d")
                overlap = "IN_WINDOW" if EMBER_TRAIN_START <= dt <= EMBER_TRAIN_END else "outside"
                if overlap == "IN_WINDOW":
                    in_window += 1
            except ValueError:
                overlap = "unparseable"
        rows.append((h, first_seen, overlap))
        print(f"[{i}/{len(hashes)}] {h[:20]}... first_seen={first_seen} -> {overlap}", flush=True)
        time.sleep(0.5)

    with open("dataset/ember_overlap_check.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["hash", "first_seen", "ember_training_window_overlap"])
        w.writerows(rows)

    print()
    print(f"{in_window}/{len(hashes)} samples have a first_seen date inside "
         f"EMBER2024's training window ({EMBER_TRAIN_START.date()} to {EMBER_TRAIN_END.date()}).")
    print("This is NOT proof those exact files are in EMBER's training set "
         "(EMBER trained on a sample of that window, not everything submitted to VT) "
         "-- but it is the honest, real answer to 'is temporal overlap even possible'.")


if __name__ == "__main__":
    main()
