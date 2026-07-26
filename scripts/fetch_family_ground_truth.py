#!/usr/bin/env python3
"""Fetch REAL family ground truth for every sample already downloaded into
dataset/malicious/, by querying MalwareBazaar's own `get_info` API for each
sha256 hash.

WHY THIS EXISTS: scripts/fetch_malwarebazaar.py saves samples named only by
their sha256 hash -- it does not persist which --tags query produced which
hash. That means there is no local ground-truth family label for any
sample. Rather than reconstruct (guess) a label from which batch/tag was
used to fetch it, this script asks MalwareBazaar directly what it knows
about each hash today. That is the only honest source of ground truth
available here -- never fabricate or infer a label from fetch order.

If a hash's lookup fails, or MalwareBazaar returns no usable signature/tag,
the row is recorded with family "unknown" -- it is NOT dropped and NOT
guessed. See malagent/family_attribution.py for how "unknown" rows are
folded into (or excluded from) the macro-F1 computation.

AUTH: same as fetch_malwarebazaar.py -- MALWAREBAZAAR_API_KEY env var, or
a gitignored .malwarebazaar_key file at the repo root. Reuses that
script's _api_key() helper rather than duplicating the lookup logic.

Usage:
    python scripts/fetch_family_ground_truth.py
    python scripts/fetch_family_ground_truth.py --dir dataset/malicious --out dataset/family_ground_truth.csv
"""
from __future__ import annotations
import argparse
import csv
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
from fetch_malwarebazaar import API_URL, _api_key  # noqa: E402

DEFAULT_DIR = REPO_ROOT / "dataset" / "malicious"
DEFAULT_OUT = REPO_ROOT / "dataset" / "family_ground_truth.csv"


def sha256_hashes_in(dir_path: Path) -> list[str]:
    """Sample files are named <sha256>.bin (fetch_malwarebazaar.py's own
    convention) -- the hash is the stem, not recomputed from bytes, since
    that's what MalwareBazaar's get_info keys on anyway."""
    return sorted(p.stem for p in dir_path.iterdir() if p.is_file() and p.suffix == ".bin")


def lookup_family(sha256: str, key: str, session) -> dict:
    """Returns a dict with keys: hash, family, signature, tags, query_status.
    'family' is MalwareBazaar's own 'signature' field when present (that IS
    the family/malware-name field in MalwareBazaar's schema); otherwise
    honestly "unknown" -- never a guess from tags or anything else."""
    resp = session.post(API_URL, data={"query": "get_info", "hash": sha256},
                        headers={"Auth-Key": key}, timeout=30)
    resp.raise_for_status()
    result = resp.json()
    status = result.get("query_status", "")
    row = {"hash": sha256, "family": "unknown", "signature": "", "tags": "",
           "query_status": status}
    if status != "ok":
        return row
    data = result.get("data") or []
    if not data:
        return row
    entry = data[0]
    signature = (entry.get("signature") or "").strip()
    tags = entry.get("tags") or []
    row["signature"] = signature
    row["tags"] = "|".join(tags)
    row["family"] = signature if signature else "unknown"
    return row


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--dir", default=str(DEFAULT_DIR), help=f"dir of <sha256>.bin samples (default {DEFAULT_DIR})")
    p.add_argument("--out", default=str(DEFAULT_OUT), help=f"output CSV (default {DEFAULT_OUT})")
    args = p.parse_args()

    try:
        import requests
    except ImportError:
        print("error: 'requests' not installed -- pip install -e \".[full]\" first", file=sys.stderr)
        return 2

    key = _api_key()
    sample_dir = Path(args.dir)
    if not sample_dir.is_dir():
        print(f"error: {sample_dir} is not a directory", file=sys.stderr)
        return 2

    hashes = sha256_hashes_in(sample_dir)
    if not hashes:
        print(f"error: no <sha256>.bin files found under {sample_dir}", file=sys.stderr)
        return 2

    session = requests.Session()
    rows = []
    for i, h in enumerate(hashes, start=1):
        row = lookup_family(h, key, session)
        print(f"[{i}/{len(hashes)}] {h} -> family={row['family']!r} "
              f"(query_status={row['query_status']}, tags={row['tags']!r})", flush=True)
        rows.append(row)
        time.sleep(1)  # be polite to the API, same pacing as fetch_malwarebazaar.py

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["hash", "family", "signature", "tags", "query_status"])
        writer.writeheader()
        writer.writerows(rows)

    known = sum(1 for r in rows if r["family"] != "unknown")
    print(f"\nDone: {len(rows)} hashes looked up, {known} with a known family, "
          f"{len(rows) - known} unknown. Wrote {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
