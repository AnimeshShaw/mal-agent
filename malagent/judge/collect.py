"""Batch evidence-bundle building over a labelled manifest.

Manifest columns: path,label[,file_type,source,first_seen,split]. Extra
columns travel into bundle['meta']. Resumable: a sample whose bundle
already exists is skipped. Parallel across processes (each sample's
triage is independent); failures are recorded, never silently dropped."""
from __future__ import annotations
import csv
import hashlib
import json
import os
import traceback
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import Optional


def read_manifest(path) -> list[dict]:
    with open(path, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    for r in rows:
        if r.get("label") not in ("malicious", "benign"):
            raise ValueError(f"bad label {r.get('label')!r} for {r.get('path')!r}")
    return rows


def _sha256_file(p: str) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _worker(row: dict, out_dir: str) -> tuple[str, Optional[str]]:
    # Keep per-process output quiet: the triage tools print progress lines.
    import contextlib
    import io
    from .bundle import analyze_for_bundle, save_bundle
    meta = {k: v for k, v in row.items() if k not in ("path", "label")}
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            b = analyze_for_bundle(row["path"], label=row["label"], meta=meta)
        save_bundle(b, out_dir)
        return row["path"], None
    except Exception:
        return row["path"], traceback.format_exc(limit=3)


def build_bundles(manifest, out_dir, workers: int = 4, limit: Optional[int] = None) -> dict:
    rows = read_manifest(manifest)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    todo = [r for r in rows if not (out / f"{_sha256_file(r['path'])}.json").exists()]
    if limit is not None:
        todo = todo[:limit]
    print(f"[bundles] {len(rows)} in manifest, {len(rows) - len(todo)} already built, "
          f"{len(todo)} to build with {workers} worker(s)", flush=True)
    errors = {}
    done = 0
    with ProcessPoolExecutor(max_workers=workers) as ex:
        futs = [ex.submit(_worker, r, str(out)) for r in todo]
        for fut in as_completed(futs):
            path, err = fut.result()
            done += 1
            if err:
                errors[path] = err
            print(f"[bundles] {done}/{len(todo)} {'ERR ' if err else ''}{os.path.basename(path)}",
                  flush=True)
    if errors:
        (out / "_errors.json").write_text(json.dumps(errors, indent=1), encoding="utf-8")
    return {"built": len(todo) - len(errors), "errors": len(errors), "skipped": len(rows) - len(todo)}
