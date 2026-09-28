"""Batch evidence-bundle building over a labelled manifest.

Manifest columns: path,label[,file_type,source,first_seen,split]. Extra
columns travel into bundle['meta']. Resumable: a sample whose bundle
already exists is skipped. Parallel across processes (each sample's
triage is independent); failures are recorded, never silently dropped.

Live-observed failure mode this module defends against: enough parallel
workers each loading the EMBER/LightGBM classifier can exhaust RAM
(OpenBLAS's allocator gives up rather than swapping gracefully), which
kills a worker process and breaks the whole ProcessPoolExecutor --
concurrent.futures then raises BrokenExecutor out of every future still
pending in that pool, not just the one that died. Treating that the same
as an ordinary per-sample error would have silently written a corrupted
'errors' record for samples that never actually ran, and previously (real
incident, 2026-09-28) let a driving script's exit-code check go
unnoticed and proceed to score judge experiments against a small
accidental fraction of the intended dataset. build_bundles() instead
restarts the pool and retries whatever was lost, and only gives up -- with
an honest, accurate count of what remains -- after repeated crashes;
nothing is ever recorded as failed for a sample that merely lost its
worker, so a later call (real executor, ideally with fewer --workers)
resumes it exactly like any other not-yet-built sample."""
from __future__ import annotations
import csv
import hashlib
import json
import os
import traceback
from concurrent.futures import BrokenExecutor, ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import Callable, Optional


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


def build_bundles(manifest, out_dir, workers: int = 4, limit: Optional[int] = None, *,
                  executor_factory: Optional[Callable[[], object]] = None,
                  max_pool_restarts: int = 3) -> dict:
    rows = read_manifest(manifest)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    todo = [r for r in rows if not (out / f"{_sha256_file(r['path'])}.json").exists()]
    if limit is not None:
        todo = todo[:limit]
    print(f"[bundles] {len(rows)} in manifest, {len(rows) - len(todo)} already built, "
          f"{len(todo)} to build with {workers} worker(s)", flush=True)

    make_executor = executor_factory or (lambda: ProcessPoolExecutor(max_workers=workers))
    errors: dict[str, str] = {}
    done = 0
    remaining = {r["path"]: r for r in todo}
    restarts = 0

    while remaining:
        pending = dict(remaining)
        pool_broke = False
        with make_executor() as ex:
            fut_to_path = {ex.submit(_worker, r, str(out)): p for p, r in pending.items()}
            for fut in as_completed(fut_to_path):
                try:
                    path, err = fut.result()
                except BrokenExecutor:
                    # The pool died -- every future still pending in it raises
                    # this, not just the one that actually crashed. None of
                    # them ran to completion, so leave them in `remaining`
                    # untouched for the next (fresh-pool) round rather than
                    # recording a false error.
                    pool_broke = True
                    continue
                remaining.pop(path, None)
                done += 1
                if err:
                    errors[path] = err
                print(f"[bundles] {done}/{len(todo)} {'ERR ' if err else ''}{os.path.basename(path)}",
                      flush=True)
        if not pool_broke:
            break
        restarts += 1
        if restarts > max_pool_restarts:
            print(f"[bundles] worker pool crashed {restarts} time(s) in a row (likely out of "
                  f"memory -- {workers} parallel workers may be too many for this machine); "
                  f"giving up with {len(remaining)} sample(s) not built. Re-run this command "
                  f"(same manifest/--out) with fewer --workers to pick up where it left off.",
                  flush=True)
            break
        print(f"[bundles] worker pool crashed (likely out of memory) -- restarting the pool "
              f"({restarts}/{max_pool_restarts}); {len(remaining)} sample(s) still pending",
              flush=True)

    if errors:
        (out / "_errors.json").write_text(json.dumps(errors, indent=1), encoding="utf-8")
    return {"built": done - len(errors), "errors": len(errors),
            "skipped": len(rows) - len(todo), "not_built": len(remaining)}
