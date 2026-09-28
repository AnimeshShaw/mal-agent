"""build_bundles() resilience: a crashed worker pool (observed live: 12
parallel EMBER/LightGBM workers exhausted RAM -> OpenBLAS allocation
failure -> BrokenProcessPool) must not silently corrupt progress or lose
samples -- it restarts the pool and retries whatever was lost, and only
gives up (honestly, with an accurate count) after repeated crashes."""
from __future__ import annotations
import json
from concurrent.futures import BrokenExecutor, Future
from pathlib import Path

from malagent.judge import collect


def _manifest(tmp_path, n):
    paths = []
    for i in range(n):
        p = tmp_path / f"s{i}.bin"
        p.write_bytes(f"sample-{i}".encode())
        paths.append(str(p))
    m = tmp_path / "m.csv"
    m.write_text("path,label\n" + "\n".join(f"{p},benign" for p in paths), encoding="utf-8")
    return m, paths


class _FakeFutureExecutor:
    """A drop-in ProcessPoolExecutor substitute: submit() returns an already-
    resolved concurrent.futures.Future, so no real subprocess/multiprocessing
    is needed to test the pool-crash-recovery path."""

    def __init__(self, plan_fn):
        self.plan_fn = plan_fn

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def submit(self, fn, row, out_dir):
        fut = Future()
        outcome = self.plan_fn(row["path"])
        if outcome == "crash":
            fut.set_exception(BrokenExecutor("simulated worker pool crash"))
        elif outcome == "err":
            fut.set_result((row["path"], "Traceback: boom"))
        else:
            sha = collect._sha256_file(row["path"])
            Path(out_dir).mkdir(parents=True, exist_ok=True)
            (Path(out_dir) / f"{sha}.json").write_text("{}", encoding="utf-8")
            fut.set_result((row["path"], None))
        return fut


def test_recovers_from_one_pool_crash_and_completes(tmp_path):
    manifest, paths = _manifest(tmp_path, 4)
    rounds = {"n": 0}

    def factory():
        rounds["n"] += 1
        this_round = rounds["n"]

        def plan(path):
            idx = paths.index(path)
            if this_round == 1 and idx in (2, 3):
                return "crash"
            return "ok"

        return _FakeFutureExecutor(plan)

    result = collect.build_bundles(str(manifest), str(tmp_path / "out"), workers=2,
                                   executor_factory=factory)
    assert result == {"built": 4, "errors": 0, "skipped": 0, "not_built": 0}
    assert rounds["n"] == 2
    assert len(list((tmp_path / "out").glob("*.json"))) == 4


def test_gives_up_after_max_restarts_without_losing_anything(tmp_path):
    manifest, paths = _manifest(tmp_path, 2)

    def factory():
        return _FakeFutureExecutor(lambda path: "crash")

    result = collect.build_bundles(str(manifest), str(tmp_path / "out"), workers=2,
                                   executor_factory=factory, max_pool_restarts=2)
    assert result["built"] == 0
    assert result["not_built"] == 2
    # Nothing was written for the samples that never completed -- a later,
    # ordinary (real-executor) call resumes them exactly like any other
    # not-yet-built sample, no special-casing needed.
    assert list((tmp_path / "out").glob("*.json")) == []


def test_ordinary_worker_error_is_recorded_and_never_triggers_a_restart(tmp_path):
    manifest, paths = _manifest(tmp_path, 2)
    calls = {"n": 0}

    def factory():
        calls["n"] += 1

        def plan(path):
            return "err" if paths.index(path) == 0 else "ok"

        return _FakeFutureExecutor(plan)

    result = collect.build_bundles(str(manifest), str(tmp_path / "out"), workers=2,
                                   executor_factory=factory)
    assert calls["n"] == 1          # a per-sample error never restarts the pool
    assert result == {"built": 1, "errors": 1, "skipped": 0, "not_built": 0}
    errs = json.loads((tmp_path / "out" / "_errors.json").read_text(encoding="utf-8"))
    assert paths[0] in errs


def test_resume_skips_samples_already_built(tmp_path):
    manifest, paths = _manifest(tmp_path, 2)
    out = tmp_path / "out"
    out.mkdir()
    (out / f"{collect._sha256_file(paths[0])}.json").write_text("{}", encoding="utf-8")
    seen = []

    def factory():
        def plan(path):
            seen.append(path)
            return "ok"
        return _FakeFutureExecutor(plan)

    result = collect.build_bundles(str(manifest), str(out), workers=2, executor_factory=factory)
    assert result["skipped"] == 1 and result["built"] == 1
    assert seen == [paths[1]]
