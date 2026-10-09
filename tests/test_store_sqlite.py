"""SqliteRepository: a local, file-based persistence backend for the web
UI -- same Repository interface as
PostgresRepository, but plain TEXT columns (SQLite has no native JSONB
type) via the stdlib sqlite3 module, no server process or extra
dependency required. Distinct from InMemoryRepository (which doesn't
survive past a single process) and PostgresRepository (which needs a
running Postgres server) -- this is what the web app defaults to."""
from __future__ import annotations
from malagent.contracts import (AnalysisState, AuditRecord, EgressPolicy, Provenance,
                                Sample, StepBudget, Verdict)
from malagent.store import SqliteRepository, get_repository


def _sample():
    return Sample(sha256="a" * 64, md5="b" * 32, path="/tmp/x.malz",
                  file_type="PE", size=10, provenance=Provenance())


def _state(run_id="r1"):
    return AnalysisState(run_id=run_id, sample=_sample(), policy=EgressPolicy(),
                         budget=StepBudget())


def _verdict():
    return Verdict(sample_sha256="a" * 64, verdict="malicious", confidence=0.9)


def test_save_and_get_verdict_round_trips(tmp_path):
    repo = SqliteRepository(str(tmp_path / "test.db"))
    repo.save_run(_state(), _verdict())
    got = repo.get_verdict("a" * 64)
    assert got is not None
    assert got.verdict == "malicious"
    assert got.confidence == 0.9


def test_get_verdict_returns_none_when_absent(tmp_path):
    repo = SqliteRepository(str(tmp_path / "test.db"))
    assert repo.get_verdict("nonexistent") is None


def test_save_run_is_idempotent_on_repeated_run_id(tmp_path):
    repo = SqliteRepository(str(tmp_path / "test.db"))
    repo.save_run(_state("r1"), _verdict())
    repo.save_run(_state("r1"), _verdict())  # must not raise on duplicate run_id


def test_saving_a_new_verdict_for_the_same_sample_updates_it(tmp_path):
    repo = SqliteRepository(str(tmp_path / "test.db"))
    repo.save_run(_state("r1"), _verdict())
    updated = Verdict(sample_sha256="a" * 64, verdict="benign", confidence=0.6)
    repo.save_run(_state("r2"), updated)
    got = repo.get_verdict("a" * 64)
    assert got.verdict == "benign"


def test_append_audit_is_idempotent_on_repeated_seq(tmp_path):
    repo = SqliteRepository(str(tmp_path / "test.db"))
    rec = AuditRecord(seq=1, run_id="r1", action="test", detail={}, prev_hash="", record_hash="h1")
    repo.append_audit(rec)
    repo.append_audit(rec)  # must not raise on duplicate (run_id, seq)


def test_data_persists_across_repository_instances_on_the_same_file(tmp_path):
    """The whole point of SQLite over InMemoryRepository: a second
    connection to the same file sees what the first one wrote."""
    path = str(tmp_path / "test.db")
    SqliteRepository(path).save_run(_state(), _verdict())
    reopened = SqliteRepository(path)
    assert reopened.get_verdict("a" * 64) is not None


def test_get_repository_dispatches_to_sqlite_for_sqlite_url(monkeypatch, tmp_path):
    db_path = tmp_path / "via_url.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")
    repo = get_repository()
    assert isinstance(repo, SqliteRepository)
    repo.save_run(_state(), _verdict())
    assert db_path.exists()
