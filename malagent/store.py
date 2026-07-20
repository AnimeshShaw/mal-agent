"""Persistence (D9). PostgreSQL is the production backend; an in-memory double
is used for tests / first run. Same Repository interface for both."""
from __future__ import annotations
import json
import os
from typing import Optional
from .contracts import AnalysisState, AuditRecord, Verdict


class InMemoryRepository:
    def __init__(self):
        self.runs: dict[str, dict] = {}
        self.verdicts: dict[str, Verdict] = {}
        self.audit: list[AuditRecord] = []

    def save_run(self, state: AnalysisState, verdict: Verdict) -> str:
        self.runs[state.run_id] = json.loads(state.model_dump_json())
        self.verdicts[verdict.sample_sha256] = verdict
        return state.run_id

    def get_verdict(self, sha256: str) -> Optional[Verdict]:
        return self.verdicts.get(sha256)

    def append_audit(self, record: AuditRecord) -> None:
        self.audit.append(record)


class PostgresRepository:
    """Thin SQLAlchemy-backed store. JSONB columns keep the schema stable while
    the contract objects evolve. Requires DATABASE_URL + sqlalchemy + psycopg2."""
    def __init__(self, url: Optional[str] = None):
        from sqlalchemy import create_engine, text
        self._text = text
        self.engine = create_engine(url or os.environ["DATABASE_URL"], future=True)
        self._init()

    def _init(self):
        with self.engine.begin() as c:
            c.execute(self._text("""
                CREATE TABLE IF NOT EXISTS runs(
                  run_id TEXT PRIMARY KEY, sample_sha256 TEXT, state JSONB,
                  created_at TIMESTAMPTZ DEFAULT now());"""))
            c.execute(self._text("""
                CREATE TABLE IF NOT EXISTS verdicts(
                  sample_sha256 TEXT PRIMARY KEY, verdict JSONB,
                  created_at TIMESTAMPTZ DEFAULT now());"""))
            c.execute(self._text("""
                CREATE TABLE IF NOT EXISTS audit(
                  run_id TEXT, seq INT, record JSONB, record_hash TEXT,
                  PRIMARY KEY(run_id, seq));"""))

    def save_run(self, state: AnalysisState, verdict: Verdict) -> str:
        with self.engine.begin() as c:
            c.execute(self._text("INSERT INTO runs(run_id,sample_sha256,state) "
                                 "VALUES(:r,:s,CAST(:j AS JSONB)) ON CONFLICT(run_id) DO NOTHING"),
                      {"r": state.run_id, "s": state.sample.sha256, "j": state.model_dump_json()})
            c.execute(self._text("INSERT INTO verdicts(sample_sha256,verdict) "
                                 "VALUES(:s,CAST(:j AS JSONB)) ON CONFLICT(sample_sha256) "
                                 "DO UPDATE SET verdict=EXCLUDED.verdict"),
                      {"s": verdict.sample_sha256, "j": verdict.model_dump_json()})
        return state.run_id

    def get_verdict(self, sha256: str) -> Optional[Verdict]:
        with self.engine.begin() as c:
            row = c.execute(self._text("SELECT verdict FROM verdicts WHERE sample_sha256=:s"),
                            {"s": sha256}).first()
        return Verdict.model_validate(row[0]) if row else None

    def append_audit(self, record: AuditRecord) -> None:
        with self.engine.begin() as c:
            c.execute(self._text("INSERT INTO audit(run_id,seq,record,record_hash) "
                                 "VALUES(:r,:q,CAST(:j AS JSONB),:h) ON CONFLICT DO NOTHING"),
                      {"r": record.run_id, "q": record.seq,
                       "j": record.model_dump_json(), "h": record.record_hash})


def get_repository():
    """Postgres if DATABASE_URL is set and deps available, else in-memory."""
    if os.getenv("DATABASE_URL"):
        try:
            return PostgresRepository()
        except Exception as e:
            print(f"[store] Postgres unavailable ({e}); using in-memory.")
    return InMemoryRepository()
