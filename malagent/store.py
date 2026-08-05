"""Persistence (D9). PostgreSQL is the production backend; an in-memory double
is used for tests / first run. SqliteRepository is a local, file-based
backend for the web UI (docs/TODO.md Phase 8) -- no server process
required, but data survives across requests/process restarts unlike
InMemoryRepository. Same Repository interface across all three."""
from __future__ import annotations
import json
import os
import threading
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


class SqliteRepository:
    """Local, file-based store -- no server process required, unlike
    PostgresRepository, but (unlike InMemoryRepository) data survives
    across requests and process restarts. Uses the stdlib sqlite3 module
    directly rather than SQLAlchemy: plain TEXT columns for JSON (SQLite
    has no native JSONB type -- CASTing to a made-up type name would
    silently apply the wrong column affinity), and a bare file path needs
    none of SQLAlchemy's URL-parsing/pooling machinery. This is what the
    web UI defaults to (see web/backend/malagent_web/app.py)."""
    def __init__(self, path: str = "malagent_web.db"):
        import sqlite3
        self.path = path
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._lock = threading.Lock()
        self._init()

    def _init(self) -> None:
        with self._lock, self._conn:
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS runs(
                  run_id TEXT PRIMARY KEY, sample_sha256 TEXT, state TEXT,
                  created_at TEXT DEFAULT CURRENT_TIMESTAMP)""")
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS verdicts(
                  sample_sha256 TEXT PRIMARY KEY, verdict TEXT,
                  created_at TEXT DEFAULT CURRENT_TIMESTAMP)""")
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS audit(
                  run_id TEXT, seq INTEGER, record TEXT, record_hash TEXT,
                  PRIMARY KEY(run_id, seq))""")

    def save_run(self, state: AnalysisState, verdict: Verdict) -> str:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT OR IGNORE INTO runs(run_id, sample_sha256, state) VALUES (?, ?, ?)",
                (state.run_id, state.sample.sha256, state.model_dump_json()))
            self._conn.execute(
                "INSERT INTO verdicts(sample_sha256, verdict) VALUES (?, ?) "
                "ON CONFLICT(sample_sha256) DO UPDATE SET verdict=excluded.verdict",
                (verdict.sample_sha256, verdict.model_dump_json()))
        return state.run_id

    def get_verdict(self, sha256: str) -> Optional[Verdict]:
        with self._lock:
            row = self._conn.execute(
                "SELECT verdict FROM verdicts WHERE sample_sha256=?", (sha256,)).fetchone()
        return Verdict.model_validate_json(row[0]) if row else None

    def append_audit(self, record: AuditRecord) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT OR IGNORE INTO audit(run_id, seq, record, record_hash) VALUES (?, ?, ?, ?)",
                (record.run_id, record.seq, record.model_dump_json(), record.record_hash))


def get_repository():
    """sqlite:// URL -> SqliteRepository; any other DATABASE_URL -> Postgres
    (falling back to in-memory if Postgres deps/connection aren't
    available); no DATABASE_URL at all -> in-memory."""
    url = os.getenv("DATABASE_URL")
    if url and url.startswith("sqlite:///"):
        return SqliteRepository(url[len("sqlite:///"):])
    if url:
        try:
            return PostgresRepository()
        except Exception as e:
            print(f"[store] Postgres unavailable ({e}); using in-memory.")
    return InMemoryRepository()
