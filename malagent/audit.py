"""Tamper-evident, hash-chained audit trail (D13). Each record commits to the
previous record's hash, so any retroactive edit breaks the chain. This is the
chain-of-custody backbone for samples received from the SOC/CDC."""
from __future__ import annotations
import hashlib
import json
from typing import Optional
from .contracts import AuditRecord, Repository, now


class AuditLog:
    def __init__(self, run_id: str, repo: Optional[Repository] = None):
        self.run_id = run_id
        self.repo = repo
        self._seq = 0
        self._prev = "GENESIS"
        self.records: list[AuditRecord] = []

    def _hash(self, rec: AuditRecord) -> str:
        payload = json.dumps(
            {"seq": rec.seq, "run_id": rec.run_id, "action": rec.action,
             "detail": rec.detail, "at": rec.at.isoformat(), "prev": rec.prev_hash},
            sort_keys=True, default=str,
        )
        return hashlib.sha256(payload.encode()).hexdigest()

    def log(self, action: str, **detail) -> AuditRecord:
        rec = AuditRecord(seq=self._seq, run_id=self.run_id, action=action,
                          detail=detail, at=now(), prev_hash=self._prev)
        rec.record_hash = self._hash(rec)
        self._prev = rec.record_hash
        self._seq += 1
        self.records.append(rec)
        if self.repo:
            self.repo.append_audit(rec)
        return rec

    def verify(self) -> bool:
        """Re-derive the chain and confirm it is intact."""
        prev = "GENESIS"
        for rec in self.records:
            if rec.prev_hash != prev:
                return False
            if self._hash(rec) != rec.record_hash:
                return False
            prev = rec.record_hash
        return True
